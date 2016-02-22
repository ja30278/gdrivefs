extern crate fuse;
extern crate hyper;
extern crate google_drive3;
extern crate libc;
#[macro_use]
extern crate log;
extern crate time;

pub mod oauth;
mod common;
mod constants;
mod http;

pub use http::FileReadOptions;
pub use common::get_contents;
pub use common::set_contents;

use std::collections::{BTreeMap, HashMap};
use std::collections::vec_deque::VecDeque;
use std::convert::From;
use std::convert::Into;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::str::FromStr;
use std::sync;
use std::thread;

const TTL: time::Timespec = time::Timespec { sec: 5, nsec: 0 };

// todo(jonallie): use the actual date as returned from drive.
const CREATE_TIME: time::Timespec = time::Timespec {
  sec: 1381237736,
  nsec: 0,
};

// gdrive id of the root node.
const ROOT_ID: &'static str = "root";

const FILE_GET_URL: &'static str = "https://www.googleapis.com/drive/v3/files";

// attributes of the root node.
const ROOT_ATTR: fuse::FileAttr = fuse::FileAttr {
  ino: 1,
  size: 0,
  blocks: 0,
  atime: CREATE_TIME,
  mtime: CREATE_TIME,
  ctime: CREATE_TIME,
  crtime: CREATE_TIME,
  kind: fuse::FileType::Directory,
  perm: 0o755,
  nlink: 2,
  uid: 0,
  gid: 0,
  rdev: 0,
  flags: 0,
};

// mime type of a directory in google drive.
const FOLDER_MIME_TYPE: &'static str = "application/vnd.google-apps.folder";

// A GoogleFile merges fuse file attributes with google drive metadata.
#[derive(Debug, Clone)]
struct GoogleFile {
  file_id: String,
  file_name: String,
  file_attr: fuse::FileAttr,
}

impl GoogleFile {
  fn name(&self) -> &String {
    &self.file_name
  }

  fn inode(&self) -> u64 {
    self.file_attr.ino
  }

  fn is_dir(&self) -> bool {
    self.file_attr.kind == fuse::FileType::Directory
  }

  fn kind(&self) -> fuse::FileType {
    self.file_attr.kind
  }

  fn download_url(&self) -> Option<String> {
    if self.is_dir() {
        None 
    } else { 
        Some(format!("{}/{}?alt=media", FILE_GET_URL, self.file_id))
    }
  }
}

impl std::convert::From<google_drive3::File> for GoogleFile {

  fn from(api_file: google_drive3::File) -> GoogleFile {
    let file_id = api_file.id.expect("file id is missing");
    let mut hasher = std::hash::SipHasher::new();
    let file_size = u64::from_str(api_file.size.as_ref().unwrap_or(&"0".into())).unwrap();
    file_id.hash(&mut hasher);
    let kind = match api_file.mime_type.as_ref() {
      Some(mime_type) if mime_type == FOLDER_MIME_TYPE => { fuse::FileType::Directory },
      Some(_) | None => { fuse::FileType::RegularFile },
    }; 
    let perms = if kind == fuse::FileType::Directory { 0o755 } else { 0o644 };
    let attr = fuse::FileAttr {
      ino: hasher.finish(),
      size: file_size,
      blocks: file_size / constants::BLOCK_SIZE as u64,
      // todo(jonallie): handle dates here.
      atime: CREATE_TIME,
      mtime: CREATE_TIME,
      ctime: CREATE_TIME,
      crtime: CREATE_TIME,
      kind: kind,
      perm: perms,
      nlink: 2,
      uid: 0,
      gid: 0,
      rdev: 0,
      flags: 0,
    };
    GoogleFile {
      file_id: file_id,
      file_name: api_file.name.unwrap_or("__UNKNOWN_FILE_NAME__".into()),
      file_attr: attr,
    }
  }
}

struct GoogleFileTree {
  // map of inode -> gfile id.
  inode_map: BTreeMap<u64, String>,
  // map of gfile id -> vec([gfile ids of children])
  file_tree: HashMap<String, Vec<String>>,
  // map of gfile id -> GoogleFile structure
  file_attrs: HashMap<String, GoogleFile>,
}

impl GoogleFileTree {
  fn new() -> GoogleFileTree {
    let mut tree = GoogleFileTree {
      inode_map: BTreeMap::new(),
      file_tree: HashMap::new(),
      file_attrs: HashMap::new(),
    };
    let root_gfile = GoogleFile {
      file_id: ROOT_ID.into(),
      file_name: ROOT_ID.into(),
      file_attr: ROOT_ATTR,
    };
    tree.insert_node(None, root_gfile);
    tree
  }

  fn get_file_id(&self, inode: u64) -> Option<&String> {
    self.inode_map.get(&inode)
  }

  fn get_file(&self, file_id: &str) -> Option<&GoogleFile> {
    self.file_attrs.get(file_id)
  }

  fn get_child_ids(&self, file_id: &str) -> Option<&[String]> {
    self.file_tree.get(file_id).map(|v| &v[..])
  }

  fn insert_node(&mut self, parent_id: Option<String>, new_node: GoogleFile) {
    self.inode_map.insert(new_node.inode(), new_node.file_id.clone());
    if parent_id.is_some() {
      self.file_tree.entry(parent_id.unwrap()).or_insert(Vec::new()).push(new_node.file_id.clone());
    }
    self.file_attrs.insert(new_node.file_id.clone(), new_node);
  }

  fn clear_children(&mut self, parent_id: &str) {
    self.file_tree.remove(parent_id);
  }
}

type DriveHub = google_drive3::Drive<hyper::client::Client, oauth::GoogleAuthenticator>;

fn list_gdrive_dir(gfile_id: &str, hub: &mut DriveHub) -> Result<Vec<GoogleFile>, Box<Error>> {
  let mut file_vec: Vec<GoogleFile> = Vec::new();
  let mut page_token: Option<String> = None;
  loop {
    let mut list_op = hub.files()
                         .list()
                         .param("fields",
                                "nextPageToken,files(id,mimeType,name,size)")
                         .q(&format!("'{}' in parents and trashed = false", gfile_id))
                         .order_by("name")
                         .page_size(500);
    if page_token.is_some() {
      list_op = list_op.page_token(page_token.as_ref().unwrap());
    }
    let (_, file_list) = try!(list_op.doit());
    page_token = file_list.next_page_token;
    if file_list.files.is_some() {
      for file in file_list.files.unwrap() {
        file_vec.push(GoogleFile::from(file));
      }
    }
    if page_token.is_none() {
      break;
    }
  }
  Ok(file_vec)
}

/// GDriveFS is a fuse filesytem backed by Google drive.
pub struct GDriveFS {
  authenticator: oauth::GoogleAuthenticator,
  file_tree: sync::Arc<sync::RwLock<GoogleFileTree>>,
  // map of gfileid -> file read handle
  read_handles: sync::Mutex<HashMap<String, http::FileReadHandle>>,
  options: FileReadOptions,
}

impl GDriveFS {
  /// Create a new GDriveFS using `auth` to provide authentication, and `options`
  /// to control the properties of file reads.
  pub fn new(auth: oauth::GoogleAuthenticator, options: FileReadOptions) -> GDriveFS {
    GDriveFS {
      authenticator: auth,
      file_tree: sync::Arc::new(sync::RwLock::new(GoogleFileTree::new())),
      read_handles: sync::Mutex::new(HashMap::new()),
      options: options,
    }
  }

  /// Starts a background thread that will periodically refresh filesystem
  /// metadata at |interval|. 
  pub fn start_auto_refresh(&self, interval: std::time::Duration) {
    let auth = self.authenticator.clone();
    let tree = self.file_tree.clone();
    thread::Builder::new().name(String::from("dir_refresh")).spawn(move || {
      let mut queue: VecDeque<String> = VecDeque::new();
      queue.push_back(ROOT_ID.into());
      let mut hub = google_drive3::Drive::new(hyper::client::Client::new(), auth);
      loop {
        if queue.is_empty() {
          queue.push_back(ROOT_ID.into());
          thread::sleep(interval);
        }
        if let Some(id) = queue.pop_front() {
          debug!("refreshing dir id {}", id);
          match list_gdrive_dir(&id, &mut hub) {
            Ok(files) => {
              let mut tree_guard = tree.write().unwrap();
              tree_guard.clear_children(&id);
              for file in files {
                if file.is_dir() {
                  queue.push_back(file.file_id.clone());
                }
                tree_guard.insert_node(Some(id.clone()), file);
              }
            }
            Err(err) => {
              warn!("list_drive_dir: {:?}", err);
            }
          }
          // avoid rate limits
          thread::sleep(std::time::Duration::from_millis(500));
        }
      }
    }).unwrap();
  }
}

impl fuse::Filesystem for GDriveFS {

  fn statfs(&mut self, _req: &fuse::Request, _ino: u64, reply: fuse::ReplyStatfs) {
      reply.statfs(0, 0, 0, 0, 0, constants::BLOCK_SIZE, 256, 0); 
  }

  fn lookup(&mut self, _req: &fuse::Request, parent: u64, name: &std::path::Path,
            reply: fuse::ReplyEntry) {
    let tree = self.file_tree.read().unwrap();
    match tree.get_file_id(parent).and_then(|file_id| tree.get_child_ids(file_id)) {
      Some(children) => {
        for child in children {
          match tree.get_file(child) {
            Some(attr) => {
              if Some(attr.name().as_ref()) == name.to_str() {
                reply.entry(&TTL, &attr.file_attr, 0);
                return;
              }
            }
            None => {}
          }
        }
      }
      None => {}
    }
    reply.error(libc::ENOENT);
  }

  fn getattr(&mut self, _req: &fuse::Request, ino: u64, reply: fuse::ReplyAttr) {
    let tree = self.file_tree.read().unwrap();
    match tree.get_file_id(ino).and_then(|fileid| tree.get_file(fileid)) {
      Some(attr) => {
        reply.attr(&TTL, &attr.file_attr);
      }
      None => {}
    }
  }

  fn readdir(&mut self, _req: &fuse::Request, ino: u64, _fh: u64, offset: u64, mut reply: fuse::ReplyDirectory) {
    debug!("readdir(ino:{}, offset:{})", ino, offset);
    let mut dir_fileid: Option<String> = None;
    {
      let tree = self.file_tree.read().unwrap();
      let child_ids = match tree.get_file_id(ino) {
        Some(fileid) => {
          dir_fileid = Some(fileid.clone());
          let attr = tree.get_file(fileid);
          if attr.is_none() {
            reply.error(libc::ENOENT);
            return;
          } else if !attr.unwrap().is_dir() {
            reply.error(libc::ENOTDIR);
            return;
          }
          tree.get_child_ids(fileid)
        }
        None => {
          // no file id found in inode map.
          reply.error(libc::ENOENT);
          return;
        }
      };
      if let Some(children) = child_ids {
        let mut foffset = offset + 1;
        let split_at = if offset == 0 {
          offset
        } else {
          foffset
        };
        if split_at >= children.len() as u64 {
          // all done.
          reply.ok();
          return;
        }
        if offset == 0 {
          reply.add(ino, 0, fuse::FileType::Directory, ".");
        }
        let (_, children) = children.split_at(split_at as usize);
        for child in children {
          let attr = tree.get_file(child).expect("Missing attr for file id");
          if reply.add(attr.inode(), foffset, attr.kind(), attr.name()) {
            // reply buffer is full.
            break;
          }
          foffset += 1;
        }
        reply.ok();
        return;
      }
    }
    // need to list the directory.
    {
      let tree = self.file_tree.clone();
      let auth = self.authenticator.clone();
      let fileid = dir_fileid.unwrap().clone();
      let offset = offset;
      thread::spawn(move || {
        let mut hub = google_drive3::Drive::new(hyper::client::Client::new(), auth);
        let result = list_gdrive_dir(&fileid, &mut hub);
        if result.is_err() {
          reply.error(libc::EIO);
          return;
        }
        {
          let mut tree_guard = tree.write().unwrap();
          for file in result.unwrap() {
            tree_guard.insert_node(Some(fileid.clone()), file);
          }
        }
        // todo(jonallie): this is a complete cut-paste of the code above,
        // and needs to be factored into a function.
        {
          let tree_guard = tree.read().unwrap();
          if let Some(children) = tree_guard.get_child_ids(&fileid) {
            let mut foffset = offset + 1;
            let split_at = if offset == 0 {
              offset
            } else {
              foffset
            };
            if split_at >= children.len() as u64 {
              reply.ok();
              return;
            }
            if offset == 0 {
              reply.add(ino, 0, fuse::FileType::Directory, ".");
            }
            let (_, children) = children.split_at(split_at as usize);
            for child in children {
              let attr = tree_guard.get_file(child).expect("missing attr for file id");
              if reply.add(attr.inode(), foffset, attr.kind(), attr.name()) {
                break;
              }
              foffset += 1;
            }
          }
          reply.ok();
        }
      });
    }
  }

  fn open(&mut self, _req: &fuse::Request, ino: u64, _flags: u32, reply: fuse::ReplyOpen) {
    debug!("open for inode {}", ino);
    let mut download_url: Option<String> = None;
    let mut gfileid: Option<String> = None;
    {
      let tree = self.file_tree.read().unwrap();
      match tree.get_file_id(ino).and_then(|fileid| {
        gfileid = Some(fileid.clone());
        tree.get_file(fileid)
        }) {
          Some(attr) => {
            download_url = attr.download_url();
          }
          None => {
            reply.error(libc::ENOENT);
            return;
        }
      }
    }  // end tree scope
    if download_url.is_none() {
        reply.error(libc::ENOSYS);
        return;
    }
    let download_url = download_url.unwrap();
    let gfileid = gfileid.unwrap();
    let mut reader_map = self.read_handles.lock().unwrap();
    let handle = reader_map.entry(gfileid.clone())
        .or_insert_with(|| {
            http::FileReadHandle::spawn(&download_url, &self.authenticator, &self.options)
        }
    );
    handle.incref();
    reply.opened(0, 0);
  }

  fn release(&mut self, _req: &fuse::Request, ino: u64, _fh: u64, _flags: u32,
             _lock_owner: u64, _flush: bool, reply: fuse::ReplyEmpty) {
    debug!("release: inode({})", ino);
    let mut fileid: Option<String> = None;
    {
      let tree = self.file_tree.read().unwrap();
      fileid = tree.get_file_id(ino).cloned();
      if fileid.is_none() {
        warn!("Release called for unknown inode: {}", ino);
        reply.ok();
        return;
      }
    }
    let fileid = fileid.unwrap();
    let mut handles = self.read_handles.lock().unwrap();
    if let Some(handle) = handles.remove(&fileid) {
      if let Some(handle) = handle.decref() {
          handles.insert(fileid, handle);
      }
    } else {
      warn!("no open handle found for inode: {}", ino);
    }
    reply.ok();
  }

  fn read(&mut self, _req: &fuse::Request, ino: u64, _fh: u64, offset: u64,
          size: u32, reply: fuse::ReplyData) {
    debug!("read: inode({})", ino);
    let mut fileid: Option<String> = None;
    {
      let tree = self.file_tree.read().unwrap();
      fileid = tree.get_file_id(ino).cloned();
      if fileid.is_none() {
        reply.error(libc::ENOENT);
        return;
      }
    }
    let handle_map = self.read_handles.lock().unwrap();
    match handle_map.get(fileid.as_ref().unwrap()) {
      Some(handle) => {
        handle.do_read(offset, size, reply);
        debug!("send read request for inode: {}", ino);
      }
      None => {
        error!("no download thread found");
        reply.error(libc::EIO);
      }
    }
  }
}
