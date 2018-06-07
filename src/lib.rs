extern crate fuse;
extern crate google_drive3;
extern crate hyper;
extern crate libc;
#[macro_use]
extern crate log;
extern crate threadpool;
extern crate time;

pub mod common;
mod constants;
mod http;
pub mod oauth;

pub use common::get_contents;
pub use common::set_contents;
pub use http::FileReadOptions;

use std::collections::vec_deque::VecDeque;
use std::collections::BTreeMap;
use std::convert::From;
use std::convert::Into;
use std::error::Error;
use std::ffi::OsStr;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync;
use std::thread;

const TTL: time::Timespec = time::Timespec { sec: 5, nsec: 0 };

// Default time used for the root, and for files for which no time is returned
// or time parsing fails.
const DEFAULT_TIME: time::Timespec = time::Timespec {
  sec: 1381237736,
  nsec: 0,
};

// Format string for RFC 3339 Datetimes.
const RFC3339_FMT: &'static str = "%Y-%m-%dT%H:%M:%S";

// gdrive id of the root node.
const ROOT_ID: &'static str = "root";

const ROOT_INODE: u64 = 1;

const FILE_GET_URL: &'static str = "https://www.googleapis.com/drive/v3/files";

// attributes of the root node.
const ROOT_ATTR: fuse::FileAttr = fuse::FileAttr {
  ino: ROOT_INODE,
  size: 0,
  blocks: 0,
  atime: DEFAULT_TIME,
  mtime: DEFAULT_TIME,
  ctime: DEFAULT_TIME,
  crtime: DEFAULT_TIME,
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

fn parse_rfc3339(s: &str) -> time::Timespec {
  match time::strptime(s, RFC3339_FMT) {
    Ok(tm) => tm.to_timespec(),
    Err(_) => DEFAULT_TIME,
  }
}

// A GoogleFile merges fuse file attributes with google drive metadata.
#[derive(Debug, Clone)]
struct GoogleFile {
  file_id: String,
  file_name: String,
  //file_download_url: String,
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
      // Some(self.file_download_url.clone())
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
      Some(mime_type) if mime_type == FOLDER_MIME_TYPE => fuse::FileType::Directory,
      Some(_) | None => fuse::FileType::RegularFile,
    };
    let perms = if kind == fuse::FileType::Directory {
      0o755
    } else {
      0o644
    };
    let created_time = parse_rfc3339(api_file.created_time.as_ref().unwrap_or(&"".into()));
    let modified_time = parse_rfc3339(api_file.modified_time.as_ref().unwrap_or(&"".into()));

    let attr = fuse::FileAttr {
      ino: hasher.finish(),
      size: file_size,
      blocks: file_size / constants::BLOCK_SIZE as u64,
      atime: modified_time,
      mtime: modified_time,
      ctime: modified_time,
      crtime: created_time,
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
      //file_download_url: api_file.download_url.unwrap_or("".into()),
      file_attr: attr,
    }
  }
}

struct GoogleFileTree {
  // map of inode-> vec([inodes of children])
  file_tree: BTreeMap<u64, Vec<u64>>,
  // map of inode -> GoogleFile
  file_attrs: BTreeMap<u64, GoogleFile>,
}

impl GoogleFileTree {
  fn new() -> GoogleFileTree {
    let mut tree = GoogleFileTree {
      file_tree: BTreeMap::new(),
      file_attrs: BTreeMap::new(),
    };
    let root_gfile = GoogleFile {
      file_id: ROOT_ID.into(),
      file_name: ROOT_ID.into(),
      //file_download_url: "".into(),
      file_attr: ROOT_ATTR,
    };
    tree.insert_node(None, root_gfile);
    tree
  }

  fn file_count(&self) -> u64 {
    self.file_attrs.len() as u64
  }

  fn get_file(&self, inode: &u64) -> Option<&GoogleFile> {
    self.file_attrs.get(inode)
  }

  fn get_children(&self, inode: &u64) -> Option<&[u64]> {
    self.file_tree.get(inode).map(|v| &v[..])
  }

  fn has_children(&self, inode: &u64) -> bool {
    self.file_tree.get(inode).is_some()
  }

  fn insert_node(&mut self, parent_inode: Option<u64>, new_node: GoogleFile) {
    if let Some(inode) = parent_inode {
      self
        .file_tree
        .entry(inode)
        .or_insert(Vec::new())
        .push(new_node.inode());
    }
    self.file_attrs.insert(new_node.inode(), new_node);
  }

  fn clear_children(&mut self, parent_inode: &u64) {
    self.file_tree.remove(parent_inode);
  }
}

type DriveHub = google_drive3::Drive<hyper::client::Client, oauth::GoogleAuthenticator>;

fn list_gdrive_dir(gfile_id: &str, hub: &mut DriveHub) -> Result<Vec<GoogleFile>, Box<Error>> {
  debug!("In list_gdrive_dir({}, …)", gfile_id);
  let mut file_vec: Vec<GoogleFile> = Vec::new();
  let mut page_token: Option<String> = None;
  loop {
    let mut list_op = hub
      .files()
      .list()
      .param(
        "fields",
        "nextPageToken,files(id,mimeType,name,size,createdTime,modifiedTime)",
      )
      .q(&format!("'{}' in parents and trashed = false", gfile_id))
      .order_by("name")
      .page_size(500);

    if let Some(ref token) = page_token {
      list_op = list_op.page_token(token);
    }

    let file_list = match list_op.doit() {
      Ok((_, l)) => l,
      Err(e) => {
        warn!(
          "Error while evaluating list_gdrive_dir({}, …): {}",
          gfile_id, e
        );
        return Err(Box::new(e));
      }
    };

    page_token = file_list.next_page_token;

    if let Some(files) = file_list.files {
      for file in files {
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
  // map of inode -> file read handle
  read_handles: sync::Mutex<BTreeMap<u64, http::FileReadHandle>>,
  list_dir_pool: threadpool::ThreadPool,
  options: FileReadOptions,
}

impl GDriveFS {
  /// Create a new GDriveFS using `auth` to provide authentication, and `options`
  /// to control the properties of file reads.
  pub fn new(auth: oauth::GoogleAuthenticator, options: FileReadOptions) -> GDriveFS {
    GDriveFS {
      authenticator: auth,
      file_tree: sync::Arc::new(sync::RwLock::new(GoogleFileTree::new())),
      read_handles: sync::Mutex::new(BTreeMap::new()),
      list_dir_pool: threadpool::ThreadPool::new(4),
      options: options,
    }
  }

  /// Starts a background thread that will periodically refresh filesystem
  /// metadata at |interval|.
  pub fn start_auto_refresh(&self, interval: std::time::Duration) {
    debug!("In start_auto_refresh(…)");
    let auth = self.authenticator.clone();
    let tree = self.file_tree.clone();
    thread::Builder::new()
      .name(String::from("dir_refresh"))
      .spawn(move || {
        let mut queue: VecDeque<u64> = VecDeque::new();
        queue.push_back(ROOT_INODE);
        let mut hub = google_drive3::Drive::new(common::new_hyper_tls_client(), auth);
        loop {
          if queue.is_empty() {
            queue.push_back(ROOT_INODE);
            thread::sleep(interval);
          }
          if let Some(inode) = queue.pop_front() {
            let id = match tree.read().unwrap().get_file(&inode) {
              Some(attr) => attr.file_id.clone(),
              None => continue,
            };
            debug!("refreshing dir id {}", id);
            match list_gdrive_dir(&id, &mut hub) {
              Ok(files) => {
                let mut tree_guard = tree.write().unwrap();
                tree_guard.clear_children(&inode);
                for file in files {
                  if file.is_dir() {
                    queue.push_back(file.inode());
                  }
                  tree_guard.insert_node(Some(inode), file);
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
      })
      .unwrap();
  }
}

impl fuse::Filesystem for GDriveFS {
  fn statfs(&mut self, _req: &fuse::Request, _ino: u64, reply: fuse::ReplyStatfs) {
    let tree = self.file_tree.read().unwrap();
    reply.statfs(0, 0, 0, tree.file_count(), 0, constants::BLOCK_SIZE, 256, 0);
  }

  fn lookup(&mut self, _req: &fuse::Request, parent: u64, name: &OsStr, reply: fuse::ReplyEntry) {
    let tree = self.file_tree.read().unwrap();
    if let Some(children) = tree.get_children(&parent) {
      for child in children {
        if let Some(attr) = tree.get_file(child) {
          if Some(attr.name().as_ref()) == name.to_str() {
            reply.entry(&TTL, &attr.file_attr, 0);
            return;
          }
        }
      }
    }
    reply.error(libc::ENOENT);
  }

  fn getattr(&mut self, _req: &fuse::Request, ino: u64, reply: fuse::ReplyAttr) {
    debug!("getattr(ino:{})", ino);
    match self.file_tree.read().unwrap().get_file(&ino) {
      Some(attr) => {
        reply.attr(&TTL, &attr.file_attr);
      }
      None => {
        reply.error(libc::ENOATTR);
      }
    }
  }

  fn readdir(
    &mut self,
    _req: &fuse::Request,
    ino: u64,
    _fh: u64,
    offset: i64,
    mut reply: fuse::ReplyDirectory,
  ) {
    debug!("readdir(ino:{}, offset:{})", ino, offset);
    let file_tree = self.file_tree.clone();
    let auth = self.authenticator.clone();
    self.list_dir_pool.execute(move || {
      let mut fileid = String::new();
      let has_children = {
        let tree = file_tree.read().unwrap();
        match tree.get_file(&ino) {
          Some(attr) => {
            if !attr.is_dir() {
              reply.error(libc::ENOTDIR);
              return;
            }
            fileid.push_str(&attr.file_id)
          }
          None => {
            reply.error(libc::ENOENT);
            return;
          }
        }
        tree.has_children(&ino)
      };
      // need to list the directory
      if !has_children {
        let mut hub = google_drive3::Drive::new(common::new_hyper_tls_client(), auth);
        let result = list_gdrive_dir(&fileid, &mut hub);
        if result.is_err() {
          reply.error(libc::EIO);
          return;
        }
        let mut tree = file_tree.write().unwrap();
        // clear_children in case we were interleaved with another list that
        // finished while we were listing.t
        tree.clear_children(&ino);
        for file in result.unwrap() {
          tree.insert_node(Some(ino), file);
        }
      }
      let tree = file_tree.read().unwrap();
      if let Some(children) = tree.get_children(&ino) {
        let mut foffset = offset + 1;
        let split_at = if offset == 0 { offset } else { foffset };
        if split_at >= children.len() as i64 {
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
      }
      reply.ok();
    });
  }

  fn open(&mut self, _req: &fuse::Request, ino: u64, _flags: u32, reply: fuse::ReplyOpen) {
    debug!("open for inode {}", ino);
    let download_url = self
      .file_tree
      .read()
      .unwrap()
      .get_file(&ino)
      .and_then(|attr| attr.download_url());
    if download_url.is_none() {
      reply.error(libc::ENOSYS);
      return;
    }
    let download_url = download_url.unwrap();
    let mut reader_map = self.read_handles.lock().unwrap();
    let handle = reader_map.entry(ino).or_insert_with(|| {
      http::FileReadHandle::spawn(&download_url, &self.authenticator, &self.options)
    });
    handle.incref();
    reply.opened(0, 0);
  }

  fn release(
    &mut self,
    _req: &fuse::Request,
    ino: u64,
    _fh: u64,
    _flags: u32,
    _lock_owner: u64,
    _flush: bool,
    reply: fuse::ReplyEmpty,
  ) {
    debug!("release: inode({})", ino);
    let mut handles = self.read_handles.lock().unwrap();
    if let Some(handle) = handles.remove(&ino) {
      if let Some(handle) = handle.decref() {
        handles.insert(ino, handle);
      }
    } else {
      warn!("no open handle found for inode: {}", ino);
    }
    reply.ok();
  }

  fn read(
    &mut self,
    _req: &fuse::Request,
    ino: u64,
    _fh: u64,
    offset: i64,
    size: u32,
    reply: fuse::ReplyData,
  ) {
    let handle_map = self.read_handles.lock().unwrap();
    match handle_map.get(&ino) {
      Some(handle) => {
        handle.do_read(offset as u64, size, reply);
      }
      None => {
        error!("no download thread found");
        reply.error(libc::EIO);
      }
    }
  }
}
