// A FUSE filesystem backed by google drive.
extern crate docopt;
extern crate env_logger;
extern crate fuse;
extern crate gdrivefs;
extern crate google_drive2;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate lru_time_cache;
extern crate inth_oauth2;
extern crate libc;
extern crate rustc_serialize;
extern crate time;

use gdrivefs::common;
use gdrivefs::oauth::GetToken;
use gdrivefs::oauth;
use std::collections::{BTreeMap, HashMap, HashSet};
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

const BLOCK_SIZE: u32 = 4096;

// todo(jonallie): use the actual date as returned from drive.
const CREATE_TIME: time::Timespec = time::Timespec {
  sec: 1381237736,
  nsec: 0,
};

// gdrive id of the root node.
const ROOT_ID: &'static str = "root";

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

// Ag GoogleFile merges fuse file attributes with google drive metadata.
#[derive(Debug, Clone)]
struct GoogleFile {
  file_id: String,
  file_title: String,
  file_attr: fuse::FileAttr,
  download_url: Option<String>,
}

impl GoogleFile {
  fn name(&self) -> &String {
    &self.file_title
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
}

impl std::convert::From<google_drive2::File> for GoogleFile {

  fn from(api_file: google_drive2::File) -> GoogleFile {
    let file_id = api_file.id.expect("file id is missing");
    let mut hasher = std::hash::SipHasher::new();
    let file_size = u64::from_str(api_file.file_size.as_ref().unwrap_or(&"0".into())).unwrap();
    file_id.hash(&mut hasher);
    let kind = match api_file.mime_type.as_ref() {
      Some(mime_type) if mime_type == FOLDER_MIME_TYPE => { fuse::FileType::Directory },
      Some(_) | None => { fuse::FileType::RegularFile },
    }; 
    let perms = if kind == fuse::FileType::Directory { 0o755 } else { 0.644 };
    let attr = fuse::FileAttr {
      ino: hasher.finish(),
      size: file_size,
      blocks: file_size / BLOCK_SIZE,
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
      file_title: api_file.title.unwrap_or("__UNKNOWN_FILE_NAME__".into()),
      file_attr: attr,
      download_url: api_file.download_url,
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
      file_title: ROOT_ID.into(),
      file_attr: ROOT_ATTR,
      download_url: None,
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



type DriveHub = google_drive2::Drive<hyper::client::Client, oauth::GoogleAuthenticator>;

fn list_gdrive_dir(gfile_id: &str, hub: &mut DriveHub) -> Result<Vec<GoogleFile>, Box<Error>> {
  let mut file_vec: Vec<GoogleFile> = Vec::new();
  let mut page_token: Option<String> = None;
  loop {
    let mut list_op = hub.files()
                         .list()
                         .param("fields",
                                "nextPageToken,items(id,title,mimeType,downloadUrl,fileSize)")
                         .q(&format!("'{}' in parents", gfile_id))
                         .order_by("title")
                         .max_results(500);
    if page_token.is_some() {
      list_op = list_op.page_token(page_token.as_ref().unwrap());
    }
    let (_, file_list) = try!(list_op.doit());
    page_token = file_list.next_page_token;
    if file_list.items.is_some() {
      for file in file_list.items.unwrap() {
        file_vec.push(GoogleFile::from(file));
      }
    }
    if page_token.is_none() {
      break;
    }
  }
  Ok(file_vec)
}

// RangeReader reads byte ranges from an http url
struct RangeReader {
  client: hyper::client::Client,
  authenticator: oauth::GoogleAuthenticator,
  file_url: String,
}

impl RangeReader {
  fn new(file_url: &str, authenticator: oauth::GoogleAuthenticator) -> RangeReader {
    RangeReader {
      client: hyper::client::Client::new(),
      authenticator: authenticator,
      file_url: file_url.clone(),
    }
  }

  // read from |start| to |end| (inclusive).
  // this uses the same semantics as http Range, notably:
  // - the range is inclusive, so 0-499 reads 500 bytes.
  // - |end| may be past EOF, in which case available data is returned.
  fn read_range(&mut self, start: u64, end: u64) -> Result<Vec<u8>, Box<Error>> {
    let token = self.authenticator.api_key().unwrap();
    let request = self.client
                      .get(&self.file_url)
                      .header(hyper::header::Range::bytes(start, end))
                      .header(hyper::header::Authorization(hyper::header::Bearer { token: token }));
    let mut resp = try!(request.send());
    if !resp.status.is_success() {
      return Err(Box::new(hyper::error::Error::Status));
    }
    debug!("got response, getting ready to read range data");
    let mut data: Vec<u8> = Vec::with_capacity(((end - start) + 1) as usize);
    try!(resp.read_to_end(&mut data));
    debug!("read range data, returning");
    Ok(data)
  }

  // As above, but using a start + size rather than a range.
  fn read_bytes(&mut self, start: u64, size: u64) -> Result<Vec<u8>, Box<Error>> {
    self.read_range(start, start + size - 1)
  }
}

// A request to read data from a file, for async handling.
struct FileReadRequest {
  offset: u64,
  size: u32,
  reply: fuse::ReplyData,
}

// A handle to a a thread performing reads for a file.
struct FileReadHandle {
  read_chan: sync::mpsc::Sender<FileReadRequest>,
  open_count: u32,
}


#[derive(Debug, Clone)]
struct Options {
  readahead_queue_size: usize,
  file_read_cache_blocks: usize,
  read_block_multiplier: u32,
}

// GDriveFS is a fuse filesytem backed by Google drive
struct GDriveFS {
  authenticator: oauth::GoogleAuthenticator,
  file_tree: sync::Arc<sync::RwLock<GoogleFileTree>>,
  // map of gfileid -> file read handle
  read_handles: sync::Mutex<HashMap<String, FileReadHandle>>,
  options: Options,
}

impl GDriveFS {
  fn new(auth: oauth::GoogleAuthenticator, options: Options) -> GDriveFS {
    GDriveFS {
      authenticator: auth,
      file_tree: sync::Arc::new(sync::RwLock::new(GoogleFileTree::new())),
      read_handles: sync::Mutex::new(HashMap::new()),
      options: options,
    }
  }

  // Starts a background thread for recursively refreshing directory metadata
  fn start_auto_refresh(&self, interval: std::time::Duration) {
    let auth = self.authenticator.clone();
    let tree = self.file_tree.clone();
    thread::spawn(move || {
      let mut queue: VecDeque<String> = VecDeque::new();
      queue.push_back(ROOT_ID.into());
      let mut hub = google_drive2::Drive::new(hyper::client::Client::new(), auth);
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
    });
  }
}

impl fuse::Filesystem for GDriveFS {

  fn statfs(&mut self, _req: &fuse::Request, _ino: u64, reply: fuse::ReplyStatfs {
      reply.statfs(0, 0, 0, 0, 0, BLOCK_SIZE, 256, 0); 
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
        let mut hub = google_drive2::Drive::new(hyper::client::Client::new(), auth);
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

  // handle fuse::open.
  // the basic strategy here is to spawn a thread for each file opened to handle reads
  // for that file. Subsequent opens() for the same file increment the count of openers
  // on the read handle, and the last release closes the transmission channel and the
  // read thread exits.
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
            download_url = attr.download_url.clone();
          }
          None => {
            reply.error(libc::ENOENT);
            return;
        }
      }
    }  // end tree scope
    let download_url = download_url.unwrap();
    let gfileid = gfileid.unwrap();
    let mut reader_map = self.read_handles.lock().unwrap();
    let handle = reader_map.entry(gfileid.clone()).or_insert_with(|| {
      let mut auth = self.authenticator.clone();
      let (tx, rx) = sync::mpsc::channel::<FileReadRequest>();
      let url = download_url.clone();
      let cache_size = self.options.file_read_cache_blocks;
      let readahead_queue_size = self.options.readahead_queue_size;
      let read_block_multiplier = self.options.read_block_multiplier;
      thread::spawn(move || {
        debug!("spawned new reader thread for url: {}", url);
        let mut block_cache: lru_time_cache::LruCache<u64, Vec<u8>> =
          lru_time_cache::LruCache::with_capacity(cache_size);
        let mut readahead: VecDeque<u64> = VecDeque::with_capacity(readahead_queue_size);
        readahead.push_back(0);
        let mut reader = RangeReader::new(&url, auth);
        let chunk_size : u64 = BLOCK_SIZE * read_block_multiplier as u64;
        'receive: loop {
          // wait for new requests
          let req = match rx.try_recv() {
              // new request is ready.
              Ok(req) => { req },
              // no request waiting
              Err(sync::mpsc::TryRecvError::Empty) => {
                  // if we have readahead to do, do it until we get a request.
                  let mut req : Option<FileReadRequest> = None;
                  while let Some(offset) = readahead.pop_front() {
                      if block_cache.contains_key(&offset) { continue; }
                      match reader.read_bytes(offset, chunk_size) {
                          Ok(data) => { block_cache.insert(offset, data); },
                          Err(err) => {
                              warn!("read error on readahead: {:?}", err);
                          }
                      }
                      // if a new request is available, stop doing readahead.
                      match rx.try_recv() {
                          Ok(new_req) => {
                              req = Some(new_req);
                              break;
                          },
                          Err(sync::mpsc::TryRecvError::Disconnected) => {
                              info!("exiting read thread for {} after channel close", url);
                              return;
                          },
                          Err(_) => { }, // still nothing
                      }
                  }
                  // done with readahead.
                  // if we were interrupted by a request, return it now, otherwise just block until
                  // a request is available, or our channel is closed.
                  let ret_req = match req {
                      Some(req) => { req },
                      None => {
                          match rx.recv() {
                              Ok(new_req) => { new_req },
                              Err(err) => {
                                  info!("Exiting read thread for {} on channel recv error: {:?}", url, err);
                                  return;
                              }
                          }
                      }
                  };
                  ret_req
              },
              Err(sync::mpsc::TryRecvError::Disconnected) => {
                  info!("exiting read thread for {} after channel close.", url);
                  return;
              }
          };

          debug!("got new read request for url: {}, offset : {}", url, req.offset);
          let chunk_offset = (req.offset / chunk_size) * chunk_size;
          if (req.offset + req.size as u64) > (chunk_offset + chunk_size) {
            error!("cross chunk read not supported");
            req.reply.error(libc::ENOSYS);
            continue 'receive;
          }
          if !block_cache.contains_key(&chunk_offset) {
            // cache miss. Either our readahead isn't keeping up, or we're
            // seeking within the file. Either way, we can clear the readahead
            // queue.
            debug!("file: {}, cache miss, clearing readahead", url);
            readahead.clear();
            match reader.read_bytes(chunk_offset, chunk_size) {
              Ok(data) => {
                debug!("read {} bytes of data from url {}", data.len(), url);
                block_cache.insert(chunk_offset, data);
              },
              Err(err) => {
                error!("Read error for file: {} : {:?}", url, err);
                req.reply.error(libc::EIO);
                continue 'receive;
              }
            }
          }
          {
              // scope for borrow of block cache values.
              let chunk_data: &Vec<u8> = block_cache.get(&chunk_offset).unwrap();
              let start: usize = (req.offset - chunk_offset) as usize;
              let end: usize = start + req.size as usize;
              let slice = &chunk_data[start..end];
              req.reply.data(slice);
          }

          // schedule readaheads
          let mut readahead_offset = chunk_offset + chunk_size;
          for _ in 0..readahead_queue_size {
              if !block_cache.contains_key(&readahead_offset) {
                debug!("file: {}, scheduling readahead for offset {}", url, readahead_offset);
                readahead.push_back(readahead_offset);
              }
              readahead_offset += chunk_size;
          }
        }
      });
      FileReadHandle {
        read_chan: tx,
        open_count: 0,
      }
    });
    handle.open_count += 1;
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
    if let Some(mut handle) = handles.remove(&fileid) {
      handle.open_count -= 1;
      if handle.open_count > 0 {
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
        handle.read_chan.send(
            FileReadRequest{offset: offset, size: size, reply: reply}
        ).unwrap();
        debug!("send read request for inode: {}", ino);
      }
      None => {
        error!("no download thread found");
        reply.error(libc::EIO);
      }
    }
  }
}

const USAGE: &'static str = "
gdrivefs: A fuse filesystem backed by Google Drive.

Usage: gdrivefs [options] <mountpoint>

<mountpoint> must exist.

Several options can make a large performance difference, depending on the
workload and characteristics of the system. Setting 'read-block-multipler
to higher values will result in fewer HTTP requests, and less overhead per
byte, but can lead to increased latency for small random reads. Likewise,
enabling readahead can help on lower-memory systems where the OS chooses
not to do its own readahead on sequential reads.

Options:
  --client-id-file=<id_file>          Path to a file containing the oauth2 client id. [default: /etc/gdrive_id]
  --client-secret-file=<secret_file>  Path to a file containing the oauth2 client secret. [default: /etc/gdrive_secret]
  --token-file=<token_file>           Path to a file containing a oauth token (generated by init_token). [default: /etc/gdrive_token]
  --allow-other                       If true, allow non-root users to access the mounted filesystem.
  --dir-poll-secs=<poll-secs>         Seconds between directory refresh scans, or 0 to disable. [default: 900]
  --readahead-queue-size=<size>       Size of the readahead queue (per-file, in number of chunks), or 0 to disable readahead. [default: 0]
  --file-read-cache-blocks=<size>     Capacity of the per-file chunk cache (in number of chunks) Should be larger than readahead-queue-size. [default: 40]
  --read-block-multiplier=<mult>      Number of 4k blocks to read per HTTP request. [default: 2048]
";

#[derive(Debug, RustcDecodable)]
struct Args {
  flag_client_id_file: String,
  flag_client_secret_file: String,
  flag_token_file: String,
  flag_allow_other: bool,
  flag_dir_poll_secs: u32,
  flag_readahead_queue_size: usize,
  flag_file_read_cache_blocks: usize,
  flag_read_block_multiplier: u32,
  arg_mountpoint: String,
}

fn main() {
  env_logger::init().unwrap();
  let args: Args = docopt::Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());
  let client = oauth::new_google_client(&common::get_contents(&args.flag_client_id_file).unwrap(),
                                        &common::get_contents(&args.flag_client_secret_file)
                                           .unwrap(),
                                        None);

  let authenticator = oauth::GoogleAuthenticator::from_file(client, &args.flag_token_file).unwrap();
  authenticator.start_auto_save(&args.flag_token_file, std::time::Duration::new(60, 0));

  println!("Mounting drive fs at {:?}", args.arg_mountpoint);
  let options = Options {
    readahead_queue_size: args.flag_readahead_queue_size,
    file_read_cache_blocks: args.flag_file_read_cache_blocks,
    read_block_multiplier: args.flag_read_block_multiplier,
  };
  let gdrivefs = GDriveFS::new(authenticator, options);
  if args.flag_dir_poll_secs > 0 {
    gdrivefs.start_auto_refresh(std::time::Duration::new(args.flag_dir_poll_secs as u64, 0));
  }

  //let mount_options: Vec<std::ffi::OsString> = Vec::new();
  // todo(jonallie): figure out how to make this the default using docopt.
  //mount_options.push(std::ffi::OsString::from("-oallow_other"));
  fuse::mount(gdrivefs, &args.arg_mountpoint, &[std::ffi::OsStr::new("-oallow_other")]);
}
