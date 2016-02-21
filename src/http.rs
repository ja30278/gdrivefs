extern crate hyper;
extern crate fuse;
extern crate lru_time_cache;
extern crate libc;

use constants;
use oauth;
use oauth::GetToken;
use std::collections::VecDeque;
use std::convert::From;
use std::io::Read;
use std::thread;
use std::error::Error;
use std::sync;

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
      file_url: file_url.into(),
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

#[derive(Debug, Clone)]
pub struct FileReadOptions {
  pub readahead_queue_size: usize,
  pub file_read_cache_blocks: usize,
  pub read_block_multiplier: u32,
}

// A request to read data from a file, for async handling.
struct FileReadRequest {
    offset: u64,
    size: u32,
    reply: fuse::ReplyData,
}

/// A handle to a a thread performing reads for a file.
/// |incref()| should be called once for each active reader of the file,
/// with a matching call to |decref| when the file is closed.
pub struct FileReadHandle {
    read_chan: sync::mpsc::Sender<FileReadRequest>,
    open_count: u32,
}

impl FileReadHandle {
    /// Asynchronously peform a read at |offset| of size |size|, returning
    /// the results of the read directly to |reply|
    pub fn do_read(&self, offset: u64, size: u32, reply: fuse::ReplyData) {
        self.read_chan.send(
            FileReadRequest{offset: offset, size: size, reply: reply}
        ).unwrap();
    }

    /// increase the reference count of the handle.
    pub fn incref(&mut self) {
        self.open_count += 1;
    }

    /// decrease the reference count of the handle, returning the
    /// handle if it's still active.
    pub fn decref(mut self) -> Option<FileReadHandle> {
        self.open_count -= 1;
        match self.open_count {
            0 =>  None,
            _ => Some(self)
        }
    }

    /// creates a new FileReadHandle to read data from |url| in a background thread. 
    pub fn spawn(url: &str, auth: &oauth::GoogleAuthenticator, options: &FileReadOptions) -> FileReadHandle {
        let url = String::from(url);
        let auth = auth.clone();
        let cache_size = options.file_read_cache_blocks;
        let readahead_queue_size = options.readahead_queue_size;
        let read_block_multiplier = options.read_block_multiplier;
        let (tx, rx) = sync::mpsc::channel::<FileReadRequest>();
        thread::spawn(move || {
            // cache of offset -> data block at that offset.
            let mut block_cache: lru_time_cache::LruCache<u64, Vec<u8>> =
                lru_time_cache::LruCache::with_capacity(cache_size);

            // queue of offsets to read next.
            let mut readahead: VecDeque<u64> = VecDeque::with_capacity(readahead_queue_size);

            // reads ranges from |url|
            let mut reader = RangeReader::new(&url, auth);

            let chunk_size : u64 = constants::BLOCK_SIZE as u64 * read_block_multiplier as u64;

            // loop until read channel is closed.
            loop {
                // get the next request.
                let req = match rx.try_recv() {
                    // A new request was waiting
                    Ok(req) => { req },

                    // channel was closed, we can exit.
                    Err(sync::mpsc::TryRecvError::Disconnected) => { return; }

                    // no request was ready, but we're still active.
                    Err(sync::mpsc::TryRecvError::Empty) => {
                        // if we have readahead requests, service them until we get a request.
                        let mut new_req : Option<FileReadRequest> = None;
                        while let Some(offset) = readahead.pop_front() {
                            // ignore offsets already in the cache.
                            if block_cache.contains_key(&offset) { continue; }
                            match reader.read_bytes(offset, chunk_size) {
                                Ok(data) => { block_cache.insert(offset, data); }
                                Err(err) => { warn!("read error on readahed: {:?}", err); }
                            }
                            // if we get a new read request, stop doing readahead
                            match rx.try_recv() {
                                Ok(req) => {
                                    new_req = Some(req);
                                    break;
                                }
                                // disconnected, exit
                                Err(sync::mpsc::TryRecvError::Disconnected) => { return; }

                                // still empty
                                Err(_) => { }
                            }
                        }
                        // yield a new request if we have one
                        let ret_req = match new_req {
                            Some(req) => { req },
                            None => {
                                //  otherwise we can block until one comes in
                                match rx.recv() {
                                    Ok(req) => { req }
                                    Err(_) => { return; }
                                }
                            }
                        };
                        // yield the new request
                        ret_req
                    }
                };
                
                // handle the new request.
                debug!("got new read request for url: {}, offset : {}", url, req.offset);
                // calculate the offset of the chunk for this read.
                let chunk_offset = (req.offset / chunk_size) * chunk_size;
                if (req.offset + req.size as u64) > (chunk_offset + chunk_size) {
                    error!("cross chunk read not supported");
                    req.reply.error(libc::ENOSYS);
                    continue;
                }

                if !block_cache.contains_key(&chunk_offset) {
                    // cache miss. Either the readahead isn't keeping up,
                    // or we're seeking within the file. Either way, we
                    // should clear the readahead queue.
                    debug!("file: {}, cache miss, clearing readahead", url);
                    readahead.clear();
                    match reader.read_bytes(chunk_offset, chunk_size) {
                        Ok(data) => {
                            block_cache.insert(chunk_offset, data);
                        }
                        Err(err) => {
                            error!("Read error for url: {} : {:?}", url, err);
                            req.reply.error(libc::EIO);
                            continue;
                        }
                    }
                }

                {
                    // scope for block cache borrow.
                    let chunk_data: &Vec<u8> = block_cache.get(&chunk_offset).unwrap();
                    let start: usize = (req.offset - chunk_offset) as usize;
                    let end: usize = start + req.size as usize;
                    let slice = &chunk_data[start..end];
                    req.reply.data(slice);
                }

                // schedule readahead.
                let mut readahead_offset = chunk_offset + chunk_size;
                for _ in 0..readahead_queue_size {
                    if !block_cache.contains_key(&readahead_offset) {
                        readahead.push_back(readahead_offset);
                    }
                    readahead_offset += chunk_size;
                }
            }

        });
        // return the read handle.
        FileReadHandle{read_chan: tx, open_count: 1}
    }
}
