extern crate hyper;
extern crate fuse;
extern crate libc;

use constants;
use oauth;
use oauth::GetToken;
use std::cell::Cell;
use std::cmp;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::convert::From;
use std::io::Read;
use std::thread;
use std::error::Error;
use std::sync;

struct BufferCacheEntry {
    buf: Vec<u8>,
    heat: Cell<u64>,
}

// maximum 'heat' value of a cache entry, bounds the work
// we have to do to find an reusable buffer.
const MAX_HEAT: u64 = 10;

impl BufferCacheEntry {
    fn new(data: Vec<u8>) -> BufferCacheEntry {
        BufferCacheEntry{buf: data, heat: Cell::new(1)}
    }

    fn inc(&self) -> u64 {
        self.heat.set(cmp::min(self.heat.get() + 1, MAX_HEAT));
        self.heat.get()
    }

    fn dec(&self) -> u64 {
        self.heat.set(cmp::max(self.heat.get() - 1, 0));
        self.heat.get()
    }
}

// BufferCache is a cache for file buffers. It uses an algorithm similar
// to GCLOCK, with a bounded 'hotness'. In theory this should avoid large
// amounts of alloc churn caused by repeatedly allocating new buffers for
// reading file data.
struct BufferCache {
    cache: BTreeMap<u64, BufferCacheEntry>,
    freelist: VecDeque<Vec<u8>>,
    clock: VecDeque<u64>,
}

impl BufferCache {
    fn new(count: usize, bufsize: usize) -> BufferCache {
        let mut freelist : VecDeque<Vec<u8>> = VecDeque::with_capacity(count);
        for _ in 0..count {
            freelist.push_back(Vec::with_capacity(bufsize));
        }
        BufferCache{
            cache: BTreeMap::new(),
            freelist: freelist,
            clock: VecDeque::new()}
    }

    fn contains_key(&self, offset: &u64) -> bool {
        self.cache.contains_key(offset)
    }

    fn get(&self, offset: &u64) -> Option<&Vec<u8>> {
        self.cache.get(offset).and_then(|entry| {
            let heat = entry.inc();
            debug!("buffercache: inc reference for offset: {}, new heat {}", offset, heat);
            Some(&entry.buf)
        })
    }

    fn take(&mut self) -> Vec<u8> {
        if let Some(mut data) = self.freelist.pop_front() {
            data.truncate(0);
            return data;
        }
        if self.clock.is_empty() {
            panic!("no data in freelist, and entries in clock");
        }
        // loop over clock, decrementing offset until we find an eligible
        // buffer.
        loop {
            let offset = self.clock.pop_front().unwrap();
            if !self.cache.contains_key(&offset) {
                continue;
            }
            let heat = self.cache.get(&offset).unwrap().dec();
            if heat == 0 {
                debug!("buffercache: reusing buffer for offset {}", offset);
                let mut buf = self.cache.remove(&offset).unwrap().buf;
                buf.truncate(0);
                return buf;
            }
            // still no zero heat buffer, offset goes back in the queue
            // and we keep looping.
            self.clock.push_back(offset);
        }
    }

    fn insert(&mut self, offset: u64, data: Vec<u8>) {
        // if we have a previous entry for this value, just add the
        // old buf to the freelist.
        if let Some(old_data) = self.cache.remove(&offset) {
            self.freelist.push_back(old_data.buf)
        }
        self.cache.insert(offset, BufferCacheEntry::new(data));
        self.clock.push_back(offset);
    }
    
    fn put(&mut self, data: Vec<u8>) {
        self.freelist.push_back(data);
    }
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
      file_url: file_url.into(),
    }
  }

  // read from |start| to |end| (inclusive).
  // this uses the same semantics as http Range, notably:
  // - the range is inclusive, so 0-499 reads 500 bytes.
  // - |end| may be past EOF, in which case available data is returned.
  fn read_range(&mut self, start: u64, end: u64, buf: &mut Vec<u8>) -> Result<(), Box<Error>> {
    let token = self.authenticator.api_key().unwrap();
    let request = self.client
                      .get(&self.file_url)
                      .header(hyper::header::Range::bytes(start, end))
                      .header(hyper::header::Authorization(hyper::header::Bearer { token: token }));
    let mut resp = try!(request.send());
    if !resp.status.is_success() {
      let mut err: String = String::new();
      try!(resp.read_to_string(&mut err));
      warn!("Read error result: {}", err);
      return Err(Box::new(hyper::error::Error::Status));
    }
    debug!("got response, getting ready to read range data");
    try!(resp.read_to_end(buf));
    debug!("read range data, returning");
    Ok(())
  }

  // As above, but using a start + size rather than a range.
  fn read_bytes(&mut self, start: u64, size: u64, buf: &mut Vec<u8>) -> Result<(), Box<Error>> {
    self.read_range(start, start + size - 1, buf)
  }
}

/// Options that control files reads from Google Drive
#[derive(Debug, Clone)]
pub struct FileReadOptions {
  /// The size of the (per-file) readahead queue. A value of `0` disables
  /// readahead. Note that this value should always be smaller than
  /// `file_read_cache_blocks`, to prevent later readahead blocks from
  /// pushing earlier blocks from the cache before they can be used.
  pub readahead_queue_size: usize,

  /// The size of the per-file read cache (in number of blocks, where
  /// the block size is determined by `read_block_muliplier`. see below).
  pub file_read_cache_blocks: usize,

  /// The multiplier of the block size (usually 4096) to read in each HTTP
  /// request to Google Drive. For example, a value of 1024 here would
  /// cause files to be retrieved in 4MB chunks.
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
        debug!("after increment, open_count = {}", self.open_count);
    }

    /// decrease the reference count of the handle, returning the
    /// handle if it's still active.
    pub fn decref(mut self) -> Option<FileReadHandle> {
        self.open_count -= 1;
        debug!("after decrement, open_count = {}", self.open_count);
        match self.open_count {
            0 =>  None,
            _ => Some(self)
        }
    }

    /// creates a new FileReadHandle to read data from |url| in a background thread. 
    /// The returned read handle has a refcount of '0', and should be `incref()`d before use.
    pub fn spawn(url: &str, auth: &oauth::GoogleAuthenticator, options: &FileReadOptions) -> FileReadHandle {
        let url = String::from(url);
        let auth = auth.clone();
        let cache_size = options.file_read_cache_blocks;
        let readahead_queue_size = options.readahead_queue_size;
        let read_block_multiplier = options.read_block_multiplier;
        let (tx, rx) = sync::mpsc::channel::<FileReadRequest>();
        thread::Builder::new().name(url.clone()).spawn(move || {
            // queue of offsets to read next.
            let mut readahead: VecDeque<u64> = VecDeque::with_capacity(readahead_queue_size);

            // reads ranges from |url|
            let mut reader = RangeReader::new(&url, auth);

            let chunk_size : u64 = constants::BLOCK_SIZE as u64 * read_block_multiplier as u64;

            // buffer cache
            let mut buf_cache = BufferCache::new(cache_size as usize, chunk_size as usize);

            // loop until read channel is closed.
            loop {
                // get the next request.
                let req = match rx.try_recv() {
                    // A new request was waiting
                    Ok(req) => { req },

                    // channel was closed, we can exit.
                    Err(sync::mpsc::TryRecvError::Disconnected) => {
                        debug!("exiting read thread on disconnect");
                        return;
                    }

                    // no request was ready, but we're still active.
                    Err(sync::mpsc::TryRecvError::Empty) => {
                        // if we have readahead requests, service them until we get a request.
                        let mut new_req : Option<FileReadRequest> = None;
                        while let Some(offset) = readahead.pop_front() {
                            // ignore offsets already in the cache.
                            if buf_cache.contains_key(&offset) { continue; }
                            //if block_cache.contains_key(&offset) { continue; }
                            let mut buf = buf_cache.take();
                            match reader.read_bytes(offset, chunk_size, &mut buf) {
                                Ok(()) => { buf_cache.insert(offset, buf); }
                                Err(err) => {
                                    // we failed to read, but need to give the buffer
                                    // back to the cache to be reused.
                                    buf_cache.put(buf);
                                    warn!("read error on readahed: {:?}", err);
                                }
                            }
                            // if we get a new read request, stop doing readahead
                            match rx.try_recv() {
                                Ok(req) => {
                                    new_req = Some(req);
                                    break;
                                }
                                // disconnected, exit
                                Err(sync::mpsc::TryRecvError::Disconnected) => {
                                    debug!("exiting read thread on disconnect");
                                    return;
                                }

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
                                    Err(_) => {
                                        debug!("exiting read thread on disconnect");
                                        return;
                                    }
                                }
                            }
                        };
                        // yield the new request
                        ret_req
                    }
                };
                
                // handle the new request.
                // calculate the offset of the chunk for this read.
                let chunk_offset = (req.offset / chunk_size) * chunk_size;
                if (req.offset + req.size as u64) > (chunk_offset + chunk_size) {
                    error!("cross chunk read not supported");
                    req.reply.error(libc::ENOSYS);
                    continue;
                }

                if !buf_cache.contains_key(&chunk_offset) {
                    // cache miss. Either the readahead isn't keeping up,
                    // or we're seeking within the file. Either way, we
                    // should clear the readahead queue.
                    debug!("file: {}, cache miss, clearing readahead", url);
                    readahead.clear();
                    let mut buf = buf_cache.take();
                    match reader.read_bytes(chunk_offset, chunk_size, &mut buf) {
                        Ok(()) => {
                            buf_cache.insert(chunk_offset, buf);
                        }
                        Err(err) => {
                            error!("Read error for url: {} : {:?}", url, err);
                            buf_cache.put(buf);
                            req.reply.error(libc::EIO);
                            continue;
                        }
                    }
                }

                {
                    // scope for block cache borrow.
                    let chunk_data: &Vec<u8> = buf_cache.get(&chunk_offset).unwrap();
                    let start: usize = (req.offset - chunk_offset) as usize;
                    let end: usize = start + req.size as usize;
                    let slice = &chunk_data[start..end];
                    req.reply.data(slice);
                }

                // schedule readahead.
                let mut readahead_offset = chunk_offset + chunk_size;
                for _ in 0..readahead_queue_size {
                    if !buf_cache.contains_key(&readahead_offset) {
                        readahead.push_back(readahead_offset);
                    }
                    readahead_offset += chunk_size;
                }
            }

        }).unwrap();
        // return the read handle.
        FileReadHandle{read_chan: tx, open_count: 0}
    }
}
