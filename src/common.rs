extern crate hyper;
extern crate hyper_rustls;
extern crate libc;

use std;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

/// get_contents is a convenience function for reading a file to a string.
pub fn get_contents(path: &str) -> std::io::Result<String> {
  let can_path = try!(std::fs::canonicalize(path));
  let mut f = try!(std::fs::File::open(can_path.as_path()));
  let mut buf = String::new();
  try!(f.read_to_string(&mut buf));
  let n = buf.trim_right().len();
  buf.truncate(n);
  Ok(buf)
}

/// set_contents is a convenience function for writing a string to a file.
pub fn set_contents(path: &str, contents: &[u8], mode: libc::mode_t) -> std::io::Result<()> {
  let mut f = try!(
    std::fs::OpenOptions::new()
      .write(true)
      .create(true)
      .mode(mode as u32)
      .open(path)
  );
  try!(f.write_all(contents));
  Ok(())
}

pub fn new_hyper_tls_client() -> hyper::Client {
  hyper::Client::with_connector(hyper::net::HttpsConnector::new(
    hyper_rustls::TlsClient::new(),
  ))
}
