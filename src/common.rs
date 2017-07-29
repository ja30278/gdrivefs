extern crate libc;

use std;
use std::os::unix::fs::OpenOptionsExt;
use std::io::Read;
use std::io::Write;

/// get_contents is a convenience function for reading a file to a string.
pub fn get_contents(path: &str) -> std::io::Result<String> {
  let can_path = try!(std::fs::canonicalize(path));
  let mut f = try!(std::fs::File::open(can_path.as_path()));
  let mut buf = String::new();
  try!(f.read_to_string(&mut buf));
  Ok(buf)
}

/// set_contents is a convenience function for writing a string to a file.
pub fn set_contents(path: &str, contents: &[u8], mode: libc::mode_t) -> std::io::Result<()> {
  let mut f = try!(std::fs::OpenOptions::new().write(true).create(true).mode(mode as u32).open(path));
  try!(f.write_all(contents));
  Ok(())
}
