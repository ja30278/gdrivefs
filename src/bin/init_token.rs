extern crate docopt;
extern crate gdrivefs;
extern crate inth_oauth2;

#[macro_use]
extern crate serde_derive;

use gdrivefs::common;
use gdrivefs::oauth;
use std::io;

// see: https://developers.google.com/identity/protocols/googlescopes
const DRIVE_SCOPE: &'static str = "https://www.googleapis.com/auth/drive";

// the auth URI used for the 'application' auth flow.
// see: https://developers.google.com/identity/protocols/OAuth2InstalledApp#choosingredirecturi
const OOB_AUTH_URI: &'static str = "urn:ietf:wg:oauth:2.0:oob";

const USAGE: &'static str = "
init_token: fetch and store an oauth2 token for gdrivefs.

Usage:
  init_token [--client-id-file=<id_file>] [--client-secret-file=<secret_file>] [--token-file=<token_file>]  [--port=<port>]
  init_token (-h | --help)

Options:
  -h --help                           Show this screen.
  --client-id-file=<id_file>          File containing a client id [default: /usr/local/etc/gdrive_id]
  --client-secret-file=<secret_file>  File containing a client secret. [default: /usr/local/etc/gdrive_secret]
  --token-file=<token_file>           Token output file. [default: /etc/gdrive_token]
";

#[derive(Debug, Deserialize)]
struct Args {
  flag_client_id_file: String,
  flag_client_secret_file: String,
  flag_token_file: String,
}

fn main() {
  let args: Args = docopt::Docopt::new(USAGE)
    .and_then(|d| d.deserialize())
    .unwrap_or_else(|e| e.exit());

  let client = oauth::new_google_client(
    &gdrivefs::get_contents(&args.flag_client_id_file).expect(&format!(
      "Error while getting content of file: {}",
      &args.flag_client_id_file
    )),
    &gdrivefs::get_contents(&args.flag_client_secret_file).expect(&format!(
      "Error while getting content of file: {}",
      &args.flag_client_secret_file
    )),
    Some(OOB_AUTH_URI.into()),
  );

  println!("Please visit the following URL to grant the required permissions");
  println!("Then paste the returned code below.");
  let auth_uri = client
    .auth_uri(Some(DRIVE_SCOPE), None)
    .expect("Error while constructing URI");
  println!("{}", auth_uri);
  println!("Code: ");

  let mut code: String = String::new();
  io::stdin()
    .read_line(&mut code)
    .expect("Could not read line from stdin");
  let code_len = code.trim_right().len();
  code.truncate(code_len);
  println!("got code: {}, requesting token", code);

  let http_client = common::new_hyper_tls_client();
  let token = client
    .request_token(&http_client, &code)
    .expect("Error while requesting token");
  oauth::save_token(&args.flag_token_file, &token).expect(&format!("Error while saving token to file: {}", &args.flag_token_file));
  println!("Saved token in {}", args.flag_token_file);
}
