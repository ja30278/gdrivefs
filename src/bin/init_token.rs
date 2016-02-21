extern crate docopt;
extern crate gdrivefs;
extern crate hyper;
extern crate inth_oauth2;
extern crate rustc_serialize;
extern crate urlparse;

use std::default::Default;
use std::str::FromStr;
use urlparse::GetQuery;
use gdrivefs::oauth;

// see: https://developers.google.com/identity/protocols/googlescopes
const DRIVE_SCOPE : &'static str = "https://www.googleapis.com/auth/drive";

fn fetch_oauth_token(client: &mut inth_oauth2::client::Client<inth_oauth2::provider::Google>,
                     port: u16)
                     -> inth_oauth2::token::Bearer<inth_oauth2::token::Expiring> {
  println!("Authentication needed");
  let (tx, rx) = std::sync::mpsc::channel();
  let mut_tx = std::sync::Mutex::new(tx);
  let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::from_str("0.0.0.0").unwrap(), port);
  let mut listener = hyper::Server::http(&addr)
                       .unwrap()
                       .handle(move |req: hyper::server::Request,
                                     mut resp: hyper::server::Response| {
                         match req.uri {
                           hyper::uri::RequestUri::AbsolutePath(path) => {
                             let parsed_url = urlparse::urlparse(&path);
                             let code = parsed_url.get_parsed_query()
                                                  .and_then(|q| q.get_first_from_str("code"));
                             if code.is_none() {
                               *resp.status_mut() = hyper::status::StatusCode::NotImplemented;
                               return;
                             }
                             mut_tx.lock().unwrap().send(code.unwrap()).unwrap();
                             resp.send(b"ok").unwrap();
                           }
                           _ => *resp.status_mut() = hyper::status::StatusCode::NotImplemented,
                         };
                       })
                       .unwrap();
  println!("Visit URL to authorize");
  let auth_uri = client.auth_uri(Some(DRIVE_SCOPE), None).unwrap();
  println!("{}", auth_uri);
  let code = rx.recv().unwrap();
  listener.close().unwrap();
  let http_client = Default::default();
  let token_result = client.request_token(&http_client, &code).unwrap();
  println!("got token: {:?}", token_result);
  token_result
}

const USAGE: &'static str = "
init_token: fetch and store an oauth2 token for gdrivefs.

Usage:
  init_token --client-id-file=<id_file> --client-secret-file=<secret_file> --token-file=<token_file>  [--port=<port>]

Options:
  --client-id-file=<id_file>          File containing a client id [default: /etc/gdrive_id]
  --client-secret-file=<secret_file>  File containing a client secret. [default: /etc/gdrive_secret]
  --token-file=<token_file>           Token output file. [default: /etc/gdrive_token]
  --port=<port>                       Port on which to listen for redirects. [default: 8080]
";

#[derive(Debug, RustcEncodable, RustcDecodable)]
struct Args {
  flag_client_id_file: String,
  flag_client_secret_file: String,
  flag_token_file: String,
  flag_port: u16,
}

fn main() {
  let args: Args = docopt::Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());
  println!("Client id = {}, secret = {}, output file = {}, port = {}",
           &args.flag_client_id_file,
           &args.flag_client_secret_file,
           &args.flag_token_file,
           &args.flag_port);
  let mut client = oauth::new_google_client(
    &gdrivefs::get_contents(&args.flag_client_id_file).unwrap(),
    &gdrivefs::get_contents(&args.flag_client_secret_file).unwrap(),
    Some(format!("http://localhost:{}/oauth_redirect", args.flag_port)));
  let token = fetch_oauth_token(&mut client, args.flag_port);
  oauth::save_token(&args.flag_token_file, &token).unwrap();
  println!("Saved token in {}", args.flag_token_file);
}
