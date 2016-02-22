extern crate hyper;
extern crate log;
extern crate inth_oauth2;
extern crate rustc_serialize;
extern crate yup_oauth2;

use std;
use std::sync;
use std::thread;
use std::error::Error;
use self::inth_oauth2::token::Token;
use common;

pub use self::yup_oauth2::GetToken;

pub type GoogleToken = inth_oauth2::token::Bearer<inth_oauth2::token::Expiring>;
pub type GoogleClient = inth_oauth2::client::Client<inth_oauth2::provider::Google>;

pub fn new_google_client(client_id : &str, client_secret: &str, auth_url: Option<String>) -> GoogleClient {
  GoogleClient::new(String::from(client_id), String::from(client_secret), auth_url)
}

// load a saved Google token from a serialized file.
pub fn load_token(path : &str) -> std::io::Result<GoogleToken> {
  common::get_contents(path)
    .and_then(|data| {
        rustc_serialize::json::decode(&data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
  })
}

// serialize and save a GoogleToken to a file.
pub fn save_token(path: &str, tok : &GoogleToken) -> std::io::Result<()> {
  rustc_serialize::json::encode(tok)
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    .and_then(|encoded| common::set_contents(path, encoded.as_bytes(), 0o600 as std::os::unix::raw::mode_t))
}


/// GoogleAuthenticator implements the yup_oauth2::GetToken trait, for use
/// with the Google drive api.
struct GoogleAuthenticatorImpl {
  http_client: hyper::client::Client,
  oauth_client: inth_oauth2::client::Client<inth_oauth2::provider::Google>,
  inth_token: GoogleToken,
}

impl GoogleAuthenticatorImpl {
  pub fn new(oauth_client: inth_oauth2::client::Client<inth_oauth2::provider::Google>,
             initial_token: GoogleToken)
             -> GoogleAuthenticatorImpl {
    GoogleAuthenticatorImpl {
      http_client: hyper::client::Client::new(),
      oauth_client: oauth_client,
      inth_token: initial_token,
    }
  }

  fn ensure_token(&mut self) {
    match self.oauth_client.ensure_token(&self.http_client, self.inth_token.clone()) {
        Ok(token) => {
            self.inth_token = token;
        },
        Err(err) => {
            warn!("token refresh error: {:?}", err);
        }
    }
  }

  pub fn get_token(&mut self) -> &GoogleToken {
    self.ensure_token();
    &self.inth_token
  }
}

pub struct GoogleAuthenticator {
  auth_impl: sync::Arc<sync::Mutex<GoogleAuthenticatorImpl>>,
}

impl GoogleAuthenticator {

  pub fn new(oauth_client: GoogleClient, initial_token: GoogleToken) -> GoogleAuthenticator {
    GoogleAuthenticator{
      auth_impl: sync::Arc::new(
        sync::Mutex::new(
          GoogleAuthenticatorImpl::new(oauth_client, initial_token)))
    }
  }
  pub fn from_file(oauth_client: GoogleClient, path: &str) -> std::io::Result<GoogleAuthenticator> {
    let init_token = try!(load_token(path));
    Ok(GoogleAuthenticator::new(oauth_client, init_token))
  }

  pub fn save_to_file(&self, path : &str) -> std::io::Result<()> {
    let mut auth_impl = self.auth_impl.lock().unwrap();
    save_token(path, auth_impl.get_token())
  }

  pub fn start_auto_save(&self, path: &str, interval : std::time::Duration) {
    let auth = self.clone();
    let save_path = String::from(path);
    thread::Builder::new().name(String::from("save_auth_token")).spawn(move|| { 
      loop {
        match auth.save_to_file(&save_path) {
          Ok(_) => { info!("saved token to file: {}", save_path); },
          Err(err) => { error!("Error saving token file: {}", err); },
        }
        std::thread::sleep(interval);
      }
    }).unwrap();
  }
  pub fn get_token(&self) -> GoogleToken {
    let mut auth_impl = self.auth_impl.lock().unwrap();
    auth_impl.get_token().clone()
  }
  
}

impl std::clone::Clone for GoogleAuthenticator {
  fn clone(&self) -> GoogleAuthenticator {
    GoogleAuthenticator{auth_impl: self.auth_impl.clone()}
  }
}

impl yup_oauth2::GetToken for GoogleAuthenticator {

  fn token<'b, I, T>(&mut self, _scopes: I) -> Result<yup_oauth2::Token, Box<Error>>
    where T: AsRef<str> + Ord + 'b,
          I: IntoIterator<Item = &'b T>
  {
    let mut auth_impl = self.auth_impl.lock().unwrap();
    Ok(inth_to_yup2(auth_impl.get_token()))
  }

  fn api_key(&mut self) -> Option<String> {
    let mut auth_impl = self.auth_impl.lock().unwrap();
    Some(String::from(auth_impl.get_token().access_token()))
  }
}

fn inth_to_yup2<T, L>(inth: &T) -> yup_oauth2::Token
  where T: inth_oauth2::token::Token<L>,
        L: inth_oauth2::token::Lifetime
{
  yup_oauth2::Token {
    access_token: String::from(inth.access_token()),
    refresh_token: String::new(),
    token_type: String::from("Bearer"),
    expires_in: None,
    expires_in_timestamp: None,
  }
}
