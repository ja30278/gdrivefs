# gdrivefs
google drive -> fuse filesystem. (rust version)

This is a rust version of a (read-only) fuse filesystem backed by Google Drive.

# Use

Build with cargo `cargo build --release`, then use the `init_token` binary to
generate an initial OAuth2 token (this initial token will be refreshed
automatically while the drive is mounted).

You'll need to create our own project on the Google Developers Console
https://console.developers.google.com/projectcreate.

Then once the project is created, go to
https://console.developers.google.com/apis/credentials to get credentials for
it. Click on Create Credentials→OAuth client ID. You'll have to configure the
consent screen and select Application type = 'Other'. Eventually Google will
show you a window with two strings: a client ID and a client secret. Save them
respectively in `id_file` and `secret_file`.

Finally you'll have to go to
https://console.developers.google.com/apis/library/drive.googleapis.com to
enable the Google Drive API for your newly created project.

Then, initialize `token_file` with:

```
$ cargo run --bin init_token -- --client-id-file=id_file --client-secret-file=secret_file --token-file=token_file
```

(and follow on-screen instructions).

Finally, you are ready to mount your GDrive with:

```
$ mkdir ~/mnt
$ export RUST_LOG=warn,google_drive3=debug,gdrivefs=debug
$ cargo run --bin gdrivefs -- --client-id-file=id_file --client-secret-file=secret_file --token-file=token_file --allow-other ~/mnt
```

See `gdrivefs` for a list of valid flags.
