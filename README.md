# gdrivefs
google drive -> fuse filesystem. (rust version)

This is a rust version of a (read-only) fuse filesystem backed by Google Drive.

# Use

Build with cargo `cargo build --release`, then use the `init_token` binary to generate an initial OAuth2 token
(this initial token will be refreshed automatically while the drive is mounted).

See `gdrivefs` for a list of valid flags.
