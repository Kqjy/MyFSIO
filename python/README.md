# Deprecated Python Implementation

The Python implementation of MyFSIO is deprecated as of 2026-04-21.

The supported server runtime now lives in `../rust/myfsio-engine` and serves the S3 API and web UI from the Rust `myfsio-server` binary. Keep this tree for migration reference, compatibility checks, and legacy tests only.

For normal development and operations, run:

```bash
cd ../rust/myfsio-engine
cargo run -p myfsio-server --
```

Do not add new product features to the Python implementation unless they are needed to unblock a migration or compare behavior with the Rust server.
