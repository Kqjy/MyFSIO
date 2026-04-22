# MyFSIO Rust Operations Guide

This document describes the MyFSIO Rust server. The repository root is the Cargo workspace.

## 1. Overview

- One process serves both the S3 API and the web UI.
- The server entrypoint is `myfsio-server`.
- The main development workflow is `cargo run -p myfsio-server --`.
- API-only mode is controlled with `UI_ENABLED=false`.

## 2. Quick Start

From the repository root:

```bash
cargo run -p myfsio-server --
```

Default endpoints:

- UI: `http://127.0.0.1:5100/ui`
- API: `http://127.0.0.1:5000/`
- Health: `http://127.0.0.1:5000/myfsio/health`

On first startup, MyFSIO bootstraps an admin user in `data/.myfsio.sys/config/iam.json` and prints the generated access key and secret key to stdout.

### Windows

From PowerShell at the repository root:

```powershell
cargo run -p myfsio-server --
```

### API-only mode

```bash
UI_ENABLED=false cargo run -p myfsio-server --
```

There is no separate UI-only mode in the Rust server.

## 3. Build and Run a Binary

```bash
cargo build --release -p myfsio-server
```

Run it directly:

```bash
./target/release/myfsio-server
```

On Windows:

```powershell
.\target\release\myfsio-server.exe
```

## 4. CLI Commands

The Rust CLI supports these operational commands:

```bash
# Start serving (default command)
cargo run -p myfsio-server --

# Print version
cargo run -p myfsio-server -- version

# Show resolved configuration
cargo run -p myfsio-server -- --show-config

# Validate configuration and exit with code 1 on critical issues
cargo run -p myfsio-server -- --check-config

# Back up the current IAM file and generate fresh admin credentials
cargo run -p myfsio-server -- --reset-cred
```

If you are running a release build instead of `cargo run`, replace the `cargo run ... --` prefix with the binary path.

## 5. Environment Files

At startup, the server tries to load environment files from these locations when they exist:

1. `/opt/myfsio/myfsio.env`
2. `.env` in the current directory
3. `myfsio.env` in the current directory
4. `.env` and `myfsio.env` in a few parent directories

That makes local development and systemd installs behave consistently.

## 6. Verified Configuration Reference

These values are taken from `crates/myfsio-server/src/config.rs`.

### Network and runtime

| Variable | Default | Description |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Bind address for both listeners |
| `PORT` | `5000` | S3 API port |
| `UI_PORT` | `5100` | Web UI port |
| `UI_ENABLED` | `true` | Disable to run API-only |
| `API_BASE_URL` | unset | Public-facing API base used by the UI and presigned URL generation |
| `TEMPLATES_DIR` | built-in templates dir | Optional override for UI templates |
| `STATIC_DIR` | built-in static dir | Optional override for static assets |

### Storage and auth

| Variable | Default | Description |
| --- | --- | --- |
| `STORAGE_ROOT` | `./data` | Root for buckets and internal state |
| `IAM_CONFIG` | `<STORAGE_ROOT>/.myfsio.sys/config/iam.json` | IAM config path |
| `AWS_REGION` | `us-east-1` | SigV4 region |
| `SIGV4_TIMESTAMP_TOLERANCE_SECONDS` | `900` | Allowed request time skew |
| `PRESIGNED_URL_MIN_EXPIRY_SECONDS` | `1` | Minimum presigned URL lifetime |
| `PRESIGNED_URL_MAX_EXPIRY_SECONDS` | `604800` | Maximum presigned URL lifetime |
| `SECRET_KEY` | unset, then fallback to `.myfsio.sys/config/.secret` if present | Session signing and IAM config encryption key |
| `ADMIN_ACCESS_KEY` | unset | Optional deterministic first-run/reset access key |
| `ADMIN_SECRET_KEY` | unset | Optional deterministic first-run/reset secret key |

### Feature toggles

| Variable | Default | Description |
| --- | --- | --- |
| `ENCRYPTION_ENABLED` | `false` | Enable object encryption support |
| `KMS_ENABLED` | `false` | Enable built-in KMS support |
| `GC_ENABLED` | `false` | Start the garbage collector worker |
| `INTEGRITY_ENABLED` | `false` | Start the integrity worker |
| `LIFECYCLE_ENABLED` | `false` | Start the lifecycle worker |
| `METRICS_HISTORY_ENABLED` | `false` | Persist system metrics snapshots |
| `OPERATION_METRICS_ENABLED` | `false` | Persist API operation metrics |
| `WEBSITE_HOSTING_ENABLED` | `false` | Enable website domain and hosting features |
| `SITE_SYNC_ENABLED` | `false` | Start the site sync worker |

### Metrics tuning

| Variable | Default | Description |
| --- | --- | --- |
| `OPERATION_METRICS_INTERVAL_MINUTES` | `5` | Snapshot interval for operation metrics |
| `OPERATION_METRICS_RETENTION_HOURS` | `24` | Retention window for operation metrics |
| `METRICS_HISTORY_INTERVAL_MINUTES` | `5` | Snapshot interval for system metrics |
| `METRICS_HISTORY_RETENTION_HOURS` | `24` | Retention window for system metrics |

### Replication and site sync

| Variable | Default | Description |
| --- | --- | --- |
| `REPLICATION_CONNECT_TIMEOUT_SECONDS` | `5` | Replication connect timeout |
| `REPLICATION_READ_TIMEOUT_SECONDS` | `30` | Replication read timeout |
| `REPLICATION_MAX_RETRIES` | `2` | Replication retry count |
| `REPLICATION_STREAMING_THRESHOLD_BYTES` | `10485760` | Switch to streaming for large copies |
| `REPLICATION_MAX_FAILURES_PER_BUCKET` | `50` | Failure budget before a bucket is skipped |
| `SITE_SYNC_INTERVAL_SECONDS` | `60` | Poll interval for the site sync worker |
| `SITE_SYNC_BATCH_SIZE` | `100` | Max objects processed per site sync batch |
| `SITE_SYNC_CONNECT_TIMEOUT_SECONDS` | `10` | Site sync connect timeout |
| `SITE_SYNC_READ_TIMEOUT_SECONDS` | `120` | Site sync read timeout |
| `SITE_SYNC_MAX_RETRIES` | `2` | Site sync retry count |
| `SITE_SYNC_CLOCK_SKEW_TOLERANCE_SECONDS` | `1.0` | Allowed skew between peers |

### Site identity values used by the UI

These are read directly by UI pages:

| Variable | Description |
| --- | --- |
| `SITE_ID` | Local site identifier shown in the UI |
| `SITE_ENDPOINT` | Public endpoint for this site |
| `SITE_REGION` | Display region for the local site |

## 7. Data Layout

With the default `STORAGE_ROOT=./data`, the Rust server writes:

```text
data/
  <bucket>/
  .myfsio.sys/
    config/
      iam.json
      bucket_policies.json
      connections.json
      gc_history.json
      integrity_history.json
      metrics_history.json
      operation_metrics.json
    buckets/<bucket>/
      meta/
      versions/
    multipart/
    keys/
```

Important files:

- `data/.myfsio.sys/config/iam.json`: IAM users, access keys, and inline policies
- `data/.myfsio.sys/config/bucket_policies.json`: bucket policies
- `data/.myfsio.sys/config/connections.json`: replication connection settings
- `data/.myfsio.sys/config/.secret`: persisted secret key when one has been generated for the install

## 8. Background Services

The Rust server can start several workers from the same process.

### Lifecycle

Enable with:

```bash
LIFECYCLE_ENABLED=true cargo run -p myfsio-server --
```

Current Rust behavior:

- Runs as a Tokio background task, not a cron job
- Default interval is 3600 seconds
- Evaluates bucket lifecycle configuration and applies expiration and multipart abort rules

At the moment, the interval is hardcoded through `LifecycleConfig::default()` rather than exposed as an environment variable.

### Garbage collection

Enable with:

```bash
GC_ENABLED=true cargo run -p myfsio-server --
```

Current Rust defaults from `GcConfig::default()`:

- Run every 6 hours
- Temp files older than 24 hours are eligible for cleanup
- Multipart uploads older than 7 days are eligible for cleanup
- Lock files older than 1 hour are eligible for cleanup

Those GC timings are currently hardcoded defaults, not environment-driven configuration.

### Integrity scanning

Enable with:

```bash
INTEGRITY_ENABLED=true cargo run -p myfsio-server --
```

Current Rust defaults from `IntegrityConfig::default()`:

- Run every 24 hours
- Batch size 1000
- Auto-heal disabled

### Metrics history

Enable with:

```bash
METRICS_HISTORY_ENABLED=true cargo run -p myfsio-server --
```

Tune it with:

```bash
METRICS_HISTORY_INTERVAL_MINUTES=10
METRICS_HISTORY_RETENTION_HOURS=72
```

Snapshots are stored in `data/.myfsio.sys/config/metrics_history.json`.

### Operation metrics

Enable with:

```bash
OPERATION_METRICS_ENABLED=true cargo run -p myfsio-server --
```

Tune it with:

```bash
OPERATION_METRICS_INTERVAL_MINUTES=5
OPERATION_METRICS_RETENTION_HOURS=24
```

Snapshots are stored in `data/.myfsio.sys/config/operation_metrics.json`.

## 9. Encryption and KMS

Object encryption and built-in KMS are both optional.

```bash
ENCRYPTION_ENABLED=true KMS_ENABLED=true cargo run -p myfsio-server --
```

Notes:

- If `ENCRYPTION_ENABLED=true` and `SECRET_KEY` is not configured, the server still starts, but `--check-config` warns that secure-at-rest config encryption is unavailable.
- KMS and the object encryption master key live under `data/.myfsio.sys/keys/`.

## 10. Docker

Build the Rust image from the repository root:

```bash
docker build -t myfsio .
docker run --rm \
  -p 5000:5000 \
  -p 5100:5100 \
  -v "$PWD/data:/app/data" \
  myfsio
```

The container entrypoint runs `/usr/local/bin/myfsio-server`.

Inside the image:

- `HOST=0.0.0.0`
- `PORT=5000`
- `STORAGE_ROOT=/app/data`

If you want generated links and presigned URLs to use an external hostname, set `API_BASE_URL`.

## 11. Linux Installer

The repository includes `scripts/install.sh`. For the Rust server, build the binary first and pass the path explicitly:

```bash
cargo build --release -p myfsio-server

sudo ./scripts/install.sh --binary ./target/release/myfsio-server
```

The installer copies that binary to `/opt/myfsio/myfsio`, creates `/opt/myfsio/myfsio.env`, and can register a `myfsio.service` systemd unit.

## 12. Updating and Rollback

Recommended update flow:

1. Stop the running service.
2. Back up `data/.myfsio.sys/config/`.
3. Build or download the new Rust binary.
4. Run `myfsio-server --check-config` against the target environment.
5. Start the service and verify `/myfsio/health`.

Example backup:

```bash
cp -r data/.myfsio.sys/config config-backup
```

Health check:

```bash
curl http://127.0.0.1:5000/myfsio/health
```

The response includes the active Rust crate version:

```json
{
  "status": "ok",
  "version": "0.5.0"
}
```

## 13. Credential Reset

To rotate the bootstrap admin credentials:

```bash
cargo run -p myfsio-server -- --reset-cred
```

The command:

- backs up the existing IAM file with a timestamped `.bak-...` suffix
- writes a fresh admin config
- respects `ADMIN_ACCESS_KEY` and `ADMIN_SECRET_KEY` if you set them

## 14. Testing

Run the Rust test suite:

```bash
cargo test
```

If you are validating documentation changes for the UI, the most relevant coverage lives under:

- `crates/myfsio-server/tests`
- `crates/myfsio-storage/src`

## 15. API Notes

The Rust server exposes:

- `GET /myfsio/health`
- S3 bucket and object operations on `/<bucket>` and `/<bucket>/<key>`
- UI routes under `/ui/...`
- admin routes under `/admin/...`
- KMS routes under `/kms/...`

For a route-level view, inspect:

- `crates/myfsio-server/src/lib.rs`
- `crates/myfsio-server/src/handlers/`
