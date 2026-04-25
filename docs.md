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
| `SESSION_LIFETIME_DAYS` | `1` | UI session lifetime in days |
| `LOG_LEVEL` | `INFO` | Log verbosity (also honored as `RUST_LOG`) |
| `REQUEST_BODY_TIMEOUT_SECONDS` | `60` | Per-request body read timeout |
| `MULTIPART_MIN_PART_SIZE` | `5242880` | Minimum part size enforced where applicable (5 MiB) |
| `BULK_DELETE_MAX_KEYS` | `1000` | Maximum keys per UI bulk-delete request |
| `STREAM_CHUNK_SIZE` | `1048576` | Default streaming chunk size for opt-in routes |
| `OBJECT_KEY_MAX_LENGTH_BYTES` | `1024` | Maximum object key length |
| `OBJECT_CACHE_MAX_SIZE` | `100` | Object metadata cache capacity |
| `BUCKET_CONFIG_CACHE_TTL_SECONDS` | `30` | Bucket config cache TTL |
| `OBJECT_TAG_LIMIT` | `50` | Maximum tags per object |

### Rate limiting

| Variable | Default | Description |
| --- | --- | --- |
| `RATE_LIMIT_DEFAULT` | `5000 per minute` | Default S3 / KMS rate limit. Accepts `N per <s/m/h/d>` or `N/<seconds>` |
| `RATE_LIMIT_LIST_BUCKETS` | inherits `RATE_LIMIT_DEFAULT` | Override for `GET /` |
| `RATE_LIMIT_BUCKET_OPS` | inherits `RATE_LIMIT_DEFAULT` | Override for `/{bucket}` |
| `RATE_LIMIT_OBJECT_OPS` | inherits `RATE_LIMIT_DEFAULT` | Override for `/{bucket}/{key}` |
| `RATE_LIMIT_HEAD_OPS` | inherits `RATE_LIMIT_DEFAULT` | Override for HEAD requests |
| `RATE_LIMIT_ADMIN` | `60 per minute` | Override for `/admin/*` |
| `RATE_LIMIT_STORAGE_URI` | `memory://` | Backend for rate-limit state. Only `memory://` is supported today |

### CORS and proxying

| Variable | Default | Description |
| --- | --- | --- |
| `CORS_ORIGINS` | `*` | Server-level allowed origins (comma-separated) |
| `CORS_METHODS` | `GET,PUT,POST,DELETE,OPTIONS,HEAD` | Server-level allowed methods |
| `CORS_ALLOW_HEADERS` | `*` | Allowed request headers |
| `CORS_EXPOSE_HEADERS` | `*` | Headers exposed to the browser |
| `NUM_TRUSTED_PROXIES` | `0` | Trusted reverse-proxy count. Forwarded-IP headers are ignored when `0` |
| `ALLOWED_REDIRECT_HOSTS` | empty | Comma-separated whitelist of safe UI login redirect hosts |
| `ALLOW_INTERNAL_ENDPOINTS` | `false` | Gate for internal diagnostic routes |

### Feature toggles

| Variable | Default | Description |
| --- | --- | --- |
| `ENCRYPTION_ENABLED` | `false` | Enable object encryption support |
| `KMS_ENABLED` | `false` | Enable built-in KMS support |
| `GC_ENABLED` | `false` | Start the garbage collector worker |
| `INTEGRITY_ENABLED` | `false` | Start the integrity worker |
| `INTEGRITY_AUTO_HEAL` | `false` | When the periodic scan finishes, attempt to heal each issue (peer-fetch corrupted bytes, drop phantom metadata, etc.) |
| `INTEGRITY_DRY_RUN` | `false` | Report what the periodic scan would heal without touching anything |
| `INTEGRITY_INTERVAL_HOURS` | `24` | Period between background integrity scans |
| `INTEGRITY_BATCH_SIZE` | `10000` | Max objects scanned per cycle |
| `INTEGRITY_HEAL_CONCURRENCY` | `4` | Max concurrent heal tasks per cycle |
| `INTEGRITY_QUARANTINE_RETENTION_DAYS` | `7` | How long to retain quarantined files (cleaned up by GC) |
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

### Garbage collection

| Variable | Default | Description |
| --- | --- | --- |
| `GC_INTERVAL_HOURS` | `6` | Hours between GC cycles |
| `GC_TEMP_FILE_MAX_AGE_HOURS` | `24` | Delete temp files older than this |
| `GC_MULTIPART_MAX_AGE_DAYS` | `7` | Delete orphaned multipart uploads older than this |
| `GC_LOCK_FILE_MAX_AGE_HOURS` | `1` | Delete stale lock files older than this |
| `GC_DRY_RUN` | `false` | Log deletions without removing files |

### Encryption tuning

| Variable | Default | Description |
| --- | --- | --- |
| `ENCRYPTION_CHUNK_SIZE_BYTES` | `65536` | Plaintext chunk size for streaming AES-256-GCM (64 KiB) |
| `KMS_GENERATE_DATA_KEY_MIN_BYTES` | `1` | Minimum size for `generate-data-key` |
| `KMS_GENERATE_DATA_KEY_MAX_BYTES` | `1024` | Maximum size for `generate-data-key` |
| `LIFECYCLE_MAX_HISTORY_PER_BUCKET` | `50` | Max lifecycle history records kept per bucket |

### Site identity values used by the UI

These are read directly by UI pages:

| Variable | Default | Description |
| --- | --- | --- |
| `SITE_ID` | unset | Local site identifier shown in the UI |
| `SITE_ENDPOINT` | unset | Public endpoint for this site |
| `SITE_REGION` | matches `AWS_REGION` | Display region for the local site |
| `SITE_PRIORITY` | `100` | Routing priority (lower = preferred) |

## 7. Data Layout

With the default `STORAGE_ROOT=./data`, the Rust server writes:

```text
data/
  <bucket>/                              # raw object data
  .myfsio.sys/
    config/
      .secret                            # persisted SECRET_KEY (if generated)
      iam.json                           # IAM users / access keys / policies
      bucket_policies.json               # legacy bucket policies (fallback only)
      connections.json                   # remote endpoint credentials
      replication_rules.json             # replication rules
      site_registry.json                 # local site + peer registry
      website_domains.json               # domain → bucket mapping (if enabled)
      gc_history.json                    # GC execution history (if enabled)
      integrity_history.json             # integrity scan history (if enabled)
      metrics_history.json               # system metrics history (if enabled)
      operation_metrics.json             # API operation metrics (if enabled)
    buckets/<bucket>/
      .bucket.json                       # bucket config (versioning, cors, lifecycle, etc.)
      meta/                              # per-object metadata
      versions/                          # archived versions (if versioning enabled)
      lifecycle_history.json             # lifecycle action log (if any rule has fired)
      replication_failures.json          # bounded failure log
      site_sync_state.json               # bidi sync watermark
    multipart/                           # in-progress multipart uploads
    keys/
      kms_master.key                     # 32-byte master key (base64)
      kms_keys.json                      # KMS keys, encrypted under master key
```

Notable files:

- `iam.json` is Fernet-encrypted at rest when `SECRET_KEY` is set.
- `bucket_policies.json` is read only as a fallback for policies that pre-date per-bucket `.bucket.json`.
- `kms_master.key` is plaintext on disk — protect `keys/` with filesystem permissions.
- `*_history.json` files only appear when their owning service has been enabled at least once.

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

Defaults (override with the env vars in section 6):

- `GC_INTERVAL_HOURS=6`
- `GC_TEMP_FILE_MAX_AGE_HOURS=24`
- `GC_MULTIPART_MAX_AGE_DAYS=7`
- `GC_LOCK_FILE_MAX_AGE_HOURS=1`
- `GC_DRY_RUN=false`

Each GC cycle also sweeps `data/.myfsio.sys/quarantine/<bucket>/<ts>/` directories whose `<ts>` mtime is older than `INTEGRITY_QUARANTINE_RETENTION_DAYS`, freeing the bytes recorded in `quarantine_bytes_freed` / `quarantine_entries_deleted` in the result JSON.

History is persisted at `data/.myfsio.sys/config/gc_history.json` and can be triggered manually via `POST /admin/gc/run` (use `{"dry_run": true}` to preview).

### Integrity scanning

Enable with:

```bash
INTEGRITY_ENABLED=true cargo run -p myfsio-server --
```

Tune with:

```bash
INTEGRITY_INTERVAL_HOURS=24
INTEGRITY_BATCH_SIZE=10000
INTEGRITY_AUTO_HEAL=false
INTEGRITY_DRY_RUN=false
INTEGRITY_HEAL_CONCURRENCY=4
INTEGRITY_QUARANTINE_RETENTION_DAYS=7
```

When `INTEGRITY_AUTO_HEAL=true` (and `INTEGRITY_DRY_RUN=false`), each scan ends with a heal phase that processes the issues it just recorded. For `corrupted_object` the bad bytes are renamed into `data/.myfsio.sys/quarantine/<bucket>/<ts>/<key>` and the heal logic tries, in order:

1. **Pull from peer.** If a replication rule for the bucket points at a healthy remote whose `HEAD` returns the same ETag the local index has, the body is streamed to a temp file, MD5-verified against the stored ETag, and atomically swapped into the live path. The poison flags are cleared on success.
2. **Poison the entry.** If there is no replication target, the peer disagrees on the ETag, the peer is unreachable, or the downloaded body fails verification, the index entry is mutated to add `__corrupted__: "true"`, `__corrupted_at__`, `__corruption_detail__`, and `__quarantine_path__`. The data file stays in quarantine for `INTEGRITY_QUARANTINE_RETENTION_DAYS`.

Subsequent reads (`GET`, `HEAD`, `CopyObject` source) on a poisoned key return `500 ObjectCorrupted` instead of serving rotted bytes; replication push skips poisoned keys; subsequent integrity scans skip poisoned keys instead of re-flagging them. Overwriting the key with a fresh `PUT` clears the poison.

`stale_version`, `etag_cache_inconsistency`, and `phantom_metadata` issues are healed locally (move-to-quarantine, rebuild cache, drop entry); `orphaned_object` is reported only.

Override per-invocation by passing `auto_heal` / `dry_run` to `POST /admin/integrity/run`. The response and history records now include a `heal_stats` map keyed by issue type with `{found, healed, poisoned, peer_mismatch, peer_unavailable, verify_failed, failed, skipped}`. History is at `data/.myfsio.sys/config/integrity_history.json`.

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
