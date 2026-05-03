# MyFSIO

MyFSIO is an S3-compatible object storage server with a Rust runtime and a filesystem-backed storage engine. The repository root is the Cargo workspace; the server serves both the S3 API and the built-in web UI from a single process.

## Features

- S3-compatible REST API with Signature Version 4 authentication
- Browser UI for buckets, objects, IAM users, policies, replication, metrics, and site administration
- Filesystem-backed storage rooted at `data/`
- Bucket versioning, multipart uploads, presigned URLs, CORS, object and bucket tagging
- Server-side encryption and built-in KMS support
- Optional background services for lifecycle, garbage collection, integrity scanning, operation metrics, and system metrics history
- Replication, site sync, and static website hosting support

## Runtime Model

MyFSIO now runs as one Rust process:

- API listener on `HOST` + `PORT` (default `127.0.0.1:5000`)
- UI listener on `HOST` + `UI_PORT` (default `127.0.0.1:5100`)
- Shared state for storage, IAM, policies, sessions, metrics, and background workers

If you want API-only mode, set `UI_ENABLED=false`. There is no separate "UI-only" runtime anymore.

## Quick Start

From the repository root:

```bash
cargo run -p myfsio-server --
```

Useful URLs:

- UI: `http://127.0.0.1:5100/ui`
- API: `http://127.0.0.1:5000/`
- Health: `http://127.0.0.1:5000/myfsio/health`

On first boot, MyFSIO creates `data/.myfsio.sys/config/iam.json` and prints the generated admin access key and secret key to the console.

### Common CLI commands

```bash
# Show resolved configuration
cargo run -p myfsio-server -- --show-config

# Validate configuration and exit non-zero on critical issues
cargo run -p myfsio-server -- --check-config

# Reset admin credentials
cargo run -p myfsio-server -- --reset-cred

# API only
UI_ENABLED=false cargo run -p myfsio-server --
```

## Building a Binary

```bash
cargo build --release -p myfsio-server
```

Binary locations:

- Linux/macOS: `target/release/myfsio-server`
- Windows: `target/release/myfsio-server.exe`

Run the built binary directly:

```bash
./target/release/myfsio-server
```

## Configuration

The server reads environment variables from the process environment and also loads, when present:

- `/opt/myfsio/myfsio.env`
- `.env`
- `myfsio.env`

Core settings:

| Variable | Default | Description |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Bind address for API and UI listeners |
| `PORT` | `5000` | API port |
| `UI_PORT` | `5100` | UI port |
| `UI_ENABLED` | `true` | Disable to run API-only |
| `STORAGE_ROOT` | `./data` | Root directory for buckets and system metadata |
| `IAM_CONFIG` | `<STORAGE_ROOT>/.myfsio.sys/config/iam.json` | IAM config path |
| `API_BASE_URL` | unset | Public API base used by the UI and presigned URL generation |
| `AWS_REGION` | `us-east-1` | Region used in SigV4 scope |
| `SIGV4_TIMESTAMP_TOLERANCE_SECONDS` | `900` | Allowed request time skew (regular SigV4) |
| `STRICT_STREAMING_SIGV4` | `false` | When `true`, reject streaming SigV4 (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD*`) requests because per-chunk signature validation is not yet implemented. When `false` (default) the server logs a warning and accepts the request without validating chunk signatures — leave it `false` only if you need AWS CLI/SDK compatibility for large uploads and trust the network |
| `ALLOW_INTERNAL_ENDPOINTS` | `false` | Permit relay/replication targets to resolve to loopback / RFC1918 / link-local / CGNAT addresses. Required for local cluster testing; leave disabled in production unless you intentionally federate over private networks |
| `RATE_LIMIT_STORAGE_URI` | `memory://` | Rate-limit backend. Only `memory://` is supported today; any other value logs a warning and falls back to in-memory limits |
| `PEER_SIGV4_TIMESTAMP_TOLERANCE_SECONDS` | `60` | Stricter skew enforced for peer-credential SigV4 requests |
| `PEER_NONCE_CACHE_SIZE` | `10000` | Replay-detection LRU capacity for peer requests |
| `ALLOW_LEGACY_HEADER_AUTH` | `false` | Accept legacy `x-access-key`/`x-secret-key` headers (peer creds are SigV4-only regardless) |
| `PEER_REQUIRE_HTTPS` | `false` | Reject non-https peer endpoint registrations |
| `MYFSIO_CLUSTER_PSK` | unset | Pre-shared key enabling cross-site admin federation (`/myfsio/admin/peer/*` + `/myfsio/admin/relay/*`). Same value on every node |
| `RELAY_IDEMPOTENCY_CACHE_SIZE` | `10000` | LRU capacity for relay idempotency keys |
| `RELAY_IDEMPOTENCY_TTL_SECONDS` | `3600` | TTL for cached relay responses |
| `AUDIT_LOG_ENABLED` | `false` | Write JSONL audit lines for relayed admin actions |
| `PRESIGNED_URL_MIN_EXPIRY_SECONDS` | `1` | Minimum presigned URL expiry |
| `PRESIGNED_URL_MAX_EXPIRY_SECONDS` | `604800` | Maximum presigned URL expiry |
| `SECRET_KEY` | loaded from `.myfsio.sys/config/.secret` if present | Session signing key and IAM-at-rest encryption key |
| `ADMIN_ACCESS_KEY` | unset | Optional first-run or reset access key |
| `ADMIN_SECRET_KEY` | unset | Optional first-run or reset secret key |

Feature toggles:

| Variable | Default |
| --- | --- |
| `ENCRYPTION_ENABLED` | `false` |
| `KMS_ENABLED` | `false` |
| `GC_ENABLED` | `false` |
| `INTEGRITY_ENABLED` | `false` |
| `LIFECYCLE_ENABLED` | `false` |
| `METRICS_HISTORY_ENABLED` | `false` |
| `OPERATION_METRICS_ENABLED` | `false` |
| `WEBSITE_HOSTING_ENABLED` | `false` |
| `SITE_SYNC_ENABLED` | `false` |

Metrics and replication tuning:

| Variable | Default |
| --- | --- |
| `OPERATION_METRICS_INTERVAL_MINUTES` | `5` |
| `OPERATION_METRICS_RETENTION_HOURS` | `24` |
| `METRICS_HISTORY_INTERVAL_MINUTES` | `5` |
| `METRICS_HISTORY_RETENTION_HOURS` | `24` |
| `REPLICATION_CONNECT_TIMEOUT_SECONDS` | `5` |
| `REPLICATION_READ_TIMEOUT_SECONDS` | `120` |
| `REPLICATION_MAX_RETRIES` | `2` |
| `REPLICATION_STREAMING_THRESHOLD_BYTES` | `10485760` |
| `REPLICATION_MAX_FAILURES_PER_BUCKET` | `50` |
| `REPLICATION_HEALER_ENABLED` | `true` |
| `REPLICATION_HEALER_INTERVAL_SECONDS` | `60` |
| `REPLICATION_HEALER_MAX_ATTEMPTS` | `12` |
| `SITE_SYNC_INTERVAL_SECONDS` | `60` |
| `SITE_SYNC_BATCH_SIZE` | `100` |
| `SITE_SYNC_CONNECT_TIMEOUT_SECONDS` | `10` |
| `SITE_SYNC_READ_TIMEOUT_SECONDS` | `120` |
| `SITE_SYNC_MAX_RETRIES` | `2` |
| `SITE_SYNC_CLOCK_SKEW_TOLERANCE_SECONDS` | `1.0` |

UI asset overrides:

| Variable | Default |
| --- | --- |
| `TEMPLATES_DIR` | built-in crate templates directory |
| `STATIC_DIR` | built-in crate static directory |

See [docs.md](./docs.md) for the full Rust-side operations guide.

## Cluster Connections — Peer Creds vs S3 Creds

A connection record (created via the UI form `POST /ui/connections/create`, fields: `name`, `endpoint_url`, `region`, `access_key`, `secret_key`) holds the credentials used to talk to another MyFSIO site. There are two distinct credential types and they are NOT interchangeable:

- **Peer credentials** (`PEERAK…`/`PEERSK…`, created via `POST /myfsio/admin/peer-credentials`). SigV4-only, scoped to `/myfsio/admin/cluster/overview` and `/myfsio/admin/peer/*`. Use these in connections referenced by site-registry peers (`peer.connection_id`) for cluster federation, the federated cluster overview, peer health checks, and the relay path. Peer credentials cannot list buckets or read objects, so they are not usable for replication or bidirectional site sync.
- **Regular IAM credentials** (admin or scoped). Use these in connections referenced by replication rules (`ReplicationRule.target_connection_id`) and bidirectional site sync. These need bucket list / object read / object write permissions on the remote site.

If you federate two sites and also replicate between them, you typically need TWO connection records per peer relationship — one with peer creds for cluster federation, one with regular creds for replication / site sync.

## Data Layout

```text
data/
  <bucket>/
  .myfsio.sys/
    config/
      iam.json
      bucket_policies.json
      connections.json
      operation_metrics.json
      metrics_history.json
    buckets/<bucket>/
      meta/
      versions/
    multipart/
    keys/
```

## Docker

Build the Rust image from the repository root:

```bash
docker build -t myfsio .
docker run --rm -p 5000:5000 -p 5100:5100 -v "${PWD}/data:/app/data" myfsio
```

If the instance sits behind a reverse proxy, set `API_BASE_URL` to the public S3 endpoint.

## Linux Installation

The repository includes `scripts/install.sh` for systemd-style Linux installs. Build the Rust binary first, then pass it to the installer:

```bash
cargo build --release -p myfsio-server

sudo ./scripts/install.sh --binary ./target/release/myfsio-server
```

The installer copies the binary into `/opt/myfsio/myfsio`, writes `/opt/myfsio/myfsio.env`, and can register a `myfsio.service` unit.

## Testing

Run the Rust test suite from the workspace:

```bash
cargo test
```

## Health Check

`GET /myfsio/health` returns:

```json
{
  "status": "ok",
  "version": "x.x.x"
}
```

The `version` field is populated at build time from the Rust crate version in `crates/myfsio-server/Cargo.toml`.
