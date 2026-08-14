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

# One-shot: tag existing peer_inbound_access_key entries as peer credentials
# (restricts them to cluster overview and peer relay paths, and clears their IAM policies)
cargo run -p myfsio-server -- --migrate-peer-creds

# One-shot: convert aggregate _index.json metadata to per-object sidecar files.
# Run with the server stopped. Older binaries cannot read migrated metadata.
cargo run -p myfsio-server -- --migrate-meta
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
| `API_BASE_URL` | derived as `http://<HOST>:<PORT>` | Public-facing API base used by the UI and presigned URL generation |
| `TEMPLATES_DIR` | built-in templates dir | Optional override for UI templates |
| `STATIC_DIR` | built-in static dir | Optional override for static assets |

### Storage and auth

| Variable | Default | Description |
| --- | --- | --- |
| `STORAGE_ROOT` | `./data` | Root for buckets and internal state |
| `IAM_CONFIG` | `<STORAGE_ROOT>/.myfsio.sys/config/iam.json` | IAM config path |
| `AWS_REGION` | `us-east-1` | SigV4 region |
| `SIGV4_TIMESTAMP_TOLERANCE_SECONDS` | `900` | Allowed request time skew for regular SigV4 |
| `STRICT_STREAMING_SIGV4` | `true` | Validate streaming SigV4 chunk chains, the final zero-length chunk, and signed trailers. `false` accepts invalid chunk signatures as a compatibility escape hatch but still verifies checksum trailers |
| `PEER_SIGV4_TIMESTAMP_TOLERANCE_SECONDS` | `60` | Stricter time skew enforced for peer-credential SigV4 requests |
| `PEER_NONCE_CACHE_SIZE` | `10000` | Capacity of the in-memory replay-detection LRU for peer requests |
| `ALLOW_LEGACY_HEADER_AUTH` | `false` | When `true`, accepts the legacy `x-access-key`/`x-secret-key` header pair. Default is off; SigV4 is preferred. Peer credentials are SigV4-only regardless of this flag |
| `PEER_REQUIRE_HTTPS` | `false` | When `true`, peer endpoint registration rejects non-`https://` URLs. The server logs a startup warning if any registered peer uses `http://` and this flag is unset |
| `MYFSIO_CLUSTER_PSK` | unset | Pre-shared key enabling `/myfsio/admin/peer/*` (inbound relay) and `/myfsio/admin/relay/*` (outbound dispatch). Same value required on every node. When unset, Phase 3 federation is disabled |
| `RELAY_IDEMPOTENCY_CACHE_SIZE` | `10000` | LRU capacity for relay idempotency dedup |
| `RELAY_IDEMPOTENCY_TTL_SECONDS` | `3600` | How long a cached relay response is replayable for the same idempotency key |
| `AUDIT_LOG_ENABLED` | `false` | When `true`, append-only JSONL log of relayed admin actions at `<STORAGE_ROOT>/.myfsio.sys/audit/YYYYMMDD.jsonl` |
| `PRESIGNED_URL_MIN_EXPIRY_SECONDS` | `1` | Minimum presigned URL lifetime; the UI validates custom expiry values against this bound |
| `PRESIGNED_URL_MAX_EXPIRY_SECONDS` | `604800` | Maximum presigned URL lifetime; the UI reports when a preset is clamped to this bound |
| `SECRET_KEY` | auto-generated | Session signing and IAM config encryption key. Resolved from the environment variable first, then `.myfsio.sys/config/.secret`. When neither is set, the server generates a random 32-byte base64 secret, persists it to `.myfsio.sys/config/.secret` (owner-only on Unix), and reuses it on every later start. The literal placeholder `dev-secret-key` is rejected from both the environment and the file |
| `ADMIN_ACCESS_KEY` | unset | Optional deterministic first-run/reset access key |
| `ADMIN_SECRET_KEY` | unset | Optional deterministic first-run/reset secret key |
| `SESSION_LIFETIME_DAYS` | `1` | UI session lifetime in days |
| `SESSION_COOKIE_SECURE` | `false` | Mark the UI session cookie as Secure |
| `LOG_LEVEL` | `INFO` | Log verbosity (also honored as `RUST_LOG`) |
| `DISPLAY_TIMEZONE` | `UTC` | Timezone used by UI date formatting |
| `REQUEST_BODY_TIMEOUT_SECONDS` | `300` | Idle timeout between request-body reads; stalled uploads receive `400 RequestTimeout` |
| `UPLOAD_STREAM_BUFFER_BYTES` | `8388608` | In-memory buffer between client stream and disk writer for uploads (8 MiB); `0` disables |
| `MULTIPART_MIN_PART_SIZE` | `5242880` | Minimum part size enforced where applicable (5 MiB) |
| `MULTIPART_OBJECT_LAYOUT` | `segments` | How completed multipart objects are stored: `segments` keeps part files and completes in O(metadata) (recommended, especially on HDD/ext4); `concat` assembles one file like older releases. Affects new completes only; both layouts stay readable. Note: binaries older than this feature cannot read `segments` objects |
| `METADATA_LAYOUT` | `sidecar` | How object metadata is written: `sidecar` writes one `.__myfsio_meta__<name>.json` file per object (O(1) metadata updates, no shared rewrite); `index` keeps appending to the legacy per-directory `_index.json` (every update rewrites the whole directory index). Affects writes only; both layouts stay readable forever, and sidecars always take precedence over index entries. Note: binaries older than this feature cannot read sidecar metadata |
| `LISTING_INDEX_ENABLED` | `true` | Persistent per-bucket listing index and aggregate counters. Flat (no-delimiter) ListObjectsV2, bucket statistics, and quota projections are served from an ordered index persisted as `snapshot.json` + generation journals (`journal.<gen>.jsonl`) under `.myfsio.sys/buckets/<bucket>/listing/`, built once per bucket and updated incrementally on every write. Threshold compaction is sealed quickly and completed by a dedicated background worker instead of the PUT/DELETE path. The index is derived data: object sidecars and version records remain the source of truth, and corruption or an unsupported snapshot version triggers an automatic rebuild. Set `false` to use the legacy recursive walks. Force a rebuild anytime with `myfsio-server --rebuild-listing` (server stopped) |
| `GC_SEGMENT_MAX_AGE_HOURS` | `24` | Age before an orphaned (unreferenced) multipart segment directory is garbage-collected |
| `BULK_DELETE_MAX_KEYS` | `1000` | Maximum keys per UI bulk-delete request |
| `STREAM_CHUNK_SIZE` | `1048576` | Default streaming chunk size for opt-in routes |
| `OBJECT_KEY_MAX_LENGTH_BYTES` | `1024` | Maximum object key length |
| `OBJECT_CACHE_MAX_SIZE` | `1024` | Object metadata LRU cache capacity |
| `BUCKET_CONFIG_CACHE_TTL_SECONDS` | `30` | Bucket config cache TTL |
| `OBJECT_TAG_LIMIT` | `50` | Maximum tags per object |

The web UI uses 1024-byte binary units consistently and labels them `KiB`, `MiB`, `GiB`, `TiB`, and `PiB`. Presigned-link custom expiry values must be whole seconds; empty or non-numeric values are rejected, and any server-side bound adjustment is shown in the dialog.

### Credential and secret files

- IAM mutations are serialized and atomic. Every write path that changes `iam.json` (user create/update/delete, enable/disable, access-key create/delete, policy updates, secret rotation, peer-credential create/delete/tag, and first-run bootstrap) takes a process-wide mutation lock and performs one load-modify-save cycle under it, so concurrent edits can no longer lose an update or resurrect a revoked key. The save itself writes a uniquely named temp file in the same directory, fsyncs it, renames it over `iam.json`, and fsyncs the parent directory on platforms that support it, so a crash mid-write cannot truncate or corrupt the credential store. Read paths (authentication, authorization, listing) do not take the mutation lock.
- First-run and `--reset-cred` credentials are encrypted at rest. Bootstrap now writes through the same IAM service the running server uses, so when `SECRET_KEY` is configured (from the environment or `.myfsio.sys/config/.secret`) the initial admin file is fernet-encrypted with the `MYFSIO_IAM_ENC:` prefix instead of being left as plaintext JSON.
- Plaintext IAM configs migrate on load. When the service starts with a secret configured and finds an unencrypted but well-formed `iam.json`, it re-saves it once through the encrypted atomic path and logs a single info line. A file that is encrypted-but-undecryptable, or that fails to parse, is never rewritten.
- The generated secret is only echoed when it was generated. The first-run banner still prints the access key and the file location, but when `ADMIN_SECRET_KEY` supplied the value the secret line reads `(from ADMIN_SECRET_KEY)` rather than repeating the secret to stdout and the console scrollback.
- The server generates its own `.secret` when one is needed. Previously only the Linux installer created `.myfsio.sys/config/.secret`, so a bare `myfsio-server serve` without `SECRET_KEY` ran with no secret at all and stored IAM credentials as plaintext. The resolution path now generates and persists a random 32-byte base64 secret when the environment variable is unset and the file is missing or empty, and reuses it afterwards. If the secret cannot be persisted the server keeps running without one rather than encrypting against a key that would be lost on restart. The placeholder `dev-secret-key` is rejected from both sources; a `.secret` containing it is left on disk untouched and logged as a warning, so deleting the file is all that is needed to get a real one generated.
- Writes to secret files are atomic. `iam.json`, `connections.json`, `.connections_key`, `kms_keys.json`, and a generated `.secret` are all written to a uniquely named temp file in the same directory, fsynced, renamed into place, and followed by a parent-directory fsync on Unix, so a crash mid-write cannot truncate a credential or key store. `connections.json` previously used a single fixed temp name, which could collide between concurrent saves.
- Secret-bearing files are created owner-only (`0600`) on Unix: `iam.json` and its `.bak-...` backups, `.myfsio.sys/keys/kms_master.key`, `.myfsio.sys/keys/kms_keys.json`, `.myfsio.sys/keys/master.key`, `.myfsio.sys/config/.connections_key`, and `.myfsio.sys/config/connections.json`. Existing `kms_master.key`, `master.key`, `.connections_key`, and `.secret` files are tightened to `0600` best-effort when they are read, so deployments created before this change are corrected on the next start. On Windows the permission step is a no-op and files inherit directory ACLs.

### Rate limiting

| Variable | Default | Description |
| --- | --- | --- |
| `RATE_LIMIT_DEFAULT` | `50000 per minute` | Default S3 / KMS rate limit. Accepts `N per <s/m/h/d>` or `N/<seconds>` |
| `RATE_LIMIT_LIST_BUCKETS` | inherits `RATE_LIMIT_DEFAULT` | Override for `GET /` |
| `RATE_LIMIT_BUCKET_OPS` | inherits `RATE_LIMIT_DEFAULT` | Override for `/{bucket}` |
| `RATE_LIMIT_OBJECT_OPS` | inherits `RATE_LIMIT_DEFAULT` | Override for `/{bucket}/{key}` |
| `RATE_LIMIT_HEAD_OPS` | inherits `RATE_LIMIT_DEFAULT` | Override for HEAD requests |
| `RATE_LIMIT_ADMIN` | `60 per minute` | Override for `/myfsio/admin/*` |
| `RATE_LIMIT_UI_LOGIN` | `20 per minute` | Per-IP limit for `GET`/`POST /login`. Browser form posts get a styled 429 page with `Retry-After`; JSON/AJAX callers get a 429 JSON error |
| `RATE_LIMIT_STORAGE_URI` | `memory://` | Backend for rate-limit state. Only `memory://` is supported today |

### Disk admission control

| Variable | Default | Description |
| --- | --- | --- |
| `HDD_READ_CONCURRENCY` | `0` (disabled) | Maximum concurrent S3 object data reads; `2` is recommended for HDD storage |
| `HDD_WRITE_CONCURRENCY` | `0` (disabled) | Maximum concurrent S3 object data writes; `2` is recommended for HDD storage |
| `DISK_QUEUE_TIMEOUT_SECONDS` | `15` | Maximum wait for a disk permit before returning `503 SlowDown` |

These limits gate S3 object data reads and writes only. Admin and UI requests, HEAD requests, and metadata operations are unaffected.

### CORS and proxying

| Variable | Default | Description |
| --- | --- | --- |
| `CORS_ORIGINS` | `*` | Server-level allowed origins (comma-separated) |
| `CORS_METHODS` | `GET,PUT,POST,DELETE,OPTIONS,HEAD` | Server-level allowed methods |
| `CORS_ALLOW_HEADERS` | `*` | Allowed request headers |
| `CORS_EXPOSE_HEADERS` | `*` | Headers exposed to the browser |
| `NUM_TRUSTED_PROXIES` | `0` | Trusted reverse-proxy count. Forwarded-IP headers are ignored when `0` |
| `ALLOWED_REDIRECT_HOSTS` | empty | Comma-separated whitelist of safe UI login redirect hosts |
| `ALLOW_INTERNAL_ENDPOINTS` | `false` | Permit outbound relay, replication, and webhook targets to resolve to loopback / RFC1918 / link-local / CGNAT addresses. Required for local cluster testing; leave disabled in production unless you intentionally federate over private networks |

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
| `INTEGRITY_HEAL_CONCURRENCY` | `1` | Max concurrent heal tasks per cycle |
| `INTEGRITY_SCAN_PACING_MS` | `0` | Optional delay between scanned objects |
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
| `METRICS_STORAGE_REFRESH_MINUTES` | `30` | Interval for refreshing total stored bytes in system metrics; minimum 5 |

### Replication and site sync

| Variable | Default | Description |
| --- | --- | --- |
| `REPLICATION_CONNECT_TIMEOUT_SECONDS` | `5` | Replication connect timeout |
| `REPLICATION_READ_TIMEOUT_SECONDS` | `120` | Replication per-part / per-attempt read timeout |
| `REPLICATION_PART_STALL_TIMEOUT_SECONDS` | `300` | Per-part zero-progress stall threshold before a replication upload is treated as stalled |
| `REPLICATION_MAX_RETRIES` | `2` | Replication retry count |
| `REPLICATION_STREAMING_THRESHOLD_BYTES` | `10485760` | Switch to streaming for large copies |
| `REPLICATION_MAX_FAILURES_PER_BUCKET` | `50` | Failure budget before a bucket is skipped |
| `REPLICATION_CONCURRENCY` | `4` | Fixed number of replication worker tasks |
| `REPLICATION_QUEUE_CAPACITY` | `10000` | Maximum queued replication events before overflow is persisted for healer retry |
| `REPLICATION_HEALER_ENABLED` | `true` | Background worker that auto-retries persisted replication failures (set `false` to disable) |
| `REPLICATION_HEALER_INTERVAL_SECONDS` | `60` | Healer pass interval; each pass re-runs eligible failures |
| `REPLICATION_HEALER_MAX_ATTEMPTS` | `12` | Per-object retry cap; failures with `failure_count` at or above this are skipped (manual retry still works) |
| `REPLICATION_FULL_RECONCILE_INTERVAL_HOURS` | `0` | Optional full object-listing and sidecar consistency pass interval in hours; `0` disables it |
| `SITE_SYNC_INTERVAL_SECONDS` | `60` | Poll interval for the site sync worker |
| `SITE_SYNC_BATCH_SIZE` | `100` | Max objects processed per site sync batch |
| `SITE_SYNC_CONNECT_TIMEOUT_SECONDS` | `10` | Site sync connect timeout |
| `SITE_SYNC_READ_TIMEOUT_SECONDS` | `120` | Site sync read timeout |
| `SITE_SYNC_MAX_RETRIES` | `2` | Site sync retry count |
| `SITE_SYNC_CLOCK_SKEW_TOLERANCE_SECONDS` | `1.0` | Allowed skew between peers |

- **A failed remote listing aborts the sync cycle.** If listing the remote bucket fails for any reason, the cycle for that bucket stops before anything is pulled or deleted and the reason is logged (`remote bucket '<name>' not found (skipping sync cycle to protect local data)` for a missing or renamed remote bucket, the underlying transport error otherwise). Previously a `NoSuchBucket`/404 response was treated as an empty remote listing, so a rule with `sync_deletions` enabled deleted every locally synchronized object the next time the remote bucket was missing or transiently unreachable.
- **A failed sync cycle is visible in the sync stats, not just the log.** Each failure increments the bucket's `errors` counter and stores `last_error` / `last_error_at`, which are persisted in `data/.myfsio.sys/config/site_sync_stats.json` and returned by `GET /myfsio/admin/sync-stats`. The counter feeds the per-peer `N err` badge on the Sites page and the `sync.errors` figure in the cluster overview, so a bucket whose cycles keep aborting no longer reports as healthy. The next successful cycle resets the bucket's counters and clears `last_error`. Stats files written before these fields existed still load.

### Garbage collection

| Variable | Default | Description |
| --- | --- | --- |
| `GC_INTERVAL_HOURS` | `6` | Hours between GC cycles |
| `GC_TEMP_FILE_MAX_AGE_HOURS` | `24` | Delete temp files older than this |
| `GC_MULTIPART_MAX_AGE_DAYS` | `7` | Delete orphaned multipart uploads older than this |
| `GC_LOCK_FILE_MAX_AGE_HOURS` | `1` | Delete stale lock files older than this |
| `GC_SEGMENT_MAX_AGE_HOURS` | `24` | Delete orphaned multipart segment directories older than this |
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

### Cross-site authentication

The Cluster dashboard on each site fetches `/myfsio/admin/cluster/overview` from every registered peer to render their cards. That endpoint is gated by `require_admin_or_registered_peer`, which accepts a request when **either**:

1. The signing principal is a full admin on the receiving site (policy `{"bucket":"*","actions":["*"]}`), **or**
2. The signing principal is a **peer credential** issued on the receiving site (an IAM record with the internal `peer_site_id` flag set; access keys conventionally start with `PEERAK…`).

Peer credentials are deliberately scoped: they can call `/myfsio/admin/cluster/overview` and the `/myfsio/admin/peer/*` relay surface, and they refuse `x-access-key`/`x-secret-key` (legacy) header authentication. They are not general S3 credentials — list/get user-management endpoints filter them out.

Issue a peer credential on the receiving site:

```bash
curl -X POST -H 'content-type: application/json' \
     -d '{"site_id":"us-west-1","display_name":"peer:us-west-1"}' \
     http://api.example.com/myfsio/admin/peer-credentials
# → { "user_id": "peer-…", "access_key": "PEERAK…", "secret_key": "PEERSK…", "site_id": "us-west-1" }
```

The returned access key/secret are what the *other* site signs with when calling here — copy them into that site's outbound Connection (or whatever it uses for cluster-overview). Symmetric setup for two sites `us-east-1` and `us-west-1`:

| On site | Action | Result |
| --- | --- | --- |
| `us-east-1` | `POST /myfsio/admin/peer-credentials {"site_id":"us-west-1"}` | Returns `(PEERAK_E, PEERSK_E)` to hand to `us-west-1` |
| `us-west-1` | `POST /myfsio/admin/peer-credentials {"site_id":"us-east-1"}` | Returns `(PEERAK_W, PEERSK_W)` to hand to `us-east-1` |
| `us-east-1` | Connection → `us-west-1` uses `(PEERAK_W, PEERSK_W)` | Local node signs cluster-overview to `us-west-1` |
| `us-west-1` | Connection → `us-east-1` uses `(PEERAK_E, PEERSK_E)` | Local node signs cluster-overview to `us-east-1` |

List with `GET /myfsio/admin/peer-credentials`; revoke with `DELETE /myfsio/admin/peer-credentials/{access_key}`.

#### Replay protection

Peer SigV4 requests are subject to a **60-second** clock-skew window (`PEER_SIGV4_TIMESTAMP_TOLERANCE_SECONDS`) and an in-memory `(access_key, signature)` LRU dedupe (`PEER_NONCE_CACHE_SIZE`). To prevent same-second false-positives, the server's outbound `peer_admin` client adds a unique signed `x-myfsio-nonce` header to every request, so two simultaneous overview pulls produce distinct signatures.

#### Migrating existing deployments

Releases prior to peer-credential namespacing reused regular IAM users for the **Peer Inbound Access Key** field. Run

```bash
cargo run -p myfsio-server -- --migrate-peer-creds
```

once on each site to retag those access keys. The migration:

- Refuses to migrate any access key that shares an IAM user with other access keys (it would clear that user's policies and convert all of its keys into peer credentials). Move the AK onto a dedicated user before retrying.
- Errors (with exit code 1) when the registry references an AK that is not present in IAM, instead of silently treating it as already-migrated.
- Clears the migrated user's policies. **If you used the same AK as a site-sync credential, you must reissue separate IAM users for site-sync** before relying on the data plane again — the migrated AK is now restricted to `/myfsio/admin/cluster/overview` and `/myfsio/admin/peer/*`.

The in-app **Documentation → Site Registry** page has a worked example with side-by-side cards.

### Cross-site admin actions (federated writes)

Once peer credentials are issued and `MYFSIO_CLUSTER_PSK` is set on every node, an admin can apply most write actions on a peer site through their local node. The local node signs a SigV4 request with the peer credential it holds for the target site and attaches three HMACs over the cluster PSK:

- `x-myfsio-cluster-attest` = `HMAC-SHA256(PSK, amz_date || origin_site_id || idempotency_key)` — proves the call comes from a cluster member
- `x-myfsio-admin-attest` = `HMAC-SHA256(PSK, amz_date || admin_user_id || method || canonical_path || body_sha256_hex || idempotency_key)` — proves a real admin authorised this exact relay request; inbound relay also requires a non-empty `x-myfsio-admin-user` header
- `x-myfsio-origin-site` must equal the peer principal's site_id on the target node

Plus a unique `x-myfsio-idempotency-key` (UUIDv4) for safe retry, a `x-myfsio-correlation-id` so origin and target audit entries can be joined, and `x-myfsio-nonce` to prevent same-second signature collisions.

#### Outbound (origin) — `/myfsio/admin/relay/{site_id}/{*path}`

Operators don't construct these signatures themselves. The local node exposes an outbound relay dispatcher: take any inbound `/myfsio/admin/peer/{...}` path, prefix it with `/myfsio/admin/relay/{target_site_id}/`, and the local node signs and forwards.

```bash
# Disable a user on us-west-1 from us-east-1's UI/API
curl -X POST https://us-east-1.example.com/myfsio/admin/relay/us-west-1/iam/users/u-someone/disable \
     -H 'authorization: AWS4-HMAC-SHA256 …'   # signed by us-east-1's local admin key
```

The response is the target site's response (status, headers, body) with `x-myfsio-correlation-id` and `x-myfsio-idempotency-key` echoed for audit/log lookup.

#### Inbound (target) — `/myfsio/admin/peer/{*}`

The target site mounts a parallel route set under `/myfsio/admin/peer/`:

| Outbound path | Underlying action |
| --- | --- |
| `POST /myfsio/admin/peer/sites` | Register peer site |
| `PUT/DELETE /myfsio/admin/peer/sites/{site_id}` | Update / delete peer site entry |
| `POST /myfsio/admin/peer/sites/{site_id}/health` | Re-check peer reachability |
| `POST /myfsio/admin/peer/iam/users/{id}/access-keys` | Issue access key for an existing user |
| `DELETE /myfsio/admin/peer/iam/users/{id}/access-keys/{ak}` | Revoke an access key |
| `POST /myfsio/admin/peer/iam/users/{id}/disable` and `/enable` | Toggle user enable flag |
| `POST/PUT/DELETE /myfsio/admin/peer/website-domains[/{domain}]` | Manage website domain mappings |
| `POST /myfsio/admin/peer/gc/run` | Trigger garbage collection |
| `POST /myfsio/admin/peer/integrity/run` | Trigger integrity scan |
| `GET /myfsio/admin/peer/{...}` | Read counterparts of the above (cluster-wide introspection) |

These accept **only** peer principals carrying valid attestation. Each request is dedup'd by `(origin_site_id, idempotency_key)` for `RELAY_IDEMPOTENCY_TTL_SECONDS`; replays return the cached response with header `x-myfsio-idempotent-replay: true`. Attestation failure is `403`; `MYFSIO_CLUSTER_PSK` not configured returns `503`.

> **Idempotent replay caveat.** The cached response is returned verbatim and the underlying action is **not** re-executed against current state. If something else mutated the target between the original call and a replay, the replay body still reflects the *original* outcome — not the live state. Treat the replay body as proof the action was applied at least once, not as a fresh status read. Use a follow-up `GET` if you need to confirm current state. Reusing the same key with a different method/path/body returns `409 InvalidArgument`.

#### Audit log

When `AUDIT_LOG_ENABLED=true`, every relayed action writes one JSONL line on both the origin (target=`outbound`) and target (target=`local`) nodes, sharing the same `correlation_id`. The UI surfaces this at `/ui/audit-log`.

#### Threat model summary

A successful federated write requires three independent secrets:
1. A SigV4-valid peer credential issued on the target site
2. The cluster PSK (shared cluster-wide; rotate by rolling restart)
3. The HMAC over the admin's `user_id` (also keyed by PSK; proves a human admin authorized the call)

Compromise of any one of the three is insufficient. The narrow `/myfsio/admin/peer/*` URL prefix and the explicit allowlist of relayable paths give a second layer of defense beyond the attestation check.

## 7. Data Layout

With the default `STORAGE_ROOT=./data`, the Rust server writes:

```text
data/
  <bucket>/                              # object paths; completed multipart objects may be sparse stubs
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
      meta/                              # per-object metadata sidecars (.__myfsio_meta__*.json)
                                         # plus legacy per-directory _index.json files
      versions/                          # archived versions (if versioning enabled)
      segments/                          # completed multipart segment files by upload id
      listing/
        snapshot.json                    # derived ordered listing snapshot
        journal.<gen>.jsonl              # generation-numbered mutation journals
      replication/
        pending.snapshot.json            # durable pending-replication snapshot
        pending.journal.jsonl             # fsynced pending upsert/ack journal
      lifecycle_history.json             # lifecycle action log (if any rule has fired)
      replication_failures.json          # bounded failure log
      site_sync_state.json               # bidi sync watermark
    multipart/                           # in-progress multipart uploads
    keys/
      kms_master.key                     # 32-byte master key (base64)
      kms_keys.json                      # KMS keys, encrypted under master key
```

Notable files:

- With the default `MULTIPART_OBJECT_LAYOUT=segments`, completed multipart key paths are sparse stubs; the bytes live in the matching `segments/<upload_id>/seg-NNNNN` directory.
- With the default `METADATA_LAYOUT=sidecar`, each object's metadata lives in its own `meta/<dirs>/.__myfsio_meta__<name>.json` file (over-long names fall back to a SHA-256-derived filename; the real entry name is embedded in the JSON as `__entry_name__`). Deployments upgraded from older releases keep their `_index.json` files readable forever; a sidecar always wins over an index entry for the same object.
- With the default `LISTING_INDEX_ENABLED=true`, each bucket keeps a derived listing index under `.myfsio.sys/buckets/<bucket>/listing/` (`snapshot.json` + generation-numbered `journal.<gen>.jsonl` files). Compaction rotates to a new journal under the index lock, then builds and installs the covering snapshot in the backend-owned background worker. Snapshot format 3 records the covered high-water generation plus live-object, live-logical-byte, version, version-logical-byte, and delete-marker counters. Generation-fenced version mutations replay with the listing journal, while crash-left journals already covered by the snapshot are ignored. Older snapshot formats are discarded and rebuilt from authoritative sidecars and version records. Deleting the listing directory is always safe and simply triggers a rebuild on the next listing (or via `--rebuild-listing`).
- Enabled replication rules keep pending puts, deletes, and delete markers in a per-bucket durable ledger under `.myfsio.sys/buckets/<bucket>/replication/`. Each pending upsert is fsynced before the object sidecar is marked `PENDING` and before worker enqueue; remote success is recorded before the sidecar becomes `COMPLETED` and the ledger ack is fsynced. Startup replays this ledger without listing objects or reading sidecars. A bucket with no ledger files is migrated once by scanning sidecars, while corrupt or oversized ledger state triggers the same recovery scan. Normal healer passes replay ledger entries and failure records only. Set `REPLICATION_FULL_RECONCILE_INTERVAL_HOURS` above `0` only when an additional low-frequency consistency scan is desired.
- `iam.json` is Fernet-encrypted at rest when `SECRET_KEY` is set.
- `bucket_policies.json` is read only as a fallback for policies that pre-date per-bucket `.bucket.json`.
- `kms_master.key` is plaintext on disk — protect `keys/` with filesystem permissions.
- `*_history.json` files only appear when their owning service has been enabled at least once.

### Metadata layout migration

Existing deployments need no migration: the server reads sidecars first, then `_index.json`, then the pre-index legacy `.meta/<key>.meta.json` form. Objects migrate themselves to sidecars whenever their metadata is next written. To convert everything at once:

```bash
myfsio-server --migrate-meta
```

Run it with the server stopped. It walks every bucket's `meta/` tree, writes one sidecar per index entry (skipping entries that already have a valid sidecar), and deletes each `_index.json` only after all of its entries were written successfully. Corrupt indexes and unreadable sidecars are reported and left in place. Re-running is safe.

**Warning:** once metadata exists in sidecar form — via `--migrate-meta` or simply by writing objects with a `METADATA_LAYOUT=sidecar` (default) server — older `myfsio-server` binaries cannot read that metadata. There is no rollback tool; do not downgrade past this feature after migrating. Setting `METADATA_LAYOUT=index` restores legacy-format *writes* for new objects but does not convert existing sidecars back.

A corrupt `_index.json` or sidecar now **fails closed**: affected objects return `422 ObjectCorrupted` instead of silently losing metadata, and the server refuses to rewrite a corrupt index (previously a corrupt index was treated as empty and the next write destroyed metadata for every sibling object in that directory).

### Durability model

MyFSIO has an explicit durability deviation from Amazon S3 compatibility. PUT object file contents are fsynced before MyFSIO acknowledges the request. Namespace durability for the rename and directory entry remains platform-dependent. On Windows, directory fsync is a no-op, so the namespace portion of that durability sequence does not receive the same guarantee as it does on platforms that support directory fsync.

An acknowledged DELETE that is still within the filesystem journal-commit window can be affected by a hard crash such as power loss or a kernel panic. This limitation does not apply to an ordinary process restart. After a hard crash, one of three states can remain:

- Full resurrection: the object and its sidecar both reappear. The object is valid and can be deleted again, and lifecycle policy will re-expire it when applicable.
- Orphan sidecar: the object data stays deleted while its metadata sidecar reappears. The integrity scan detects and removes the orphan.
- Ghost LIST entry: the object remains deleted but a derived listing-index entry reappears. The unclean-shutdown marker causes all persisted listing indexes to be discarded and lazily rebuilt from authoritative sidecars at the next boot.

`DELETE_DURABILITY=strict` and durable tombstones are unimplemented future work. MyFSIO does not currently offer a strict DELETE durability mode.

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
- A `Days` expiration rule expires objects older than that many days. A `Date` expiration rule does nothing until the date has passed, and from then on expires every object matching the rule filter regardless of age, as AWS does. Previously the configured date was used directly as the age cutoff, so a rule dated in the future deleted every matching object on the next cycle.

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
- `GC_SEGMENT_MAX_AGE_HOURS=24`
- `GC_DRY_RUN=false`

Each GC cycle also sweeps `data/.myfsio.sys/quarantine/<bucket>/<ts>/` directories whose `<ts>` mtime is older than `INTEGRITY_QUARANTINE_RETENTION_DAYS`, freeing the bytes recorded in `quarantine_bytes_freed` / `quarantine_entries_deleted` in the result JSON. Age alone is not sufficient: before deleting anything the sweep collects every `__quarantine_path__` still referenced by poisoned object metadata (sidecar and legacy layouts both) and retains those directories, counting them as `quarantine_entries_protected`. If that reference scan hits any read or parse error, every aged entry is retained for that cycle and the error is reported — an incomplete scan must never delete the only surviving copy of a poisoned object's bytes. The scan itself runs only when at least one entry is actually past retention. It also deletes unreferenced `data/.myfsio.sys/buckets/<bucket>/segments/<upload_id>/` directories older than `GC_SEGMENT_MAX_AGE_HOURS`, reported as `segment_dirs_deleted` / `segment_bytes_freed`.

Deciding which segment directories are orphaned requires a complete walk of the bucket's live tree and its archived versions. If any part of that walk fails — an unreadable directory or entry, or an unreadable segment stub header — the segment sweep is skipped for that bucket, a `Skipped segment sweep for bucket <name>: reference scan incomplete: …` line is added to the run's `errors` array (so it appears in the result JSON and in GC history), and a warning is logged. Every other GC phase still runs, and buckets whose scan completed sweep normally. Previously the scan swallowed these failures, so one transient IO error could make live segmented objects look unreferenced and delete them while still reporting a clean run.

History is persisted at `data/.myfsio.sys/config/gc_history.json` and can be triggered manually via `POST /myfsio/admin/gc/run` (use `{"dry_run": true}` to preview).

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
INTEGRITY_HEAL_CONCURRENCY=1
INTEGRITY_QUARANTINE_RETENTION_DAYS=7
```

The checksum phase verifies single-part objects against their stored MD5 and multipart objects against a recomputed composite ETag, reading either the segment files or the concatenated body according to the `__part_sizes__` manifest. Objects the scanner cannot verify are counted rather than accused: `encrypted_objects_unverifiable` for server-side-encrypted objects, and `multipart_objects_unverifiable` for multipart objects completed before `__part_sizes__` existed. A read failure that indicates damaged content (short read, trailing bytes, wrong segment size) is reported as `corrupted_object`; any other IO failure is reported in `errors` and the object is left alone.

When `INTEGRITY_AUTO_HEAL=true` (and `INTEGRITY_DRY_RUN=false`), each scan ends with a heal phase that processes the issues it just recorded. For `corrupted_object` the bad bytes are renamed into `data/.myfsio.sys/quarantine/<bucket>/<ts>/<key>` and the heal logic tries, in order:

1. **Pull from peer.** If a replication rule for the bucket points at a healthy remote whose `HEAD` returns the same ETag the local index has, the body is streamed to a temp file, MD5-verified against the stored ETag, and atomically swapped into the live path. The poison flags are cleared on success.
2. **Poison the entry.** If there is no replication target, the peer disagrees on the ETag, the peer is unreachable, or the downloaded body fails verification, the index entry is mutated to add `__corrupted__: "true"`, `__corrupted_at__`, `__corruption_detail__`, `__quarantine_path__`, `__corruption_retry_count__`, and `__corruption_last_retry_at__`. The data file stays in quarantine until it is recovered or stops being referenced.

Quarantine, heal-install, recovery-failure recording, and phantom-metadata deletion are all check-and-set operations performed by the storage backend under the per-object write lock: the object is re-hashed under the lock before it is quarantined, a healed body is re-verified against the expected ETag before it is installed, and every one of them re-reads the metadata and aborts if the object was overwritten in the meantime. A concurrent `PUT` therefore always wins against an in-flight heal.

Poisoned entries whose live object is gone are re-reported on every scan as `poisoned_object` and retried by the heal phase, oldest-failure-first so a permanently unrecoverable key cannot starve the rest out of the per-type issue cap. With no peer configured the retry is skipped rather than recorded, since it cannot make progress.

Subsequent reads (`GET`, `HEAD`, `CopyObject` source) on a poisoned key return `422 ObjectCorrupted` instead of serving rotted bytes; the response includes an `x-amz-error-code: ObjectCorrupted` header so HEAD callers (which receive no body) can still detect the condition. Replication push skips poisoned keys; the checksum phase skips poisoned keys instead of re-flagging them as corrupt. Overwriting the key with a fresh `PUT` clears the poison.

`stale_version`, `etag_cache_inconsistency`, and `phantom_metadata` issues are healed locally (move-to-quarantine, rebuild cache, drop entry); `orphaned_object` is reported only. A metadata key that does not resolve to a path inside its bucket is reported as `invalid_metadata_key` and never touched.

Override per-invocation by passing `auto_heal` / `dry_run` to `POST /myfsio/admin/integrity/run`. Setting both requests a heal preview: the scan runs, every issue is classified as healable or not, and nothing is modified — reported as `issues_would_heal` and the per-type `would_heal` count. The response and history records include a `heal_stats` map keyed by issue type with `{found, healed, poisoned, peer_mismatch, peer_unavailable, verify_failed, failed, skipped, would_heal}`. History is at `data/.myfsio.sys/config/integrity_history.json`; if it cannot be written the error is surfaced on the System page instead of being silently dropped.

### Metrics history

Enable with:

```bash
METRICS_HISTORY_ENABLED=true cargo run -p myfsio-server --
```

Tune it with:

```bash
METRICS_HISTORY_INTERVAL_MINUTES=10
METRICS_HISTORY_RETENTION_HOURS=72
METRICS_STORAGE_REFRESH_MINUTES=30
```

Snapshots are stored in `data/.myfsio.sys/config/metrics_history.json` with atomic temp-file replacement. CPU sampling and storage-size walks run on blocking worker threads; total stored bytes are refreshed on the `METRICS_STORAGE_REFRESH_MINUTES` cadence and reused between refreshes.

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

Empty operation windows are not persisted. The Metrics UI zero-fills gaps in charts, and `/ui/metrics/operations/error-summary?hours=1|6|24` merges the live window with persisted snapshots so S3 API error codes remain visible after snapshot rollover. Recent in-memory error details are exposed at `/ui/metrics/operations/errors?limit=N&code=X&bucket=Y`.

## 9. Encryption and KMS

Object encryption and built-in KMS are both optional.

```bash
ENCRYPTION_ENABLED=true KMS_ENABLED=true cargo run -p myfsio-server --
```

Notes:

- If `ENCRYPTION_ENABLED=true` and `SECRET_KEY` is not configured, the server still starts, but `--check-config` warns that secure-at-rest config encryption is unavailable.
- If `ENCRYPTION_ENABLED=true` or `KMS_ENABLED=true` and the corresponding subsystem fails to initialize, the server logs the reason and exits non-zero instead of starting. Starting without it would silently store objects unencrypted while still returning `200 OK`.
- A bucket configured with default encryption fails its writes with `InternalError` if the encryption service is unavailable or its stored configuration cannot be parsed, rather than falling back to writing plaintext.
- KMS and the object encryption master key live under `data/.myfsio.sys/keys/`.
- Encrypted PUTs stream the client body straight through the encryptor into a temp file and commit the ciphertext atomically; plaintext is never installed at the live key path. Encrypted GETs (full, ranged, and SSE-C multipart) decrypt chunk-by-chunk while streaming the response instead of materializing a decrypted temp file. Objects written by older builds without `x-amz-encryption-plaintext-size` metadata fall back to temp-file decryption.
- One remaining non-atomic window: SSE-S3/SSE-KMS multipart uploads encrypt after CompleteMultipartUpload commits the assembled object; a crash inside that window can leave the assembled plaintext live. Per-part SSE-C multipart uploads are not affected.

### Write integrity and conditional writes

- `Content-MD5`, `x-amz-checksum-sha256`, `x-amz-checksum-sha1`, `x-amz-checksum-crc32`, `x-amz-checksum-crc32c`, and `x-amz-checksum-crc64nvme` are verified on PutObject, UploadPart, POST policy uploads, and SSE-C variants while the body streams to disk. A `Content-MD5` mismatch returns `BadDigest`; an `x-amz-checksum-*` mismatch returns `InvalidRequest`; nothing is committed.
- Aws-chunked uploads honor `x-amz-trailer`, require every declared trailer, and verify checksum trailers against the decoded body. Truncated trailer sections return `IncompleteBody`; malformed or mismatched trailers return `InvalidRequest`.
- Streaming SigV4 validates each chunk signature in sequence, including the final zero-length chunk. `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` also validates the signed canonical trailer block. `STREAMING-UNSIGNED-PAYLOAD-TRAILER` performs checksum-trailer verification without chunk signatures.
- GET and HEAD return stored `x-amz-checksum-*` headers only when `x-amz-checksum-mode: ENABLED` is requested. GetObjectAttributes returns its checksum element unconditionally.
- `If-Match` / `If-None-Match` / `If-Unmodified-Since` / `If-Modified-Since` on PutObject and CompleteMultipartUpload are re-evaluated inside the storage commit lock, so concurrent conditional writes cannot both succeed (`412 PreconditionFailed` on conflict).
- Object lock (retention and legal hold) is enforced at the storage commit for destructive operations: unversioned overwrite/delete, suspended-versioning null-version replacement, and version deletion. This covers internal writers (replication, site sync, lifecycle) in addition to the S3 API.
- Bucket quotas are checked under a per-bucket commit lock, so concurrent uploads to different keys cannot race past the limit. When the listing index and its counters are live, quota projection and bucket statistics are O(1) and perform no recursive directory walk. If the index is disabled, unavailable, dirty, or rebuilding, MyFSIO falls back to the existing recursive statistics walk and its 60-second cache. A versioned overwrite adds a stored copy because the prior live object becomes an archived version. With suspended versioning, a non-null live version remains counted when archived, while the replaced live null version and any archived null version purged by the commit are removed from the projection. Creating a delete marker frees no quota; purging the stored object version frees its bytes and object count.
- Object data and multipart part files are fsynced before the commit rename, and parent directories are fsynced after rename (crash durability).

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

If either listener task ends on its own — a listener error or a panic — the process logs which one and why, drains the surviving listener, runs the normal shutdown sequence, and exits with status 1 so the unit's `Restart=` policy takes effect. Previously the process kept running with a dead endpoint, and health checks against the other listener still passed.

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
  "version": "x.x.x"
}
```

## 13. Credential Reset

To rotate the bootstrap admin credentials:

```bash
cargo run -p myfsio-server -- --reset-cred
```

The command:

- backs up the existing IAM file with a timestamped `.bak-...` suffix, tightening the backup to `0600` on Unix
- writes a fresh admin config through the atomic, owner-only, encrypted-when-`SECRET_KEY`-is-set save path
- respects `ADMIN_ACCESS_KEY` and `ADMIN_SECRET_KEY` if you set them, and prints `(from ADMIN_SECRET_KEY)` instead of the secret value when the secret came from the environment

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
- admin routes under `/myfsio/admin/...`
- KMS routes under `/myfsio/kms/...`

`CompleteMultipartUpload` includes `x-amz-version-id` on the response when the completed object has a version id.

### S3 Select

`POST /<bucket>/<key>?select&select-type=2` (SelectObjectContent) runs on a purpose-built streaming engine — SQL is parsed with sqlparser-rs and validated against the supported subset before any data is read, then rows stream through an interpreter one at a time. There is no embedded database and no whole-object buffering: input is read incrementally (CSV and JSON never touch a temp file, even for multipart `segments`-layout objects), `Records` events are emitted as 64 KiB chunks while the scan is still running, and the former 256 MB whole-query engine memory cap is gone — object size no longer matters, only record size. Individual records are bounded so a pathological input cannot buffer unbounded memory: a CSV record may be at most 4 MiB, a JSON `LINES` value at most 16 MiB, and a JSON `DOCUMENT` body at most 128 MiB (each a superset of the old engine's 2 MiB CSV line and 16 MiB JSON object limits); an oversized record aborts the scan with an in-stream error.

Supported SQL: single `SELECT` over `S3Object` (case-insensitive, optional alias; other table names, table functions, and wildcard qualifiers that are not the table or its alias are rejected), projections with aliases, `WHERE`, `LIMIT`, the aggregates `COUNT`/`SUM`/`MIN`/`MAX`/`AVG`, `LIKE`/`ILIKE` (with `ESCAPE`), `BETWEEN`, `IN`, `IS [NOT] NULL`, `CASE` (both forms), `CAST` to int/float/string/boolean, arithmetic and `||` concatenation, and the scalar functions `LOWER`, `UPPER`, `TRIM`/`LTRIM`/`RTRIM`, `CHAR_LENGTH`/`CHARACTER_LENGTH`/`LENGTH`, `SUBSTRING`, `COALESCE`, `NULLIF`, `ABS`, `CEIL`/`CEILING`, `FLOOR`, `ROUND`. Everything else — `GROUP BY`, `ORDER BY`, `DISTINCT`, `OFFSET`, joins, subqueries, `WITH`, table functions, unknown functions — is rejected with `400 InvalidRequest` at parse time, before the response stream starts. The engine is allow-by-construction: only the validated AST is interpreted, so there is no SQL string ever handed to an execution layer.

Inputs are CSV (`FileHeaderInfo` `USE` reads header names; `IGNORE` skips the header row and names columns `_1`..`_N`; `NONE` names them `_1`..`_N` with no skip), JSON (`LINES` and `DOCUMENT`, including nested field paths like `s.user.name`), and Parquet. CSV fields are typed by per-field inference (canonical integers, floats, `true`/`false`, empty ⇒ NULL) and comparisons coerce leniently between numeric strings and numbers. Outputs are CSV (quoted as needed, or always with `QuoteFields` `ALWAYS`) and JSON (one object per row, projection order preserved, missing fields omitted).

Serialization options are validated up front instead of being silently coerced: `FileHeaderInfo` must be `USE`/`IGNORE`/`NONE`, JSON `Type` must be `DOCUMENT`/`LINES`, `FieldDelimiter`/`QuoteCharacter`/`Comments` must be single ASCII characters (`Comments` skips lines starting with that character), and `QuoteFields` must be `ALWAYS`/`ASNEEDED`. Unsupported combinations return `400 InvalidRequest` rather than potentially wrong records: any `CompressionType` other than `NONE`, an input CSV `RecordDelimiter` other than `\n`/`\r\n`, and a `QuoteEscapeCharacter` different from the quote character.

Select now works on SSE-S3 and SSE-KMS objects for CSV and JSON input — the scan streams through the same decrypting data plane as `GET`, and SSE-C objects are supported when the request carries the customer key headers. Parquet input still requires an unencrypted object (`400 InvalidRequest` otherwise) because the reader needs seekable access. The `Stats` event reports real `BytesScanned`/`BytesProcessed` (input bytes consumed) instead of `0`. Errors detected after streaming has begun (for example malformed CSV or JSON mid-object) arrive as an event-stream `error` message rather than an HTTP error, matching AWS behavior.

### Authorization and request validation

- **Per-key authorization on bulk delete.** `POST /<bucket>?delete` authorizes every key in the request body individually, not just the bucket. A principal whose IAM policy is scoped to a prefix can no longer delete keys outside it; unauthorized keys come back as `AccessDenied` entries in the `DeleteResult` while authorized keys still succeed.
- **A request may name at most one subresource.** The authorization middleware and the request dispatchers previously scanned the query string in independent orders, so a request naming two selectors could be authorized as one operation and executed as another. `PUT /<bucket>?location=&policy=` was authorized as `list` but dispatched to `PutBucketPolicy`, letting a list-only principal replace a bucket policy — and because an `AllUsers` bucket ACL grants `list` to anonymous callers, the same request installed an attacker-chosen policy on a public-read bucket with no credentials at all. The object level had the same defect in a worse form: `?attributes` mapped to the `read` action for every method while no PUT or DELETE handler branched on it, so `PUT /<bucket>/<key>?attributes=` and `DELETE /<bucket>/<key>?attributes=` were authorized as reads and then performed a real overwrite or delete.

  Bucket and object selectors are now each resolved by one parser shared between the middleware and every dispatcher, so the two layers cannot disagree. A request carrying more than one recognized selector is rejected with `InvalidArgument` at authorization time, before the operation is dispatched. A selector that the dispatcher for that method does not implement returns `MethodNotAllowed` rather than falling through to the method's default operation — notably `PUT /<bucket>?location`, `?policyStatus`, `?versions`, `?uploads` and `?delete`, which previously **created the bucket**; `GET /<bucket>?delete`, which previously returned an object listing; `POST /<bucket>?<anything but delete>`; and `PUT`/`DELETE` of an object with `?attributes`, `?select` or `?uploads`. When a selector is not implemented for the requested method, authorization uses that method's default action, so it is never weaker than what the request could perform.

  Two bucket selectors that authorization did not previously recognize at all now have their own IAM actions instead of falling through to the method default (`create_bucket` on PUT): `?ownershipControls` requires `ownership_controls` and `?publicAccessBlock` requires `public_access_block`. Grant these explicitly to any non-admin principal that manages those settings.
- **Governance-retention bypass is a permission, not a header.** `x-amz-bypass-governance-retention: true` is only honored for an admin principal or for a principal granted the `bypass_governance` IAM action (or `s3:BypassGovernanceRetention` in a bucket policy) on the bucket and key being modified. An unauthorized caller, including an anonymous one on a public bucket, is treated as if the header were absent: a `GOVERNANCE`-locked object then refuses the delete, overwrite or retention change, while unlocked objects are unaffected. This is enforced on `DeleteObject`, versioned deletes, `POST /<bucket>?delete` (per key, so a prefix-scoped policy applies key by key), `PutObject`, `CopyObject`, POST form uploads, `CompleteMultipartUpload` and `PutObjectRetention`. `COMPLIANCE` retention remains absolute and no permission overrides it. The web UI never bypasses governance retention.
- **A prefix-scoped wildcard policy is no longer an admin policy.** A principal is admin only when a policy grants `"bucket": "*"` with `"actions": ["*"]` and an unrestricted prefix (`"*"` or empty). Previously the prefix was ignored, so `{"bucket": "*", "actions": ["*"], "prefix": "home/"}` (a legitimate "everything under this prefix, in any bucket" grant) produced an admin principal that skipped every later check, including its own prefix scoping and admin-only APIs. Such a principal is now evaluated by the normal policy loop and stays confined to its prefix.
- **Bucket-policy resource keys match case-sensitively.** S3 object keys are case-sensitive, so the key segment of a `Resource` ARN is compared case-sensitively: `arn:aws:s3:::b/public/*` matches `public/x` but not `PUBLIC/secret`. The bucket segment stays case-insensitive, since a policy may spell the bucket name in mixed case, and `Action` matching stays case-insensitive as AWS does.
- **Bucket policies fail closed on unsupported clauses.** `Condition`, `NotPrincipal`, `NotAction`, and `NotResource` are not evaluated by this server. `PutBucketPolicy` (and the UI policy editor) now reject statements containing them with `InvalidArgument`. For policies already stored, a matching `Allow` carrying such a clause grants nothing, and a `Deny` carrying one denies. Previously these clauses were silently ignored, so a restrictive-looking policy could be permissive.
- **Presigned URLs must sign their `x-amz-*` headers.** A presigned request carrying an `x-amz-*` header that is not listed in `X-Amz-SignedHeaders` is rejected with `SignatureDoesNotMatch`. This prevents a URL bearer from adding `x-amz-copy-source`, `x-amz-acl`, `x-amz-bypass-governance-retention`, SSE, or user-metadata headers the signer never authorized. Only `x-amz-content-sha256`, `x-amz-date`, and `x-amz-decoded-content-length` are exempt, since they affect body framing only. SDKs that attach unsigned checksum headers to presigned PUTs will need to include them in the signature, as they already must against AWS.
- **Reserved metadata keys are dropped.** User metadata keys beginning with `__` or `x-amz-` collide with internal storage and encryption metadata and are discarded on PutObject, CopyObject, POST form uploads, UI multipart initiation, and objects pulled from a peer. Ordinary `x-amz-meta-<name>` metadata is unaffected.
- **A ranged GET of an SSE-C object validates the customer key like any other read.** `GET` with a `Range` header (or `partNumber`) on an SSE-C object returns `400 InvalidRequest` when the `x-amz-server-side-encryption-customer-*` headers are absent and `403 AccessDenied` when the supplied key does not match the one the object was written with — the same responses the whole-object `GET` has always returned. Previously only the whole-object path checked, so a ranged read failed inside the decryptor and surfaced as `500 InternalError` carrying an internal error string.
- **Multipart upload ids are validated.** `uploadId` and internal segment ids must be 32 lowercase hex characters. A malformed id returns `NoSuchUpload` rather than being joined into a filesystem path.
- **Listing parameters are validated and bounded.** `encoding-type` accepts only `url` (case-insensitive); any other value returns `InvalidArgument` with `Invalid Encoding Method specified in Request` on `ListObjects`, `ListObjectsV2`, `ListObjectVersions` and `ListMultipartUploads`, instead of being silently ignored. `max-keys` above `1000` is capped at `1000` as AWS does, and the capped value is what the response echoes in `MaxKeys`, so an oversized page request can no longer force an unbounded single-page listing. Negative or non-integer `max-keys` values still return `InvalidArgument`, and `max-keys=0` still returns an empty listing.
- **Bucket names are validated on every access, not only on creation.** Full S3 bucket-name syntax (3–63 characters, lowercase letters, digits, dots and hyphens) is enforced inside the storage backend for every read, write, delete, list, configuration and multipart operation, and the resolved path is checked to still fall under `STORAGE_ROOT`. Previously only `CreateBucket` ran the syntax check while every other operation checked reserved names alone, so a percent-encoded absolute path in the bucket position (`/C%3A%5CWindows%5CTemp/file.txt`) was joined onto the storage root and replaced it, giving a signed request read, write and delete access outside the configured storage directory. The authorization middleware also percent-decodes the bucket and key before evaluating them, so it can no longer authorize a different string than the handler acts on. Malformed names now return `InvalidBucketName`. Bucket names supplied in request bodies and UI forms rather than in the path are validated too: the `PutBucketLogging` `TargetBucket`, website-domain mappings, and a replication rule's source bucket all reject an invalid name with `InvalidBucketName` instead of reporting that the bucket does not exist, and a persisted replication rule whose source bucket name is invalid is ignored at load with an error log. A replication rule's *target* bucket lives on a remote server, so it is only checked for path safety — a remote bucket may legitimately carry a name this server would not issue locally. Directories in the storage root whose names are not valid bucket names are skipped by `ListBuckets` with a warning rather than being served as buckets, and `--rebuild-listing` skips them instead of failing the run.
- **Corrupt bucket configuration fails closed.** If a bucket's `.bucket.json` exists but cannot be read or parsed, the bucket is treated as unusable rather than as an empty configuration: policy evaluation denies, object writes and deletes return `InternalError` (versioning and quota settings cannot be determined, so proceeding could destroy versions on a bucket that is actually versioned), writes needing its encryption settings return `InternalError`, and every configuration write refuses to overwrite it. The last guard matters because the config is a read-modify-write: without it, the next settings change would replace the corrupt file with a near-empty one and silently discard every other bucket setting.

  To recover, stop the server and repair the file, or delete it to return the bucket to default settings — a missing `.bucket.json` is legitimate and reads as an empty configuration. The server logs the bucket name and full path when it detects the condition. Note the bucket config cache holds the failed read for up to `BUCKET_CONFIG_CACHE_TTL_SECONDS` (default 30).

- **Every buffered request body is bounded.** Requests whose body is parsed in full — bucket and object subresource XML (`?versioning`, `?tagging`, `?cors`, `?encryption`, `?lifecycle`, `?quota`, `?policy`, `?replication`, `?acl`, `?website`, `?ownershipControls`, `?publicAccessBlock`, `?object-lock`, `?notification`, `?logging`, `?retention`, `?legal-hold`), `CreateBucket`'s location constraint and the S3 Select request document — accept at most 1 MiB and otherwise return `400 MaxMessageLengthExceeded` (`Your request was too big`). `CompleteMultipartUpload` and `POST /<bucket>?delete` accept 8 MiB, enough for the 10,000-part and 1,000-key maxima. KMS and `/myfsio/admin/*` JSON bodies accept 1 MiB and answer with a `413` in their own JSON error shape; UI JSON and form bodies accept 2 MiB and answer `413 {"error": "Request body exceeds the 2.0 MiB limit"}`. Bodies are read frame by frame and abandoned the moment they pass the cap, so an oversized request is never buffered. Object data paths (`PutObject`, `UploadPart`, POST form uploads) are unaffected — they stream to disk and are governed by `UPLOAD_STREAM_BUFFER_BYTES` as before. Previously every one of these call sites read the body with no limit at all, so a single authenticated request could exhaust server memory.
- **Multipart form fields other than the file are capped at 1 MiB.** `POST /<bucket>` (browser-based POST form upload) and the UI's `POST /ui/buckets/<bucket>/upload` both read their non-file fields (`key`, `policy`, the `x-amz-*` fields, `object_key`, `metadata`) fully into memory. Each is now limited to 1 MiB while the file field itself stays unlimited and streams as before; an oversized field returns `400 MaxMessageLengthExceeded` on the S3 endpoint and `413` in the UI's JSON error shape.
- **`POST /myfsio/admin/relay/<site_id>/<path>` bounds the body it forwards.** The outbound relay handler now reads its request body through the same 8 MiB limit as the inbound relay layer and the peer-response reader, answering `413 InvalidRequest` past it. It was the one relay path still collecting without a limit.
- **The UI upload endpoint answers AJAX callers in JSON, not S3 XML.** When the proxied `PutObject` fails, `POST /ui/buckets/<bucket>/upload` now returns the S3 status with `{"error": "<Message> (<Code>)"}` instead of forwarding the raw S3 error XML, so the upload dialog shows the real reason (quota exceeded, object lock, and so on) rather than a bare "Upload failed (403)".
- **The UI multipart part upload streams.** `PUT /ui/buckets/<bucket>/multipart/<upload_id>?partNumber=N` feeds the request body straight into the storage layer as an async read stream instead of collecting it into memory and then copying it a second time into a cursor. A part larger than S3's 5 GiB maximum is rejected with `413` once the limit is crossed rather than after the whole part is resident. An empty body still returns `400`.
- **UI sessions are created only when something is stored in them.** A request that arrives without a session cookie — or with one naming a session that no longer exists — is served from an in-memory session that is never inserted into the session store, and no `Set-Cookie` is emitted for it. The session is persisted (and the cookie set) only when a handler actually writes to it, which is what `GET /login` does when it issues a CSRF token, so the login flow is unchanged. Previously every cookie-less request inserted a session, and because the store is capped at 10,000 entries, a flood of anonymous requests evicted signed-in users' sessions and logged them out. When the cap is reached, eviction now takes the oldest *unauthenticated* session first and only touches a signed-in session when no anonymous one remains.
- **`/login` is rate limited per IP.** `GET` and `POST /login` share a token bucket sized by `RATE_LIMIT_UI_LOGIN` (default `20 per minute`, parsed like the other `RATE_LIMIT_*` values and honoring `NUM_TRUSTED_PROXIES`). Over the limit, a browser form post gets a styled "Too many login attempts" page with `Retry-After`; a JSON or AJAX caller gets `429 {"error": ...}`. Neither the sign-in form nor the credential check had any limiter before.

### System maintenance permissions

Garbage collection and integrity scanning are server-wide, not bucket-scoped, so they are authorized by namespaced IAM actions rather than by bucket:

| Action | Grants |
|--------|--------|
| `system:gc_read` | `GET /myfsio/admin/gc/status`, `/gc/history`, and the `/ui/system/gc/*` equivalents |
| `system:gc_run` | `POST /myfsio/admin/gc/run` and `/ui/system/gc/run` |
| `system:integrity_read` | `GET /myfsio/admin/integrity/status`, `/integrity/history`, and the `/ui/system/integrity/*` equivalents |
| `system:integrity_run` | `POST /myfsio/admin/integrity/run` and `/ui/system/integrity/run` |

Admin principals pass these checks implicitly. For a non-admin, the granting policy must use `"bucket": "*"`, since a bucket-scoped policy cannot authorize a server-wide operation. `system:*` grants all four, and a `"*"` action grants them as with any other action.

```json
{ "bucket": "*", "prefix": "*", "actions": ["system:gc_read", "system:integrity_read"] }
```

The `/ui/system` dashboard honors the read actions per card: without one, that card states which permission is missing instead of exposing status and history, and the Run/Scan buttons are hidden without the matching run action. The rest of the page (version, platform, timezone, feature flags) is unrestricted.

Both the `/myfsio/admin/...` routes and the `/ui/system/...` routes previously required a full admin principal. They now enforce these permissions instead, so maintenance can be delegated without granting admin. The UI routes moved out of the admin-only router group for this; every one of them performs its own permission check, and a principal with no `system:` action sees the dashboard shell with both cards withheld. Admins are unaffected, and relayed cluster maintenance still works because `relay_inbound_layer` substitutes a verified admin principal before the handler runs.

### Static website hosting

- **Website responses stream and decrypt.** A website request is served through the same data path as the S3 `GetObject` handler instead of reading the whole object into memory first, so an anonymous request can no longer make the server buffer an entire object, and a `Range` request produces a real `206` computed from plaintext offsets rather than a slice of a fully-read buffer (an unsatisfiable range still returns `416` with `Content-Range: bytes */<size>`). Objects encrypted with SSE-S3 or SSE-KMS — including through bucket default encryption — are decrypted before they are sent; they were previously served as raw ciphertext. `HEAD` reports the plaintext `Content-Length`, the same size `HeadObject` reports. An SSE-C object can only be decrypted with the caller's key, which a browser cannot supply, so a website `GET` or `HEAD` of one returns `403` rather than ciphertext. Index-document resolution, the configured error document, and its `404` status are unchanged.

For a route-level view, inspect:

- `crates/myfsio-server/src/lib.rs`
- `crates/myfsio-server/src/handlers/`
