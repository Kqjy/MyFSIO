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
| `SECRET_KEY` | unset, then fallback to `.myfsio.sys/config/.secret` if present | Session signing and IAM config encryption key |
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

### Rate limiting

| Variable | Default | Description |
| --- | --- | --- |
| `RATE_LIMIT_DEFAULT` | `50000 per minute` | Default S3 / KMS rate limit. Accepts `N per <s/m/h/d>` or `N/<seconds>` |
| `RATE_LIMIT_LIST_BUCKETS` | inherits `RATE_LIMIT_DEFAULT` | Override for `GET /` |
| `RATE_LIMIT_BUCKET_OPS` | inherits `RATE_LIMIT_DEFAULT` | Override for `/{bucket}` |
| `RATE_LIMIT_OBJECT_OPS` | inherits `RATE_LIMIT_DEFAULT` | Override for `/{bucket}/{key}` |
| `RATE_LIMIT_HEAD_OPS` | inherits `RATE_LIMIT_DEFAULT` | Override for HEAD requests |
| `RATE_LIMIT_ADMIN` | `60 per minute` | Override for `/myfsio/admin/*` |
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

Each GC cycle also sweeps `data/.myfsio.sys/quarantine/<bucket>/<ts>/` directories whose `<ts>` mtime is older than `INTEGRITY_QUARANTINE_RETENTION_DAYS`, freeing the bytes recorded in `quarantine_bytes_freed` / `quarantine_entries_deleted` in the result JSON. It also deletes unreferenced `data/.myfsio.sys/buckets/<bucket>/segments/<upload_id>/` directories older than `GC_SEGMENT_MAX_AGE_HOURS`, reported as `segment_dirs_deleted` / `segment_bytes_freed`.

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

When `INTEGRITY_AUTO_HEAL=true` (and `INTEGRITY_DRY_RUN=false`), each scan ends with a heal phase that processes the issues it just recorded. For `corrupted_object` the bad bytes are renamed into `data/.myfsio.sys/quarantine/<bucket>/<ts>/<key>` and the heal logic tries, in order:

1. **Pull from peer.** If a replication rule for the bucket points at a healthy remote whose `HEAD` returns the same ETag the local index has, the body is streamed to a temp file, MD5-verified against the stored ETag, and atomically swapped into the live path. The poison flags are cleared on success.
2. **Poison the entry.** If there is no replication target, the peer disagrees on the ETag, the peer is unreachable, or the downloaded body fails verification, the index entry is mutated to add `__corrupted__: "true"`, `__corrupted_at__`, `__corruption_detail__`, and `__quarantine_path__`. The data file stays in quarantine for `INTEGRITY_QUARANTINE_RETENTION_DAYS`.

Subsequent reads (`GET`, `HEAD`, `CopyObject` source) on a poisoned key return `422 ObjectCorrupted` instead of serving rotted bytes; the response includes an `x-amz-error-code: ObjectCorrupted` header so HEAD callers (which receive no body) can still detect the condition. Replication push skips poisoned keys; subsequent integrity scans skip poisoned keys instead of re-flagging them. Overwriting the key with a fresh `PUT` clears the poison.

`stale_version`, `etag_cache_inconsistency`, and `phantom_metadata` issues are healed locally (move-to-quarantine, rebuild cache, drop entry); `orphaned_object` is reported only.

Override per-invocation by passing `auto_heal` / `dry_run` to `POST /myfsio/admin/integrity/run`. The response and history records now include a `heal_stats` map keyed by issue type with `{found, healed, poisoned, peer_mismatch, peer_unavailable, verify_failed, failed, skipped}`. History is at `data/.myfsio.sys/config/integrity_history.json`.

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
- admin routes under `/myfsio/admin/...`
- KMS routes under `/myfsio/kms/...`

`CompleteMultipartUpload` includes `x-amz-version-id` on the response when the completed object has a version id.

For a route-level view, inspect:

- `crates/myfsio-server/src/lib.rs`
- `crates/myfsio-server/src/handlers/`
