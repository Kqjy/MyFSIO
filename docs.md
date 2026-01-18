# MyFSIO Documentation

This document expands on the README to describe the full workflow for running, configuring, and extending MyFSIO. Use it as a playbook for local S3-style experimentation.

## 1. System Overview

MyFSIO ships two Flask entrypoints that share the same storage, IAM, and bucket-policy state:

- **API server** – Implements the S3-compatible REST API, policy evaluation, and Signature Version 4 presign service.
- **UI server** – Provides the browser console for buckets, IAM, and policies. It proxies to the API for presign operations.

Both servers read `AppConfig`, so editing JSON stores on disk instantly affects both surfaces.

## 2. Quickstart

```bash
python -m venv .venv
. .venv/Scripts/activate      # PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run both API and UI
python run.py
```

Visit `http://127.0.0.1:5100/ui` to use the console and `http://127.0.0.1:5000/` (with IAM headers) for raw API calls.

### Run modes

You can run services individually if needed:

```bash
python run.py --mode api   # API only (port 5000)
python run.py --mode ui    # UI only (port 5100)
```

### Configuration validation

Validate your configuration before deploying:

```bash
# Show configuration summary
python run.py --show-config
./myfsio --show-config

# Validate and check for issues (exits with code 1 if critical issues found)
python run.py --check-config
./myfsio --check-config
```

### Linux Installation (Recommended for Production)

For production deployments on Linux, use the provided installation script:

```bash
# Download the binary and install script
# Then run the installer with sudo:
sudo ./scripts/install.sh --binary ./myfsio

# Or with custom paths:
sudo ./scripts/install.sh \
  --binary ./myfsio \
  --install-dir /opt/myfsio \
  --data-dir /mnt/storage/myfsio \
  --log-dir /var/log/myfsio \
  --api-url https://s3.example.com \
  --user myfsio

# Non-interactive mode (for automation):
sudo ./scripts/install.sh --binary ./myfsio -y
```

The installer will:
1. Create a dedicated system user
2. Set up directories with proper permissions
3. Generate a secure `SECRET_KEY`
4. Create an environment file at `/opt/myfsio/myfsio.env`
5. Install and configure a systemd service

After installation:
```bash
sudo systemctl start myfsio    # Start the service
sudo systemctl enable myfsio   # Enable on boot
sudo systemctl status myfsio   # Check status
sudo journalctl -u myfsio -f   # View logs
```

To uninstall:
```bash
sudo ./scripts/uninstall.sh              # Full removal
sudo ./scripts/uninstall.sh --keep-data  # Keep data directory
```

### Docker quickstart

The repo now ships a `Dockerfile` so you can run both services in one container:

```bash
docker build -t myfsio .
docker run --rm -p 5000:5000 -p 5100:5100 \
  -v "$PWD/data:/app/data" \
  -v "$PWD/logs:/app/logs" \
  -e SECRET_KEY="change-me" \
  --name myfsio myfsio
```

PowerShell (Windows) example:

```powershell
docker run --rm -p 5000:5000 -p 5100:5100 `
  -v ${PWD}\data:/app/data `
  -v ${PWD}\logs:/app/logs `
  -e SECRET_KEY="change-me" `
  --name myfsio myfsio
```

Key mount points:
- `/app/data` &rarr; persists buckets directly under `/app/data/<bucket>` while system metadata (IAM config, bucket policies, versions, multipart uploads, etc.) lives under `/app/data/.myfsio.sys` (for example, `/app/data/.myfsio.sys/config/iam.json`).
- `/app/logs` &rarr; captures the rotating app log.
- `/app/tmp-storage` (optional) if you rely on the demo upload staging folders.

With these volumes attached you can rebuild/restart the container without losing stored objects or credentials.

### Versioning

The repo now tracks a human-friendly release string inside `app/version.py` (see the `APP_VERSION` constant). Edit that value whenever you cut a release. The constant flows into Flask as `APP_VERSION` and is exposed via `GET /myfsio/health`, so you can monitor deployments or surface it in UIs.

## 3. Configuration Reference

All configuration is done via environment variables. The table below lists every supported variable.

### Core Settings

| Variable | Default | Notes |
| --- | --- | --- |
| `STORAGE_ROOT` | `<repo>/data` | Filesystem home for all buckets/objects. |
| `MAX_UPLOAD_SIZE` | `1073741824` (1 GiB) | Bytes. Caps incoming uploads in both API + UI. |
| `UI_PAGE_SIZE` | `100` | `MaxKeys` hint shown in listings. |
| `SECRET_KEY` | Auto-generated | Flask session key. Auto-generates and persists if not set. **Set explicitly in production.** |
| `API_BASE_URL` | `None` | Public URL for presigned URLs. Required behind proxies. |
| `AWS_REGION` | `us-east-1` | Region embedded in SigV4 credential scope. |
| `AWS_SERVICE` | `s3` | Service string for SigV4. |

### IAM & Security

| Variable | Default | Notes |
| --- | --- | --- |
| `IAM_CONFIG` | `data/.myfsio.sys/config/iam.json` | Stores users, secrets, and inline policies. |
| `BUCKET_POLICY_PATH` | `data/.myfsio.sys/config/bucket_policies.json` | Bucket policy store (auto hot-reload). |
| `AUTH_MAX_ATTEMPTS` | `5` | Failed login attempts before lockout. |
| `AUTH_LOCKOUT_MINUTES` | `15` | Lockout duration after max failed attempts. |
| `SESSION_LIFETIME_DAYS` | `30` | How long UI sessions remain valid. |
| `SECRET_TTL_SECONDS` | `300` | TTL for ephemeral secrets (presigned URLs). |
| `UI_ENFORCE_BUCKET_POLICIES` | `false` | Whether the UI should enforce bucket policies. |

### CORS (Cross-Origin Resource Sharing)

| Variable | Default | Notes |
| --- | --- | --- |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins. Use specific domains in production. |
| `CORS_METHODS` | `GET,PUT,POST,DELETE,OPTIONS,HEAD` | Allowed HTTP methods. |
| `CORS_ALLOW_HEADERS` | `*` | Allowed request headers. |
| `CORS_EXPOSE_HEADERS` | `*` | Response headers visible to browsers (e.g., `ETag`). |

### Rate Limiting

| Variable | Default | Notes |
| --- | --- | --- |
| `RATE_LIMIT_DEFAULT` | `200 per minute` | Default rate limit for API endpoints. |
| `RATE_LIMIT_STORAGE_URI` | `memory://` | Storage backend for rate limits. Use `redis://host:port` for distributed setups. |

### Logging

| Variable | Default | Notes |
| --- | --- | --- |
| `LOG_LEVEL` | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `LOG_TO_FILE` | `true` | Enable file logging. |
| `LOG_DIR` | `<repo>/logs` | Directory for log files. |
| `LOG_FILE` | `app.log` | Log filename. |
| `LOG_MAX_BYTES` | `5242880` (5 MB) | Max log file size before rotation. |
| `LOG_BACKUP_COUNT` | `3` | Number of rotated log files to keep. |

### Encryption

| Variable | Default | Notes |
| --- | --- | --- |
| `ENCRYPTION_ENABLED` | `false` | Enable server-side encryption support. |
| `ENCRYPTION_MASTER_KEY_PATH` | `data/.myfsio.sys/keys/master.key` | Path to the master encryption key file. |
| `DEFAULT_ENCRYPTION_ALGORITHM` | `AES256` | Default algorithm for new encrypted objects. |
| `KMS_ENABLED` | `false` | Enable KMS key management for encryption. |
| `KMS_KEYS_PATH` | `data/.myfsio.sys/keys/kms_keys.json` | Path to store KMS key metadata. |


## Lifecycle Rules

Lifecycle rules automate object management by scheduling deletions based on object age.

### Enabling Lifecycle Enforcement

By default, lifecycle enforcement is disabled. Enable it by setting the environment variable:

```bash
LIFECYCLE_ENABLED=true python run.py
```

Or in your `myfsio.env` file:
```
LIFECYCLE_ENABLED=true
LIFECYCLE_INTERVAL_SECONDS=3600  # Check interval (default: 1 hour)
```

### Configuring Rules

Once enabled, configure lifecycle rules via:
- **Web UI:** Bucket Details → Lifecycle tab → Add Rule
- **S3 API:** `PUT /<bucket>?lifecycle` with XML configuration

### Available Actions

| Action | Description |
|--------|-------------|
| **Expiration** | Delete current version objects after N days |
| **NoncurrentVersionExpiration** | Delete old versions N days after becoming noncurrent (requires versioning) |
| **AbortIncompleteMultipartUpload** | Clean up incomplete multipart uploads after N days |

### Example Configuration (XML)

```xml
<LifecycleConfiguration>
  <Rule>
    <ID>DeleteOldLogs</ID>
    <Status>Enabled</Status>
    <Filter><Prefix>logs/</Prefix></Filter>
    <Expiration><Days>30</Days></Expiration>
  </Rule>
</LifecycleConfiguration>
```

### Performance Tuning

| Variable | Default | Notes |
| --- | --- | --- |
| `STREAM_CHUNK_SIZE` | `65536` (64 KB) | Chunk size for streaming large files. |
| `MULTIPART_MIN_PART_SIZE` | `5242880` (5 MB) | Minimum part size for multipart uploads. |
| `BUCKET_STATS_CACHE_TTL` | `60` | Seconds to cache bucket statistics. |
| `BULK_DELETE_MAX_KEYS` | `500` | Maximum keys per bulk delete request. |

### Server Settings

| Variable | Default | Notes |
| --- | --- | --- |
| `APP_HOST` | `0.0.0.0` | Network interface to bind to. |
| `APP_PORT` | `5000` | API server port (UI uses 5100). |
| `FLASK_DEBUG` | `0` | Enable Flask debug mode. **Never enable in production.** |

### Production Checklist

Before deploying to production, ensure you:

1. **Set `SECRET_KEY`** - Use a strong, unique value (e.g., `openssl rand -base64 32`)
2. **Restrict CORS** - Set `CORS_ORIGINS` to your specific domains instead of `*`
3. **Configure `API_BASE_URL`** - Required for correct presigned URLs behind proxies
4. **Enable HTTPS** - Use a reverse proxy (nginx, Cloudflare) with TLS termination
5. **Review rate limits** - Adjust `RATE_LIMIT_DEFAULT` based on your needs
6. **Secure master keys** - Back up `ENCRYPTION_MASTER_KEY_PATH` if using encryption
7. **Use `--prod` flag** - Runs with Waitress instead of Flask dev server

### Proxy Configuration

If running behind a reverse proxy (e.g., Nginx, Cloudflare, or a tunnel), ensure the proxy sets the standard forwarding headers:
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

The application automatically trusts these headers to generate correct presigned URLs (e.g., `https://s3.example.com/...` instead of `http://127.0.0.1:5000/...`). Alternatively, you can explicitly set `API_BASE_URL` to your public endpoint.

## 4. Upgrading and Updates

### Version Checking

The application version is tracked in `app/version.py` and exposed via:
- **Health endpoint:** `GET /myfsio/health` returns JSON with `version` field
- **Metrics dashboard:** Navigate to `/ui/metrics` to see the running version in the System Status card

To check your current version:

```bash
# API health endpoint
curl http://localhost:5000/myfsio/health

# Or inspect version.py directly
cat app/version.py | grep APP_VERSION
```

### Pre-Update Backup Procedures

**Always backup before upgrading to prevent data loss:**

```bash
# 1. Stop the application
# Ctrl+C if running in terminal, or:
docker stop myfsio  # if using Docker

# 2. Backup configuration files (CRITICAL)
mkdir -p backups/$(date +%Y%m%d_%H%M%S)
cp -r data/.myfsio.sys/config backups/$(date +%Y%m%d_%H%M%S)/

# 3. Backup all data (optional but recommended)
tar -czf backups/data_$(date +%Y%m%d_%H%M%S).tar.gz data/

# 4. Backup logs for audit trail
cp -r logs backups/$(date +%Y%m%d_%H%M%S)/
```

**Windows PowerShell:**

```powershell
# Create timestamped backup
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
New-Item -ItemType Directory -Path "backups\$timestamp" -Force

# Backup configs
Copy-Item -Recurse "data\.myfsio.sys\config" "backups\$timestamp\"

# Backup entire data directory
Compress-Archive -Path "data\" -DestinationPath "backups\data_$timestamp.zip"
```

**Critical files to backup:**
- `data/.myfsio.sys/config/iam.json` – User accounts and access keys
- `data/.myfsio.sys/config/bucket_policies.json` – Bucket access policies
- `data/.myfsio.sys/config/kms_keys.json` – Encryption keys (if using KMS)
- `data/.myfsio.sys/config/secret_store.json` – Application secrets

### Update Procedures

#### Source Installation Updates

```bash
# 1. Backup (see above)
# 2. Pull latest code
git fetch origin
git checkout main  # or your target branch/tag
git pull

# 3. Check for dependency changes
pip install -r requirements.txt

# 4. Review CHANGELOG/release notes for breaking changes
cat CHANGELOG.md  # if available

# 5. Run migration scripts (if any)
# python scripts/migrate_vX_to_vY.py  # example

# 6. Restart application
python run.py
```

#### Docker Updates

```bash
# 1. Backup (see above)
# 2. Pull/rebuild image
docker pull yourregistry/myfsio:latest
# OR rebuild from source:
docker build -t myfsio:latest .

# 3. Stop and remove old container
docker stop myfsio
docker rm myfsio

# 4. Start new container with same volumes
docker run -d \
  --name myfsio \
  -p 5000:5000 -p 5100:5100 \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/logs:/app/logs" \
  -e SECRET_KEY="your-secret" \
  myfsio:latest

# 5. Verify health
curl http://localhost:5000/myfsio/health
```

### Version Compatibility Checks

Before upgrading across major versions, verify compatibility:

| From Version | To Version | Breaking Changes | Migration Required |
|--------------|------------|------------------|-------------------|
| 0.1.x | 0.2.x | None expected | No |
| 0.1.6 | 0.1.7 | None | No |
| < 0.1.0 | >= 0.1.0 | New IAM config format | Yes - run migration script |

**Automatic compatibility detection:**

The application will log warnings on startup if config files need migration:

```
WARNING: IAM config format is outdated (v1). Please run: python scripts/migrate_iam.py
```

**Manual compatibility check:**

```bash
# Compare version schemas
python -c "from app.version import APP_VERSION; print(f'Running: {APP_VERSION}')"
python scripts/check_compatibility.py data/.myfsio.sys/config/
```

### Migration Steps for Breaking Changes

When release notes indicate breaking changes, follow these steps:

#### Config Format Migrations

```bash
# 1. Backup first (critical!)
cp data/.myfsio.sys/config/iam.json data/.myfsio.sys/config/iam.json.backup

# 2. Run provided migration script
python scripts/migrate_iam_v1_to_v2.py

# 3. Validate migration
python scripts/validate_config.py

# 4. Test with read-only mode first (if available)
# python run.py --read-only

# 5. Restart normally
python run.py
```

#### Database/Storage Schema Changes

If object metadata format changes:

```bash
# 1. Run storage migration script
python scripts/migrate_storage.py --dry-run  # preview changes

# 2. Apply migration
python scripts/migrate_storage.py --apply

# 3. Verify integrity
python scripts/verify_storage.py
```

#### IAM Policy Updates

If IAM action names change (e.g., `s3:Get` → `s3:GetObject`):

```bash
# Migration script will update all policies
python scripts/migrate_policies.py \
  --input data/.myfsio.sys/config/iam.json \
  --backup data/.myfsio.sys/config/iam.json.v1

# Review changes before committing
python scripts/diff_policies.py \
  data/.myfsio.sys/config/iam.json.v1 \
  data/.myfsio.sys/config/iam.json
```

### Rollback Procedures

If an update causes issues, rollback to the previous version:

#### Quick Rollback (Source)

```bash
# 1. Stop application
# Ctrl+C or kill process

# 2. Revert code
git checkout <previous-version-tag>
# OR
git reset --hard HEAD~1

# 3. Restore configs from backup
cp backups/20241213_103000/config/* data/.myfsio.sys/config/

# 4. Downgrade dependencies if needed
pip install -r requirements.txt

# 5. Restart
python run.py
```

#### Docker Rollback

```bash
# 1. Stop current container
docker stop myfsio
docker rm myfsio

# 2. Start previous version
docker run -d \
  --name myfsio \
  -p 5000:5000 -p 5100:5100 \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/logs:/app/logs" \
  -e SECRET_KEY="your-secret" \
  myfsio:0.1.3  # specify previous version tag

# 3. Verify
curl http://localhost:5000/myfsio/health
```

#### Emergency Config Restore

If only config is corrupted but code is fine:

```bash
# Stop app
# Restore from latest backup
cp backups/20241213_103000/config/iam.json data/.myfsio.sys/config/
cp backups/20241213_103000/config/bucket_policies.json data/.myfsio.sys/config/

# Restart app
python run.py
```

### Blue-Green Deployment (Zero Downtime)

For production environments requiring zero downtime:

```bash
# 1. Run new version on different port (e.g., 5001/5101)
APP_PORT=5001 UI_PORT=5101 python run.py &

# 2. Health check new instance
curl http://localhost:5001/myfsio/health

# 3. Update load balancer to route to new ports

# 4. Monitor for issues

# 5. Gracefully stop old instance
kill -SIGTERM <old-pid>
```

### Post-Update Verification

After any update, verify functionality:

```bash
# 1. Health check
curl http://localhost:5000/myfsio/health

# 2. Login to UI
open http://localhost:5100/ui

# 3. Test IAM authentication
curl -H "X-Amz-Security-Token: <your-access-key>:<your-secret>" \
  http://localhost:5000/

# 4. Test presigned URL generation
# Via UI or API

# 5. Check logs for errors
tail -n 100 logs/myfsio.log
```

### Automated Update Scripts

Create a custom update script for your environment:

```bash
#!/bin/bash
# update.sh - Automated update with rollback capability

set -e  # Exit on error

VERSION_NEW="$1"
BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"

echo "Creating backup..."
mkdir -p "$BACKUP_DIR"
cp -r data/.myfsio.sys/config "$BACKUP_DIR/"

echo "Updating to version $VERSION_NEW..."
git fetch origin
git checkout "v$VERSION_NEW"
pip install -r requirements.txt

echo "Starting application..."
python run.py &
APP_PID=$!

# Wait and health check
sleep 5
if curl -f http://localhost:5000/myfsio/health; then
  echo "Update successful!"
else
  echo "Health check failed, rolling back..."
  kill $APP_PID
  git checkout -
  cp -r "$BACKUP_DIR/config/*" data/.myfsio.sys/config/
  python run.py &
  exit 1
fi
```

## 4. Authentication & IAM

MyFSIO implements a comprehensive Identity and Access Management (IAM) system that controls who can access your buckets and what operations they can perform. The system supports both simple action-based permissions and AWS-compatible policy syntax.

### Getting Started

1. On first boot, `data/.myfsio.sys/config/iam.json` is seeded with `localadmin / localadmin` that has wildcard access.
2. Sign into the UI using those credentials, then open **IAM**:
   - **Create user**: supply a display name and optional JSON inline policy array.
   - **Rotate secret**: generates a new secret key; the UI surfaces it once.
   - **Policy editor**: select a user, paste an array of objects (`{"bucket": "*", "actions": ["list", "read"]}`), and submit. Alias support includes AWS-style verbs (e.g., `s3:GetObject`).
3. Wildcard action `iam:*` is supported for admin user definitions.

### Authentication

The API expects every request to include authentication headers. The UI persists them in the Flask session after login.

| Header | Description |
| --- | --- |
| `X-Access-Key` | The user's access key identifier |
| `X-Secret-Key` | The user's secret key for signing |

**Security Features:**
- **Lockout Protection**: After `AUTH_MAX_ATTEMPTS` (default: 5) failed login attempts, the account is locked for `AUTH_LOCKOUT_MINUTES` (default: 15 minutes).
- **Session Management**: UI sessions remain valid for `SESSION_LIFETIME_DAYS` (default: 30 days).
- **Hot Reload**: IAM configuration changes take effect immediately without restart.

### Permission Model

MyFSIO uses a two-layer permission model:

1. **IAM User Policies** – Define what a user can do across the system (stored in `iam.json`)
2. **Bucket Policies** – Define who can access a specific bucket (stored in `bucket_policies.json`)

Both layers are evaluated for each request. A user must have permission in their IAM policy AND the bucket policy must allow the action (or have no explicit deny).

### Available IAM Actions

#### S3 Actions (Bucket/Object Operations)

| Action | Description | AWS Aliases |
| --- | --- | --- |
| `list` | List buckets and objects | `s3:ListBucket`, `s3:ListAllMyBuckets`, `s3:ListBucketVersions`, `s3:ListMultipartUploads`, `s3:ListParts` |
| `read` | Download objects, get metadata | `s3:GetObject`, `s3:GetObjectVersion`, `s3:GetObjectTagging`, `s3:GetObjectVersionTagging`, `s3:GetObjectAcl`, `s3:GetBucketVersioning`, `s3:HeadObject`, `s3:HeadBucket` |
| `write` | Upload objects, create buckets, manage tags | `s3:PutObject`, `s3:CreateBucket`, `s3:PutObjectTagging`, `s3:PutBucketVersioning`, `s3:CreateMultipartUpload`, `s3:UploadPart`, `s3:CompleteMultipartUpload`, `s3:AbortMultipartUpload`, `s3:CopyObject` |
| `delete` | Remove objects, versions, and buckets | `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:DeleteBucket`, `s3:DeleteObjectTagging` |
| `share` | Manage Access Control Lists (ACLs) | `s3:PutObjectAcl`, `s3:PutBucketAcl`, `s3:GetBucketAcl` |
| `policy` | Manage bucket policies | `s3:PutBucketPolicy`, `s3:GetBucketPolicy`, `s3:DeleteBucketPolicy` |
| `lifecycle` | Manage lifecycle rules | `s3:GetLifecycleConfiguration`, `s3:PutLifecycleConfiguration`, `s3:DeleteLifecycleConfiguration`, `s3:GetBucketLifecycle`, `s3:PutBucketLifecycle` |
| `cors` | Manage CORS configuration | `s3:GetBucketCors`, `s3:PutBucketCors`, `s3:DeleteBucketCors` |
| `replication` | Configure and manage replication | `s3:GetReplicationConfiguration`, `s3:PutReplicationConfiguration`, `s3:DeleteReplicationConfiguration`, `s3:ReplicateObject`, `s3:ReplicateTags`, `s3:ReplicateDelete` |

#### IAM Actions (User Management)

| Action | Description | AWS Aliases |
| --- | --- | --- |
| `iam:list_users` | View all IAM users and their policies | `iam:ListUsers` |
| `iam:create_user` | Create new IAM users | `iam:CreateUser` |
| `iam:delete_user` | Delete IAM users | `iam:DeleteUser` |
| `iam:rotate_key` | Rotate user secret keys | `iam:RotateAccessKey` |
| `iam:update_policy` | Modify user policies | `iam:PutUserPolicy` |
| `iam:*` | **Admin wildcard** – grants all IAM actions | — |

#### Wildcards

| Wildcard | Scope | Description |
| --- | --- | --- |
| `*` (in actions) | All S3 actions | Grants `list`, `read`, `write`, `delete`, `share`, `policy`, `lifecycle`, `cors`, `replication` |
| `iam:*` | All IAM actions | Grants all `iam:*` actions for user management |
| `*` (in bucket) | All buckets | Policy applies to every bucket |

### IAM Policy Structure

User policies are stored as a JSON array of policy objects. Each object specifies a bucket and the allowed actions:

```json
[
  {
    "bucket": "<bucket-name-or-wildcard>",
    "actions": ["<action1>", "<action2>", ...]
  }
]
```

**Fields:**
- `bucket`: The bucket name (case-insensitive) or `*` for all buckets
- `actions`: Array of action strings (simple names or AWS aliases)

### Example User Policies

**Full Administrator (complete system access):**
```json
[{"bucket": "*", "actions": ["list", "read", "write", "delete", "share", "policy", "lifecycle", "cors", "replication", "iam:*"]}]
```

**Read-Only User (browse and download only):**
```json
[{"bucket": "*", "actions": ["list", "read"]}]
```

**Single Bucket Full Access (no access to other buckets):**
```json
[{"bucket": "user-bucket", "actions": ["list", "read", "write", "delete"]}]
```

**Multiple Bucket Access (different permissions per bucket):**
```json
[
  {"bucket": "public-data", "actions": ["list", "read"]},
  {"bucket": "my-uploads", "actions": ["list", "read", "write", "delete"]},
  {"bucket": "team-shared", "actions": ["list", "read", "write"]}
]
```

**IAM Manager (manage users but no data access):**
```json
[{"bucket": "*", "actions": ["iam:list_users", "iam:create_user", "iam:delete_user", "iam:rotate_key", "iam:update_policy"]}]
```

**Replication Operator (manage replication only):**
```json
[{"bucket": "*", "actions": ["list", "read", "replication"]}]
```

**Lifecycle Manager (configure object expiration):**
```json
[{"bucket": "*", "actions": ["list", "lifecycle"]}]
```

**CORS Administrator (configure cross-origin access):**
```json
[{"bucket": "*", "actions": ["cors"]}]
```

**Bucket Administrator (full bucket config, no IAM access):**
```json
[{"bucket": "my-bucket", "actions": ["list", "read", "write", "delete", "policy", "lifecycle", "cors"]}]
```

**Upload-Only User (write but cannot read back):**
```json
[{"bucket": "drop-box", "actions": ["write"]}]
```

**Backup Operator (read, list, and replicate):**
```json
[{"bucket": "*", "actions": ["list", "read", "replication"]}]
```

### Using AWS-Style Action Names

You can use AWS S3 action names instead of simple names. They are automatically normalized:

```json
[
  {
    "bucket": "my-bucket",
    "actions": [
      "s3:ListBucket",
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject"
    ]
  }
]
```

This is equivalent to:
```json
[{"bucket": "my-bucket", "actions": ["list", "read", "write", "delete"]}]
```

### Managing Users via API

```bash
# List all users (requires iam:list_users)
curl http://localhost:5000/iam/users \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..."

# Create a new user (requires iam:create_user)
curl -X POST http://localhost:5000/iam/users \
  -H "Content-Type: application/json" \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..." \
  -d '{
    "display_name": "New User",
    "policies": [{"bucket": "*", "actions": ["list", "read"]}]
  }'

# Rotate user secret (requires iam:rotate_key)
curl -X POST http://localhost:5000/iam/users/<access-key>/rotate \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..."

# Update user policies (requires iam:update_policy)
curl -X PUT http://localhost:5000/iam/users/<access-key>/policies \
  -H "Content-Type: application/json" \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..." \
  -d '[{"bucket": "*", "actions": ["list", "read", "write"]}]'

# Delete a user (requires iam:delete_user)
curl -X DELETE http://localhost:5000/iam/users/<access-key> \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..."
```

### Permission Precedence

When a request is made, permissions are evaluated in this order:

1. **Authentication** – Verify the access key and secret key are valid
2. **Lockout Check** – Ensure the account is not locked due to failed attempts
3. **IAM Policy Check** – Verify the user has the required action for the target bucket
4. **Bucket Policy Check** – If a bucket policy exists, verify it allows the action

A request is allowed only if:
- The IAM policy grants the action, AND
- The bucket policy allows the action (or no bucket policy exists)

### Common Permission Scenarios

| Scenario | Required Actions |
| --- | --- |
| Browse bucket contents | `list` |
| Download a file | `read` |
| Upload a file | `write` |
| Delete a file | `delete` |
| Generate presigned URL (GET) | `read` |
| Generate presigned URL (PUT) | `write` |
| Generate presigned URL (DELETE) | `delete` |
| Enable versioning | `write` (includes `s3:PutBucketVersioning`) |
| View bucket policy | `policy` |
| Modify bucket policy | `policy` |
| Configure lifecycle rules | `lifecycle` |
| View lifecycle rules | `lifecycle` |
| Configure CORS | `cors` |
| View CORS rules | `cors` |
| Configure replication | `replication` (admin-only for creation) |
| Pause/resume replication | `replication` |
| Manage other users | `iam:*` or specific `iam:` actions |
| Set bucket quotas | `iam:*` or `iam:list_users` (admin feature) |

### Security Best Practices

1. **Principle of Least Privilege** – Grant only the permissions users need
2. **Avoid Wildcards** – Use specific bucket names instead of `*` when possible
3. **Rotate Secrets Regularly** – Use the rotate key feature periodically
4. **Separate Admin Accounts** – Don't use admin accounts for daily operations
5. **Monitor Failed Logins** – Check logs for repeated authentication failures
6. **Use Bucket Policies for Fine-Grained Control** – Combine with IAM for defense in depth

## 5. Bucket Policies & Presets

- **Storage**: Policies are persisted in `data/.myfsio.sys/config/bucket_policies.json` under `{"policies": {"bucket": {...}}}`.
- **Hot reload**: Both API and UI call `maybe_reload()` before evaluating policies. Editing the JSON on disk is immediately reflected—no restarts required.
- **UI editor**: Each bucket detail page includes:
  - A preset selector: **Private** detaches the policy (delete mode), **Public** injects an allow policy granting anonymous `s3:ListBucket` + `s3:GetObject`, and **Custom** restores your draft.
  - A read-only preview of the attached policy.
  - Autosave behavior for custom drafts while you type.

### Editing via CLI

```bash
curl -X PUT "http://127.0.0.1:5000/test?policy" \
  -H "Content-Type: application/json" \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..." \
  -d '{
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["s3:ListBucket"],
            "Resource": ["arn:aws:s3:::test"]
          }
        ]
      }'
```

The UI will reflect this change as soon as the request completes thanks to the hot reload.

### UI Object Browser

The bucket detail page includes a powerful object browser with the following features:

#### Folder Navigation

Objects with forward slashes (`/`) in their keys are displayed as a folder hierarchy. Click a folder row to navigate into it. A breadcrumb navigation bar shows your current path and allows quick navigation back to parent folders or the root.

#### Pagination & Infinite Scroll

- Objects load in configurable batches (50, 100, 150, 200, or 250 per page)
- Scroll to the bottom to automatically load more objects (infinite scroll)
- A **Load more** button is available as a fallback for touch devices or when infinite scroll doesn't trigger
- The footer shows the current load status (e.g., "Showing 100 of 500 objects")

#### Bulk Operations

- Select multiple objects using checkboxes
- **Bulk Delete**: Delete multiple objects at once
- **Bulk Download**: Download selected objects as individual files

#### Search & Filter

Use the search box to filter objects by name in real-time. The filter applies to the currently loaded objects.

#### Error Handling

If object loading fails (e.g., network error), a friendly error message is displayed with a **Retry** button to attempt loading again.

#### Object Preview

Click any object row to view its details in the preview sidebar:
- File size and last modified date
- ETag (content hash)
- Custom metadata (if present)
- Download and presign (share link) buttons
- Version history (when versioning is enabled)

#### Drag & Drop Upload

Drag files directly onto the objects table to upload them to the current bucket and folder path.

## 6. Presigned URLs

- Trigger from the UI using the **Presign** button after selecting an object.
- Supported methods: `GET`, `PUT`, `DELETE`; expiration must be `1..604800` seconds.
- The service signs requests using the caller's IAM credentials and enforces bucket policies both when issuing and when the presigned URL is used.
- Legacy share links have been removed; presigned URLs now handle both private and public workflows.

### Multipart Upload Example

```python
import boto3

s3 = boto3.client('s3', endpoint_url='http://localhost:5000')

# Initiate
response = s3.create_multipart_upload(Bucket='mybucket', Key='large.bin')
upload_id = response['UploadId']

# Upload parts
parts = []
chunks = [b'chunk1', b'chunk2'] # Example data chunks
for part_number, chunk in enumerate(chunks, start=1):
    response = s3.upload_part(
        Bucket='mybucket',
        Key='large.bin',
        PartNumber=part_number,
        UploadId=upload_id,
        Body=chunk
    )
    parts.append({'PartNumber': part_number, 'ETag': response['ETag']})

# Complete
s3.complete_multipart_upload(
    Bucket='mybucket',
    Key='large.bin',
    UploadId=upload_id,
    MultipartUpload={'Parts': parts}
)
```

## 7. Encryption

MyFSIO supports **server-side encryption at rest** to protect your data. When enabled, objects are encrypted using AES-256-GCM before being written to disk.

### Encryption Types

| Type | Description |
|------|-------------|
| **AES-256 (SSE-S3)** | Server-managed encryption using a local master key |
| **KMS (SSE-KMS)** | Encryption using customer-managed keys via the built-in KMS |

### Enabling Encryption

#### 1. Set Environment Variables

```powershell
# PowerShell
$env:ENCRYPTION_ENABLED = "true"
$env:KMS_ENABLED = "true"  # Optional, for KMS key management
python run.py
```

```bash
# Bash
export ENCRYPTION_ENABLED=true
export KMS_ENABLED=true
python run.py
```

#### 2. Configure Bucket Default Encryption (UI)

1. Navigate to your bucket in the UI
2. Click the **Properties** tab
3. Find the **Default Encryption** card
4. Click **Enable Encryption**
5. Choose algorithm:
   - **AES-256**: Uses the server's master key
   - **aws:kms**: Uses a KMS-managed key (select from dropdown)
6. Save changes

Once enabled, all **new objects** uploaded to the bucket will be automatically encrypted.

### KMS Key Management

When `KMS_ENABLED=true`, you can manage encryption keys via the KMS API:

```bash
# Create a new KMS key
curl -X POST http://localhost:5000/kms/keys \
  -H "Content-Type: application/json" \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..." \
  -d '{"alias": "my-key", "description": "Production encryption key"}'

# List all keys
curl http://localhost:5000/kms/keys \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..."

# Get key details
curl http://localhost:5000/kms/keys/{key-id} \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..."

# Rotate a key (creates new key material)
curl -X POST http://localhost:5000/kms/keys/{key-id}/rotate \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..."

# Disable/Enable a key
curl -X POST http://localhost:5000/kms/keys/{key-id}/disable \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..."

curl -X POST http://localhost:5000/kms/keys/{key-id}/enable \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..."

# Schedule key deletion (30-day waiting period)
curl -X DELETE http://localhost:5000/kms/keys/{key-id}?waiting_period_days=30 \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..."
```

### How It Works

1. **Envelope Encryption**: Each object is encrypted with a unique Data Encryption Key (DEK)
2. **Key Wrapping**: The DEK is encrypted (wrapped) by the master key or KMS key
3. **Storage**: The encrypted DEK is stored alongside the encrypted object
4. **Decryption**: On read, the DEK is unwrapped and used to decrypt the object

### Client-Side Encryption

For additional security, you can use client-side encryption. The `ClientEncryptionHelper` class provides utilities:

```python
from app.encryption import ClientEncryptionHelper

# Generate a client-side key
key = ClientEncryptionHelper.generate_key()
key_b64 = ClientEncryptionHelper.key_to_base64(key)

# Encrypt before upload
plaintext = b"sensitive data"
encrypted, metadata = ClientEncryptionHelper.encrypt_for_upload(plaintext, key)

# Upload with metadata headers
# x-amz-meta-x-amz-key: <wrapped-key>
# x-amz-meta-x-amz-iv: <iv>
# x-amz-meta-x-amz-matdesc: <material-description>

# Decrypt after download
decrypted = ClientEncryptionHelper.decrypt_from_download(encrypted, metadata, key)
```

### Important Notes

- **Existing objects are NOT encrypted** - Only new uploads after enabling encryption are encrypted
- **Master key security** - The master key file (`master.key`) should be backed up securely and protected
- **Key rotation** - Rotating a KMS key creates new key material; existing objects remain encrypted with the old material
- **Disabled keys** - Objects encrypted with a disabled key cannot be decrypted until the key is re-enabled
- **Deleted keys** - Once a key is deleted (after the waiting period), objects encrypted with it are permanently inaccessible

### Verifying Encryption

To verify an object is encrypted:
1. Check the raw file in `data/<bucket>/` - it should be unreadable binary
2. Look for `.meta` files containing encryption metadata
3. Download via the API/UI - the object should be automatically decrypted

## 8. Bucket Quotas

MyFSIO supports **storage quotas** to limit how much data a bucket can hold. Quotas are enforced on uploads and multipart completions.

### Quota Types

| Limit | Description |
|-------|-------------|
| **Max Size (MB)** | Maximum total storage in megabytes (includes current objects + archived versions) |
| **Max Objects** | Maximum number of objects (includes current objects + archived versions) |

### Managing Quotas (Admin Only)

Quota management is restricted to administrators (users with `iam:*` or `iam:list_users` permissions).

#### Via UI

1. Navigate to your bucket in the UI
2. Click the **Properties** tab
3. Find the **Storage Quota** card
4. Enter limits:
   - **Max Size (MB)**: Leave empty for unlimited
   - **Max Objects**: Leave empty for unlimited
5. Click **Update Quota**

To remove a quota, click **Remove Quota**.

#### Via API

```bash
# Set quota (max 100MB, max 1000 objects)
curl -X PUT "http://localhost:5000/bucket/<bucket>?quota" \
  -H "Content-Type: application/json" \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..." \
  -d '{"max_bytes": 104857600, "max_objects": 1000}'

# Get current quota
curl "http://localhost:5000/bucket/<bucket>?quota" \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..."

# Remove quota
curl -X PUT "http://localhost:5000/bucket/<bucket>?quota" \
  -H "Content-Type: application/json" \
  -H "X-Access-Key: ..." -H "X-Secret-Key: ..." \
  -d '{"max_bytes": null, "max_objects": null}'
```

### Quota Behavior

- **Version Counting**: When versioning is enabled, archived versions count toward the quota
- **Enforcement Points**: Quotas are checked during `PUT` object and `CompleteMultipartUpload` operations
- **Error Response**: When quota is exceeded, the API returns `HTTP 400` with error code `QuotaExceeded`
- **Visibility**: All users can view quota usage in the bucket detail page, but only admins can modify quotas

### Example Error

```xml
<Error>
  <Code>QuotaExceeded</Code>
  <Message>Bucket quota exceeded: storage limit reached</Message>
  <BucketName>my-bucket</BucketName>
</Error>
```

## 9. Site Replication

### Permission Model

Replication uses a two-tier permission system:

| Role | Capabilities |
|------|--------------|
| **Admin** (users with `iam:*` permissions) | Create/delete replication rules, configure connections and target buckets |
| **Users** (with `replication` permission) | Enable/disable (pause/resume) existing replication rules |

> **Note:** The Replication tab is hidden for users without the `replication` permission on the bucket.

This separation allows administrators to pre-configure where data should replicate, while allowing authorized users to toggle replication on/off without accessing connection credentials.

### Architecture

- **Source Instance**: The MyFSIO instance where you upload files. It runs the replication worker.
- **Target Instance**: Another MyFSIO instance (or any S3-compatible service like AWS S3, MinIO) that receives the copies.

Replication is **asynchronous** (happens in the background) and **one-way** (Source -> Target).

### Setup Guide

#### 1. Prepare the Target Instance

If your target is another MyFSIO server (e.g., running on a different machine or port), you need to create a destination bucket and a user with write permissions.

**Option A: Using the UI (Easiest)**
If you have access to the UI of the target instance:
1.  Log in to the Target UI.
2.  Create a new bucket (e.g., `backup-bucket`).
3.  Go to **IAM**, create a new user (e.g., `replication-user`), and copy the Access/Secret keys.

**Option B: Headless Setup (API Only)**
If the target server is only running the API (`run_api.py`) and has no UI access, you can bootstrap the credentials and bucket by running a Python script on the server itself.

Run this script on the **Target Server**:

```python
# setup_target.py
from pathlib import Path
from app.iam import IamService
from app.storage import ObjectStorage

# Initialize services (paths match default config)
data_dir = Path("data")
iam = IamService(data_dir / ".myfsio.sys" / "config" / "iam.json")
storage = ObjectStorage(data_dir)

# 1. Create the bucket
bucket_name = "backup-bucket"
try:
    storage.create_bucket(bucket_name)
    print(f"Bucket '{bucket_name}' created.")
except Exception as e:
    print(f"Bucket creation skipped: {e}")

# 2. Create the user
try:
    # Create user with full access (or restrict policy as needed)
    creds = iam.create_user(
        display_name="Replication User",
        policies=[{"bucket": bucket_name, "actions": ["write", "read", "list"]}]
    )
    print("\n--- CREDENTIALS GENERATED ---")
    print(f"Access Key: {creds['access_key']}")
    print(f"Secret Key: {creds['secret_key']}")
    print("-----------------------------")
except Exception as e:
    print(f"User creation failed: {e}")
```

Save and run: `python setup_target.py`

#### 2. Configure the Source Instance

Now, configure the primary instance to replicate to the target.

1.  **Access the Console**:
    Log in to the UI of your Source Instance.

2.  **Add a Connection**:
    - Navigate to **Connections** in the top menu.
    - Click **Add Connection**.
    - **Name**: `Secondary Site`.
    - **Endpoint URL**: The URL of your Target Instance's API (e.g., `http://target-server:5002`).
    - **Access Key**: The key you generated on the Target.
    - **Secret Key**: The secret you generated on the Target.
    - Click **Add Connection**.

3.  **Enable Replication** (Admin):
    - Navigate to **Buckets** and select the source bucket.
    - Switch to the **Replication** tab.
    - Select the `Secondary Site` connection.
    - Enter the target bucket name (`backup-bucket`).
    - Click **Enable Replication**.

    Once configured, users with `replication` permission on this bucket can pause/resume replication without needing access to connection details.

### Verification

1.  Upload a file to the source bucket.
2.  Check the target bucket (via UI, CLI, or API). The file should appear shortly.

```bash
# Verify on target using AWS CLI
aws --endpoint-url http://target-server:5002 s3 ls s3://backup-bucket
```

### Pausing and Resuming Replication

Users with the `replication` permission (but not admin rights) can pause and resume existing replication rules:

1. Navigate to the bucket's **Replication** tab.
2. If replication is **Active**, click **Pause Replication** to temporarily stop syncing.
3. If replication is **Paused**, click **Resume Replication** to continue syncing.

When paused, new objects uploaded to the source will not replicate until replication is resumed. Objects uploaded while paused will be replicated once resumed.

> **Note:** Only admins can create new replication rules, change the target connection/bucket, or delete rules entirely.

### Bidirectional Replication (Active-Active)

To set up two-way replication (Server A ↔ Server B):

1.  Follow the steps above to replicate **A → B**.
2.  Repeat the process on Server B to replicate **B → A**:
    - Create a connection on Server B pointing to Server A.
    - Enable replication on the target bucket on Server B.

**Loop Prevention**: The system automatically detects replication traffic using a custom User-Agent (`S3ReplicationAgent`). This prevents infinite loops where an object replicated from A to B is immediately replicated back to A.

**Deletes**: Deleting an object on one server will propagate the deletion to the other server.

**Note**: Deleting a bucket will automatically remove its associated replication configuration.

## 11. Running Tests

```bash
pytest -q
```

The suite now includes a boto3 integration test that spins up a live HTTP server and drives the API through the official AWS SDK. If you want to skip it (for faster unit-only loops), run `pytest -m "not integration"`.

The suite covers bucket CRUD, presigned downloads, bucket policy enforcement, and regression tests for anonymous reads when a Public policy is attached.

## 12. Troubleshooting

| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| 403 from API despite Public preset | Policy didn’t save or bucket key path mismatch | Reapply Public preset, confirm bucket name in `Resource` matches `arn:aws:s3:::bucket/*`. |
| UI still shows old policy text | Browser cached view before hot reload | Refresh; JSON is already reloaded on server. |
| Presign modal errors with 403 | IAM user lacks `read/write/delete` for target bucket or bucket policy denies | Update IAM inline policies or remove conflicting deny statements. |
| Large upload rejected immediately | File exceeds `MAX_UPLOAD_SIZE` | Increase env var or shrink object. |

## 13. API Matrix

```
GET    /                               # List buckets
PUT    /<bucket>                        # Create bucket
DELETE /<bucket>                        # Remove bucket
GET    /<bucket>                        # List objects
PUT    /<bucket>/<key>                  # Upload object
GET    /<bucket>/<key>                  # Download object
DELETE /<bucket>/<key>                  # Delete object
GET    /<bucket>?policy                 # Fetch policy
PUT    /<bucket>?policy                 # Upsert policy
DELETE /<bucket>?policy                 # Delete policy
GET    /<bucket>?quota                  # Get bucket quota
PUT    /<bucket>?quota                  # Set bucket quota (admin only)
```
