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

The repo now tracks a human-friendly release string inside `app/version.py` (see the `APP_VERSION` constant). Edit that value whenever you cut a release. The constant flows into Flask as `APP_VERSION` and is exposed via `GET /healthz`, so you can monitor deployments or surface it in UIs.

## 3. Configuration Reference

| Variable | Default | Notes |
| --- | --- | --- |
| `STORAGE_ROOT` | `<repo>/data` | Filesystem home for all buckets/objects. |
| `MAX_UPLOAD_SIZE` | `1073741824` | Bytes. Caps incoming uploads in both API + UI. |
| `UI_PAGE_SIZE` | `100` | `MaxKeys` hint shown in listings. |
| `SECRET_KEY` | `dev-secret-key` | Flask session key for UI auth. |
| `IAM_CONFIG` | `<repo>/data/.myfsio.sys/config/iam.json` | Stores users, secrets, and inline policies. |
| `BUCKET_POLICY_PATH` | `<repo>/data/.myfsio.sys/config/bucket_policies.json` | Bucket policy store (auto hot-reload). |
| `API_BASE_URL` | `None` | Used by the UI to hit API endpoints (presign/policy). If unset, the UI will auto-detect the host or use `X-Forwarded-*` headers. |
| `AWS_REGION` | `us-east-1` | Region embedded in SigV4 credential scope. |
| `AWS_SERVICE` | `s3` | Service string for SigV4. |

Set env vars (or pass overrides to `create_app`) to point the servers at custom paths.

### Proxy Configuration

If running behind a reverse proxy (e.g., Nginx, Cloudflare, or a tunnel), ensure the proxy sets the standard forwarding headers:
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

The application automatically trusts these headers to generate correct presigned URLs (e.g., `https://s3.example.com/...` instead of `http://127.0.0.1:5000/...`). Alternatively, you can explicitly set `API_BASE_URL` to your public endpoint.

## 4. Authentication & IAM

1. On first boot, `data/.myfsio.sys/config/iam.json` is seeded with `localadmin / localadmin` that has wildcard access.
2. Sign into the UI using those credentials, then open **IAM**:
   - **Create user**: supply a display name and optional JSON inline policy array.
   - **Rotate secret**: generates a new secret key; the UI surfaces it once.
   - **Policy editor**: select a user, paste an array of objects (`{"bucket": "*", "actions": ["list", "read"]}`), and submit. Alias support includes AWS-style verbs (e.g., `s3:GetObject`).
3. Wildcard action `iam:*` is supported for admin user definitions.

The API expects every request to include `X-Access-Key` and `X-Secret-Key` headers. The UI persists them in the Flask session after login.

### Available IAM Actions

| Action | Description | AWS Aliases |
| --- | --- | --- |
| `list` | List buckets and objects | `s3:ListBucket`, `s3:ListAllMyBuckets`, `s3:ListBucketVersions`, `s3:ListMultipartUploads`, `s3:ListParts` |
| `read` | Download objects | `s3:GetObject`, `s3:GetObjectVersion`, `s3:GetObjectTagging`, `s3:HeadObject`, `s3:HeadBucket` |
| `write` | Upload objects, create buckets | `s3:PutObject`, `s3:CreateBucket`, `s3:CreateMultipartUpload`, `s3:UploadPart`, `s3:CompleteMultipartUpload`, `s3:AbortMultipartUpload`, `s3:CopyObject` |
| `delete` | Remove objects and buckets | `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:DeleteBucket` |
| `share` | Manage ACLs | `s3:PutObjectAcl`, `s3:PutBucketAcl`, `s3:GetBucketAcl` |
| `policy` | Manage bucket policies | `s3:PutBucketPolicy`, `s3:GetBucketPolicy`, `s3:DeleteBucketPolicy` |
| `replication` | Configure and manage replication | `s3:GetReplicationConfiguration`, `s3:PutReplicationConfiguration`, `s3:ReplicateObject`, `s3:ReplicateTags`, `s3:ReplicateDelete` |
| `iam:list_users` | View IAM users | `iam:ListUsers` |
| `iam:create_user` | Create IAM users | `iam:CreateUser` |
| `iam:delete_user` | Delete IAM users | `iam:DeleteUser` |
| `iam:rotate_key` | Rotate user secrets | `iam:RotateAccessKey` |
| `iam:update_policy` | Modify user policies | `iam:PutUserPolicy` |
| `iam:*` | All IAM actions (admin wildcard) | — |

### Example Policies

**Full Control (admin):**
```json
[{"bucket": "*", "actions": ["list", "read", "write", "delete", "share", "policy", "replication", "iam:*"]}]
```

**Read-Only:**
```json
[{"bucket": "*", "actions": ["list", "read"]}]
```

**Single Bucket Access (no listing other buckets):**
```json
[{"bucket": "user-bucket", "actions": ["read", "write", "delete"]}]
```

**Bucket Access with Replication:**
```json
[{"bucket": "my-bucket", "actions": ["list", "read", "write", "delete", "replication"]}]
```

## 5. Bucket Policies & Presets

- **Storage**: Policies are persisted in `data/.myfsio.sys/config/bucket_policies.json` under `{"policies": {"bucket": {...}}}`.
- **Hot reload**: Both API and UI call `maybe_reload()` before evaluating policies. Editing the JSON on disk is immediately reflected—no restarts required.
- **UI editor**: Each bucket detail page includes:
  - A preset selector: **Private** detaches the policy (delete mode), **Public** injects an allow policy granting anonymous `s3:ListBucket` + `s3:GetObject`, and **Custom** restores your draft.
  - A read-only preview of the attached policy.
  - Autosave behavior for custom drafts while you type.

### Editing via CLI

```bash
curl -X PUT http://127.0.0.1:5000/bucket-policy/test \
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

## 6. Presigned URLs

- Trigger from the UI using the **Presign** button after selecting an object.
- Or call `POST /presign/<bucket>/<key>` with JSON `{ "method": "GET", "expires_in": 900 }`.
- Supported methods: `GET`, `PUT`, `DELETE`; expiration must be `1..604800` seconds.
- The service signs requests using the caller’s IAM credentials and enforces bucket policies both when issuing and when the presigned URL is used.
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

## 6. Site Replication

MyFSIO supports **Site Replication**, allowing you to automatically copy new objects from one MyFSIO instance (Source) to another (Target). This is useful for disaster recovery, data locality, or backups.

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

## 7. Running Tests

```bash
pytest -q
```

The suite now includes a boto3 integration test that spins up a live HTTP server and drives the API through the official AWS SDK. If you want to skip it (for faster unit-only loops), run `pytest -m "not integration"`.

The suite covers bucket CRUD, presigned downloads, bucket policy enforcement, and regression tests for anonymous reads when a Public policy is attached.

## 8. Troubleshooting

| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| 403 from API despite Public preset | Policy didn’t save or bucket key path mismatch | Reapply Public preset, confirm bucket name in `Resource` matches `arn:aws:s3:::bucket/*`. |
| UI still shows old policy text | Browser cached view before hot reload | Refresh; JSON is already reloaded on server. |
| Presign modal errors with 403 | IAM user lacks `read/write/delete` for target bucket or bucket policy denies | Update IAM inline policies or remove conflicting deny statements. |
| Large upload rejected immediately | File exceeds `MAX_UPLOAD_SIZE` | Increase env var or shrink object. |

## 9. API Matrix

```
GET    /                               # List buckets
PUT    /<bucket>                        # Create bucket
DELETE /<bucket>                        # Remove bucket
GET    /<bucket>                        # List objects
PUT    /<bucket>/<key>                  # Upload object
GET    /<bucket>/<key>                  # Download object
DELETE /<bucket>/<key>                  # Delete object
POST   /presign/<bucket>/<key>          # Generate SigV4 URL
GET    /bucket-policy/<bucket>          # Fetch policy
PUT    /bucket-policy/<bucket>          # Upsert policy
DELETE /bucket-policy/<bucket>          # Delete policy
```

## 10. Next Steps

- Tailor IAM + policy JSON files for team-ready presets.
- Wrap `run_api.py` with gunicorn or another WSGI server for long-running workloads.
- Extend `bucket_policies.json` to cover Deny statements that simulate production security controls.
