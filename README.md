# MyFSIO

A lightweight, S3-compatible object storage system built with Flask. MyFSIO implements core AWS S3 REST API operations with filesystem-backed storage, making it ideal for local development, testing, and self-hosted storage scenarios.

## Features

**Core Storage**
- S3-compatible REST API with AWS Signature Version 4 authentication
- Bucket and object CRUD operations
- Object versioning with version history
- Multipart uploads for large files
- Presigned URLs (1 second to 7 days validity)

**Security & Access Control**
- IAM users with access key management and rotation
- Bucket policies (AWS Policy Version 2012-10-17)
- Server-side encryption (SSE-S3 and SSE-KMS)
- Built-in Key Management Service (KMS)
- Rate limiting per endpoint

**Advanced Features**
- Cross-bucket replication to remote S3-compatible endpoints
- Hot-reload for bucket policies (no restart required)
- CORS configuration per bucket

**Management UI**
- Web console for bucket and object management
- IAM dashboard for user administration
- Inline JSON policy editor with presets
- Object browser with folder navigation and bulk operations
- Dark mode support

## Architecture

```
+------------------+         +------------------+
|   API Server     |         |   UI Server      |
|   (port 5000)    |         |   (port 5100)    |
|                  |         |                  |
|  - S3 REST API   |<------->|  - Web Console   |
|  - SigV4 Auth    |         |  - IAM Dashboard |
|  - Presign URLs  |         |  - Bucket Editor |
+--------+---------+         +------------------+
         |
         v
+------------------+         +------------------+
| Object Storage   |         | System Metadata  |
| (filesystem)     |         | (.myfsio.sys/)   |
|                  |         |                  |
| data/<bucket>/   |         | - IAM config     |
|   <objects>      |         | - Bucket policies|
|                  |         | - Encryption keys|
+------------------+         +------------------+
```

## Quick Start

```bash
# Clone and setup
git clone https://gitea.jzwsite.com/kqjy/MyFSIO
cd s3
python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Windows CMD:
.venv\Scripts\activate.bat
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start both servers
python run.py

# Or start individually
python run.py --mode api   # API only (port 5000)
python run.py --mode ui    # UI only (port 5100)
```

**Default Credentials:** `localadmin` / `localadmin`

- **Web Console:** http://127.0.0.1:5100/ui
- **API Endpoint:** http://127.0.0.1:5000

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_ROOT` | `./data` | Filesystem root for bucket storage |
| `IAM_CONFIG` | `.myfsio.sys/config/iam.json` | IAM user and policy store |
| `BUCKET_POLICY_PATH` | `.myfsio.sys/config/bucket_policies.json` | Bucket policy store |
| `API_BASE_URL` | `http://127.0.0.1:5000` | API endpoint for UI calls |
| `MAX_UPLOAD_SIZE` | `1073741824` | Maximum upload size in bytes (1 GB) |
| `MULTIPART_MIN_PART_SIZE` | `5242880` | Minimum multipart part size (5 MB) |
| `UI_PAGE_SIZE` | `100` | Default page size for listings |
| `SECRET_KEY` | `dev-secret-key` | Flask session secret |
| `AWS_REGION` | `us-east-1` | Region for SigV4 signing |
| `AWS_SERVICE` | `s3` | Service name for SigV4 signing |
| `ENCRYPTION_ENABLED` | `false` | Enable server-side encryption |
| `KMS_ENABLED` | `false` | Enable Key Management Service |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

## Data Layout

```
data/
├── <bucket>/                    # User buckets with objects
└── .myfsio.sys/                 # System metadata
    ├── config/
    │   ├── iam.json             # IAM users and policies
    │   ├── bucket_policies.json # Bucket policies
    │   ├── replication_rules.json
    │   └── connections.json     # Remote S3 connections
    ├── buckets/<bucket>/
    │   ├── meta/                # Object metadata (.meta.json)
    │   ├── versions/            # Archived object versions
    │   └── .bucket.json         # Bucket config (versioning, CORS)
    ├── multipart/               # Active multipart uploads
    └── keys/                    # Encryption keys (SSE-S3/KMS)
```

## API Reference

All endpoints require AWS Signature Version 4 authentication unless using presigned URLs or public bucket policies.

### Bucket Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | List all buckets |
| `PUT` | `/<bucket>` | Create bucket |
| `DELETE` | `/<bucket>` | Delete bucket (must be empty) |
| `HEAD` | `/<bucket>` | Check bucket exists |

### Object Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/<bucket>` | List objects (supports `list-type=2`) |
| `PUT` | `/<bucket>/<key>` | Upload object |
| `GET` | `/<bucket>/<key>` | Download object |
| `DELETE` | `/<bucket>/<key>` | Delete object |
| `HEAD` | `/<bucket>/<key>` | Get object metadata |
| `POST` | `/<bucket>/<key>?uploads` | Initiate multipart upload |
| `PUT` | `/<bucket>/<key>?partNumber=N&uploadId=X` | Upload part |
| `POST` | `/<bucket>/<key>?uploadId=X` | Complete multipart upload |
| `DELETE` | `/<bucket>/<key>?uploadId=X` | Abort multipart upload |

### Bucket Policies (S3-compatible)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/<bucket>?policy` | Get bucket policy |
| `PUT` | `/<bucket>?policy` | Set bucket policy |
| `DELETE` | `/<bucket>?policy` | Delete bucket policy |

### Versioning

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/<bucket>/<key>?versionId=X` | Get specific version |
| `DELETE` | `/<bucket>/<key>?versionId=X` | Delete specific version |
| `GET` | `/<bucket>?versions` | List object versions |

### Health Check

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/myfsio/health` | Health check endpoint |

## IAM & Access Control

### Users and Access Keys

On first run, MyFSIO creates a default admin user (`localadmin`/`localadmin`). Use the IAM dashboard to:

- Create and delete users
- Generate and rotate access keys
- Attach inline policies to users
- Control IAM management permissions

### Bucket Policies

Bucket policies follow AWS policy grammar (Version `2012-10-17`) with support for:

- Principal-based access (`*` for anonymous, specific users)
- Action-based permissions (`s3:GetObject`, `s3:PutObject`, etc.)
- Resource patterns (`arn:aws:s3:::bucket/*`)
- Condition keys

**Policy Presets:**
- **Public:** Grants anonymous read access (`s3:GetObject`, `s3:ListBucket`)
- **Private:** Removes bucket policy (IAM-only access)
- **Custom:** Manual policy editing with draft preservation

Policies hot-reload when the JSON file changes.

## Server-Side Encryption

MyFSIO supports two encryption modes:

- **SSE-S3:** Server-managed keys with automatic key rotation
- **SSE-KMS:** Customer-managed keys via built-in KMS

Enable encryption with:
```bash
ENCRYPTION_ENABLED=true python run.py
```

## Cross-Bucket Replication

Replicate objects to remote S3-compatible endpoints:

1. Configure remote connections in the UI
2. Create replication rules specifying source/destination
3. Objects are automatically replicated on upload

## Docker

```bash
docker build -t myfsio .
docker run -p 5000:5000 -p 5100:5100 -v ./data:/app/data myfsio
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_api.py -v

# Run with coverage
pytest tests/ --cov=app --cov-report=html
```

## References

- [Amazon S3 Documentation](https://docs.aws.amazon.com/s3/)
- [AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
- [S3 Bucket Policy Examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
