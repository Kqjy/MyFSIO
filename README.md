# MyFSIO (Flask S3 + IAM)

MyFSIO is a batteries-included, Flask-based recreation of Amazon S3 and IAM workflows built for local development. The design mirrors the [AWS S3 documentation](https://docs.aws.amazon.com/s3/) wherever practical: bucket naming, Signature Version 4 presigning, Version 2012-10-17 bucket policies, IAM-style users, and familiar REST endpoints.

## Why MyFSIO?

- **Dual servers:** Run both the API (port 5000) and UI (port 5100) with a single command: `python run.py`.
- **IAM + access keys:** Users, access keys, key rotation, and bucket-scoped actions (`list/read/write/delete/policy`) now live in `data/.myfsio.sys/config/iam.json` and are editable from the IAM dashboard.
- **Bucket policies + hot reload:** `data/.myfsio.sys/config/bucket_policies.json` uses AWS' policy grammar (Version `2012-10-17`) with a built-in watcher, so editing the JSON file applies immediately. The UI also ships Public/Private/Custom presets for faster edits.
- **Presigned URLs everywhere:** Signature Version 4 presigned URLs respect IAM + bucket policies and replace the now-removed "share link" feature for public access scenarios.
- **Modern UI:** Responsive tables, quick filters, preview sidebar, object-level delete buttons, a presign modal, and an inline JSON policy editor that respects dark mode keep bucket management friendly.
- **Tests & health:** `/healthz` for smoke checks and `pytest` coverage for IAM, CRUD, presign, and policy flows.

## Architecture at a Glance

```
+-----------------+        +----------------+
| API Server      |<----->| Object storage |
| (port 5000)     |        | (filesystem)   |
|  - S3 routes    |        +----------------+
|  - Presigned URLs |
|  - Bucket policy  |
+-----------------+
        ^
        |
+-----------------+
| UI Server       |
| (port 5100)     |
|  - Auth console |
|  - IAM dashboard|
|  - Bucket editor|
+-----------------+
```

Both apps load the same configuration via `AppConfig` so IAM data and bucket policies stay consistent no matter which process you run.
Bucket policies are automatically reloaded whenever `bucket_policies.json` changes—no restarts required.

## Getting Started

```bash
python -m venv .venv
. .venv/Scripts/activate  # PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run both API and UI (default)
python run.py

# Or run individually:
# python run.py --mode api
# python run.py --mode ui
```

Visit `http://127.0.0.1:5100/ui` for the console and `http://127.0.0.1:5000/` for the raw API. Override ports/hosts with the environment variables listed below.

## IAM, Access Keys, and Bucket Policies

- First run creates `data/.myfsio.sys/config/iam.json` with `localadmin / localadmin` (full control). Sign in via the UI, then use the **IAM** tab to create users, rotate secrets, or edit inline policies without touching JSON by hand.
- Bucket policies live in `data/.myfsio.sys/config/bucket_policies.json` and follow the AWS `arn:aws:s3:::bucket/key` resource syntax with Version `2012-10-17`. Attach/replace/remove policies from the bucket detail page or edit the JSON by hand—changes hot reload automatically.
- IAM actions include extended verbs (`iam:list_users`, `iam:create_user`, `iam:update_policy`, etc.) so you can control who is allowed to manage other users and policies.

### Bucket Policy Presets & Hot Reload

- **Presets:** Every bucket detail view includes Public (read-only), Private (detach policy), and Custom presets. Public auto-populates a policy that grants anonymous `s3:ListBucket` + `s3:GetObject` access to the entire bucket.
- **Custom drafts:** Switching back to Custom restores your last manual edit so you can toggle between presets without losing work.
- **Hot reload:** The server watches `bucket_policies.json` and reloads statements on-the-fly—ideal for editing policies in your favorite editor while testing Via curl or the UI.

## Presigned URLs

Presigned URLs follow the AWS CLI playbook:

- Call `POST /presign/<bucket>/<key>` (or use the "Presign" button in the UI) to request a Signature Version 4 URL valid for 1 second to 7 days.
- The generated URL honors IAM permissions and bucket-policy decisions at generation-time and again when somebody fetches it.
- Because presigned URLs cover both authenticated and public sharing scenarios, the legacy "share link" feature has been removed.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `STORAGE_ROOT` | `<project>/data` | Filesystem root for bucket directories |
| `MAX_UPLOAD_SIZE` | `1073741824` | Maximum upload size (bytes) |
| `UI_PAGE_SIZE` | `100` | `MaxKeys` hint for listings |
| `SECRET_KEY` | `dev-secret-key` | Flask session secret for the UI |
| `IAM_CONFIG` | `<project>/data/.myfsio.sys/config/iam.json` | IAM user + policy store |
| `BUCKET_POLICY_PATH` | `<project>/data/.myfsio.sys/config/bucket_policies.json` | Bucket policy store |
| `API_BASE_URL` | `http://127.0.0.1:5000` | Used by the UI when calling API endpoints (presign, bucket policy) |
| `AWS_REGION` | `us-east-1` | Region used in Signature V4 scope |
| `AWS_SERVICE` | `s3` | Service used in Signature V4 scope |

> Buckets now live directly under `data/` while system metadata (versions, IAM, bucket policies, multipart uploads, etc.) lives in `data/.myfsio.sys`. Existing installs can keep their environment variables, but the defaults now match MinIO's `data/.system` pattern for easier bind-mounting.

## API Cheatsheet (IAM headers required)

```
GET    /                               -> List buckets (XML)
PUT    /<bucket>                       -> Create bucket
DELETE /<bucket>                       -> Delete bucket (must be empty)
GET    /<bucket>                       -> List objects (XML)
PUT    /<bucket>/<key>                 -> Upload object (binary stream)
GET    /<bucket>/<key>                 -> Download object
DELETE /<bucket>/<key>                 -> Delete object
POST   /presign/<bucket>/<key>         -> Generate AWS SigV4 presigned URL (JSON)
GET    /bucket-policy/<bucket>         -> Fetch bucket policy (JSON)
PUT    /bucket-policy/<bucket>         -> Attach/replace bucket policy (JSON)
DELETE /bucket-policy/<bucket>         -> Remove bucket policy
```

## Testing

```bash
pytest -q
```

## References

- [Amazon Simple Storage Service Documentation](https://docs.aws.amazon.com/s3/)
- [Signature Version 4 Signing Process](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
- [Amazon S3 Bucket Policy Examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
