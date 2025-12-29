"""Authenticated HTML UI for browsing buckets and objects."""
from __future__ import annotations

import json
import uuid
import psutil
import shutil
from typing import Any
from urllib.parse import quote, urlparse

import boto3
import requests
from botocore.exceptions import ClientError
from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_wtf.csrf import generate_csrf

from .bucket_policies import BucketPolicyStore
from .connections import ConnectionStore, RemoteConnection
from .extensions import limiter
from .iam import IamError
from .kms import KMSManager
from .replication import ReplicationManager, ReplicationRule
from .secret_store import EphemeralSecretStore
from .storage import ObjectStorage, StorageError

ui_bp = Blueprint("ui", __name__, template_folder="../templates", url_prefix="/ui")



def _storage() -> ObjectStorage:
    return current_app.extensions["object_storage"]


def _replication_manager() -> ReplicationManager:
    return current_app.extensions["replication"]


def _iam():
    return current_app.extensions["iam"]


def _kms() -> KMSManager | None:
    return current_app.extensions.get("kms")


def _bucket_policies() -> BucketPolicyStore:
    store: BucketPolicyStore = current_app.extensions["bucket_policies"]
    store.maybe_reload()
    return store


def _connections() -> ConnectionStore:
    return current_app.extensions["connections"]


def _replication() -> ReplicationManager:
    return current_app.extensions["replication"]


def _secret_store() -> EphemeralSecretStore:
    store: EphemeralSecretStore = current_app.extensions["secret_store"]
    store.purge_expired()
    return store


def _format_bytes(num: int) -> str:
    step = 1024
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(num)
    for unit in units:
        if value < step or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= step
    return f"{value:.1f} PB"


def _friendly_error_message(exc: Exception) -> str:
    message = str(exc) or "An unexpected error occurred"
    if isinstance(exc, IamError):
        return f"Access issue: {message}"
    if isinstance(exc, StorageError):
        return f"Storage issue: {message}"
    return message


def _policy_allows_public_read(policy: dict[str, Any]) -> bool:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    list_allowed = False
    get_allowed = False
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition"):
            continue
        principal = statement.get("Principal")
        principal_all = principal == "*" or (
            isinstance(principal, dict)
            and any(value == "*" or value == ["*"] for value in principal.values())
        )
        if not principal_all:
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        normalized = {action.lower() for action in actions}
        if not list_allowed:
            list_allowed = any(action in {"*", "s3:*", "s3:listbucket"} for action in normalized)
        if not get_allowed:
            get_allowed = any(action in {"*", "s3:*", "s3:getobject"} for action in normalized)
        if list_allowed and get_allowed:
            return True
    return False


def _bucket_access_descriptor(policy: dict[str, Any] | None) -> tuple[str, str]:
    if not policy:
        return ("IAM only", "text-bg-secondary")
    if _policy_allows_public_read(policy):
        return ("Public read", "text-bg-warning")
    return ("Custom policy", "text-bg-info")


def _current_principal():
    creds = session.get("credentials")
    if not creds:
        return None
    try:
        return _iam().authenticate(creds["access_key"], creds["secret_key"])
    except IamError:
        session.pop("credentials", None)
        return None


def _authorize_ui(principal, bucket_name: str | None, action: str, *, object_key: str | None = None) -> None:
    iam_allowed = True
    iam_error: IamError | None = None
    try:
        _iam().authorize(principal, bucket_name, action)
    except IamError as exc:
        iam_allowed = False
        iam_error = exc
    decision = None
    enforce_bucket_policies = current_app.config.get("UI_ENFORCE_BUCKET_POLICIES", True)
    if bucket_name and enforce_bucket_policies:
        access_key = principal.access_key if principal else None
        decision = _bucket_policies().evaluate(access_key, bucket_name, object_key, action)
        if decision == "deny":
            raise IamError("Access denied by bucket policy")
    if not iam_allowed and decision != "allow":
        raise iam_error or IamError("Access denied")


def _api_headers() -> dict[str, str]:
    creds = session.get("credentials") or {}
    return {
        "X-Access-Key": creds.get("access_key", ""),
        "X-Secret-Key": creds.get("secret_key", ""),
    }


@ui_bp.app_context_processor
def inject_nav_state() -> dict[str, Any]:
    principal = _current_principal()
    can_manage = False
    if principal:
        try:
            _iam().authorize(principal, None, "iam:list_users")
            can_manage = True
        except IamError:
            can_manage = False
    return {
        "principal": principal,
        "can_manage_iam": can_manage,
        "can_view_metrics": can_manage, 
        "csrf_token": generate_csrf,
    }


@ui_bp.before_request
def ensure_authenticated():
    exempt = {"ui.login"}
    if request.endpoint in exempt or request.endpoint is None:
        return None
    if _current_principal() is None:
        return redirect(url_for("ui.login"))
    return None


@ui_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        access_key = request.form.get("access_key", "").strip()
        secret_key = request.form.get("secret_key", "").strip()
        try:
            principal = _iam().authenticate(access_key, secret_key)
        except IamError as exc:
            flash(_friendly_error_message(exc), "danger")
            return render_template("login.html")
        session["credentials"] = {"access_key": access_key, "secret_key": secret_key}
        session.permanent = True
        flash(f"Welcome back, {principal.display_name}", "success")
        return redirect(url_for("ui.buckets_overview"))
    return render_template("login.html")


@ui_bp.post("/logout")
def logout():
    session.pop("credentials", None)
    flash("Signed out", "info")
    return redirect(url_for("ui.login"))


@ui_bp.get("/docs")
def docs_page():
    principal = _current_principal()
    api_base = current_app.config.get("API_BASE_URL") or "http://127.0.0.1:5000"
    api_base = api_base.rstrip("/")
    parsed = urlparse(api_base)
    api_host = parsed.netloc or parsed.path or api_base
    return render_template(
        "docs.html",
        principal=principal,
        api_base=api_base,
        api_host=api_host,
    )


@ui_bp.get("/")
def buckets_overview():
    principal = _current_principal()
    buckets = _storage().list_buckets()
    allowed_names = set(_iam().buckets_for_principal(principal, [b.name for b in buckets]))
    visible_buckets = []
    policy_store = _bucket_policies()
    for bucket in buckets:
        if bucket.name not in allowed_names:
            continue
        policy = policy_store.get_policy(bucket.name)
        cache_ttl = current_app.config.get("BUCKET_STATS_CACHE_TTL", 60)
        stats = _storage().bucket_stats(bucket.name, cache_ttl=cache_ttl)
        access_label, access_badge = _bucket_access_descriptor(policy)
        visible_buckets.append({
            "meta": bucket,
            "summary": {
                "objects": stats["total_objects"],
                "total_bytes": stats["total_bytes"],
                "human_size": _format_bytes(stats["total_bytes"]),
            },
            "access_label": access_label,
            "access_badge": access_badge,
            "has_policy": bool(policy),
            "detail_url": url_for("ui.bucket_detail", bucket_name=bucket.name),
        })
    return render_template("buckets.html", buckets=visible_buckets, principal=principal)


@ui_bp.post("/buckets")
def create_bucket():
    principal = _current_principal()
    bucket_name = request.form.get("bucket_name", "").strip()
    if not bucket_name:
        flash("Bucket name is required", "danger")
        return redirect(url_for("ui.buckets_overview"))
    try:
        _authorize_ui(principal, bucket_name, "write")
        _storage().create_bucket(bucket_name)
        flash(f"Bucket '{bucket_name}' created", "success")
    except (StorageError, FileExistsError, IamError) as exc:
        flash(_friendly_error_message(exc), "danger")
    return redirect(url_for("ui.buckets_overview"))


@ui_bp.get("/buckets/<bucket_name>")
def bucket_detail(bucket_name: str):
    principal = _current_principal()
    storage = _storage()
    try:
        _authorize_ui(principal, bucket_name, "list")
        if not storage.bucket_exists(bucket_name):
            raise StorageError("Bucket does not exist")
    except (StorageError, IamError) as exc:
        flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.buckets_overview"))
    bucket_policy = _bucket_policies().get_policy(bucket_name)
    policy_text = json.dumps(bucket_policy, indent=2) if bucket_policy else ""
    default_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowList",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket_name}"],
                },
                {
                    "Sid": "AllowRead",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject"],
                    "Resource": [f"arn:aws:s3:::{bucket_name}/*"],
                },
            ],
        },
        indent=2,
    )
    can_edit_policy = False
    if principal:
        try:
            _iam().authorize(principal, bucket_name, "policy")
            can_edit_policy = True
        except IamError:
            can_edit_policy = False
    try:
        versioning_enabled = storage.is_versioning_enabled(bucket_name)
    except StorageError:
        versioning_enabled = False
    can_manage_versioning = False
    if principal:
        try:
            _iam().authorize(principal, bucket_name, "write")
            can_manage_versioning = True
        except IamError:
            can_manage_versioning = False

    can_manage_replication = False
    if principal:
        try:
            _iam().authorize(principal, bucket_name, "replication")
            can_manage_replication = True
        except IamError:
            can_manage_replication = False

    is_replication_admin = False
    if principal:
        try:
            _iam().authorize(principal, None, "iam:list_users")
            is_replication_admin = True
        except IamError:
            is_replication_admin = False

    replication_rule = _replication().get_rule(bucket_name)
    connections = _connections().list() if (is_replication_admin or replication_rule) else []

    encryption_config = storage.get_bucket_encryption(bucket_name)
    kms_manager = _kms()
    kms_keys = kms_manager.list_keys() if kms_manager else []
    kms_enabled = current_app.config.get("KMS_ENABLED", False)
    encryption_enabled = current_app.config.get("ENCRYPTION_ENABLED", False)
    can_manage_encryption = can_manage_versioning  # Same as other bucket properties

    bucket_quota = storage.get_bucket_quota(bucket_name)
    bucket_stats = storage.bucket_stats(bucket_name)
    can_manage_quota = False
    try:
        _iam().authorize(principal, None, "iam:list_users")
        can_manage_quota = True
    except IamError:
        pass

    objects_api_url = url_for("ui.list_bucket_objects", bucket_name=bucket_name)

    return render_template(
        "bucket_detail.html",
        bucket_name=bucket_name,
        objects_api_url=objects_api_url,
        principal=principal,
        bucket_policy_text=policy_text,
        bucket_policy=bucket_policy,
        can_edit_policy=can_edit_policy,
        can_manage_versioning=can_manage_versioning,
        can_manage_replication=can_manage_replication,
        can_manage_encryption=can_manage_encryption,
        is_replication_admin=is_replication_admin,
        default_policy=default_policy,
        versioning_enabled=versioning_enabled,
        replication_rule=replication_rule,
        connections=connections,
        encryption_config=encryption_config,
        kms_keys=kms_keys,
        kms_enabled=kms_enabled,
        encryption_enabled=encryption_enabled,
        bucket_quota=bucket_quota,
        bucket_stats=bucket_stats,
        can_manage_quota=can_manage_quota,
    )


@ui_bp.get("/buckets/<bucket_name>/objects")
def list_bucket_objects(bucket_name: str):
    """API endpoint for paginated object listing."""
    principal = _current_principal()
    storage = _storage()
    try:
        _authorize_ui(principal, bucket_name, "list")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    max_keys = min(int(request.args.get("max_keys", 1000)), 100000)
    continuation_token = request.args.get("continuation_token") or None
    prefix = request.args.get("prefix") or None

    try:
        result = storage.list_objects(
            bucket_name,
            max_keys=max_keys,
            continuation_token=continuation_token,
            prefix=prefix,
        )
    except StorageError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        versioning_enabled = storage.is_versioning_enabled(bucket_name)
    except StorageError:
        versioning_enabled = False

    # Pre-compute URL templates once (not per-object) for performance
    # Frontend will construct actual URLs by replacing KEY_PLACEHOLDER
    preview_template = url_for("ui.object_preview", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER")
    delete_template = url_for("ui.delete_object", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER")
    presign_template = url_for("ui.object_presign", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER")
    versions_template = url_for("ui.object_versions", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER")
    restore_template = url_for("ui.restore_object_version", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER", version_id="VERSION_ID_PLACEHOLDER")

    objects_data = []
    for obj in result.objects:
        objects_data.append({
            "key": obj.key,
            "size": obj.size,
            "last_modified": obj.last_modified.isoformat(),
            "last_modified_display": obj.last_modified.strftime("%b %d, %Y %H:%M"),
            "etag": obj.etag,
        })

    return jsonify({
        "objects": objects_data,
        "is_truncated": result.is_truncated,
        "next_continuation_token": result.next_continuation_token,
        "total_count": result.total_count,
        "versioning_enabled": versioning_enabled,
        "url_templates": {
            "preview": preview_template,
            "download": preview_template + "?download=1",
            "presign": presign_template,
            "delete": delete_template,
            "versions": versions_template,
            "restore": restore_template,
        },
    })


@ui_bp.post("/buckets/<bucket_name>/upload")
@limiter.limit("30 per minute")
def upload_object(bucket_name: str):
    principal = _current_principal()
    file = request.files.get("object")
    object_key = request.form.get("object_key")
    metadata_raw = (request.form.get("metadata") or "").strip()
    wants_json = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    def _response(success: bool, message: str, status: int = 200):
        if wants_json:
            payload = {"status": "ok" if success else "error", "message": message}
            return jsonify(payload), status
        flash(message, "success" if success else "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="objects"))

    if file and not object_key:
        object_key = file.filename
    if not object_key:
        return _response(False, "Object key is required", 400)
    if not file:
        return _response(False, "Choose a file to upload", 400)

    metadata = None
    if metadata_raw:
        try:
            parsed = json.loads(metadata_raw)
            if not isinstance(parsed, dict):
                raise ValueError
            metadata = {str(k): str(v) for k, v in parsed.items()}
        except ValueError:
            return _response(False, "Metadata must be a JSON object", 400)

    try:
        _authorize_ui(principal, bucket_name, "write")
        _storage().put_object(bucket_name, object_key, file.stream, metadata=metadata)
        
        # Trigger replication
        _replication().trigger_replication(bucket_name, object_key)
        
        message = f"Uploaded '{object_key}'"
        if metadata:
            message += " with metadata"
        return _response(True, message)
    except (StorageError, IamError) as exc:
        return _response(False, _friendly_error_message(exc), 400)


@ui_bp.post("/buckets/<bucket_name>/multipart/initiate")
def initiate_multipart_upload(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "write")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403
    payload = request.get_json(silent=True) or {}
    object_key = str(payload.get("object_key", "")).strip()
    if not object_key:
        return jsonify({"error": "object_key is required"}), 400
    metadata_payload = payload.get("metadata")
    metadata = None
    if metadata_payload is not None:
        if not isinstance(metadata_payload, dict):
            return jsonify({"error": "metadata must be an object"}), 400
        metadata = {str(k): str(v) for k, v in metadata_payload.items()}
    try:
        upload_id = _storage().initiate_multipart_upload(bucket_name, object_key, metadata=metadata)
    except StorageError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"upload_id": upload_id})


@ui_bp.put("/buckets/<bucket_name>/multipart/<upload_id>/parts")
def upload_multipart_part(bucket_name: str, upload_id: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "write")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403
    try:
        part_number = int(request.args.get("partNumber", "0"))
    except ValueError:
        return jsonify({"error": "partNumber must be an integer"}), 400
    if part_number < 1:
        return jsonify({"error": "partNumber must be >= 1"}), 400
    try:
        etag = _storage().upload_multipart_part(bucket_name, upload_id, part_number, request.stream)
    except StorageError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"etag": etag, "part_number": part_number})


@ui_bp.post("/buckets/<bucket_name>/multipart/<upload_id>/complete")
def complete_multipart_upload(bucket_name: str, upload_id: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "write")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403
    payload = request.get_json(silent=True) or {}
    parts_payload = payload.get("parts")
    if not isinstance(parts_payload, list) or not parts_payload:
        return jsonify({"error": "parts array required"}), 400
    normalized = []
    for part in parts_payload:
        if not isinstance(part, dict):
            return jsonify({"error": "Each part must be an object"}), 400
        raw_number = part.get("part_number") or part.get("PartNumber")
        try:
            number = int(raw_number)
        except (TypeError, ValueError):
            return jsonify({"error": "Each part must include part_number"}), 400
        etag = str(part.get("etag") or part.get("ETag") or "").strip()
        normalized.append({"part_number": number, "etag": etag})
    try:
        result = _storage().complete_multipart_upload(bucket_name, upload_id, normalized)
        _replication().trigger_replication(bucket_name, result["key"])
        
        return jsonify(result)
    except StorageError as exc:
        return jsonify({"error": str(exc)}), 400


@ui_bp.delete("/buckets/<bucket_name>/multipart/<upload_id>")
def abort_multipart_upload(bucket_name: str, upload_id: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "write")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403
    try:
        _storage().abort_multipart_upload(bucket_name, upload_id)
    except StorageError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"status": "aborted"})


@ui_bp.post("/buckets/<bucket_name>/delete")
@limiter.limit("20 per minute")
def delete_bucket(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "delete")
        _storage().delete_bucket(bucket_name)
        _bucket_policies().delete_policy(bucket_name)
        _replication_manager().delete_rule(bucket_name)
        flash(f"Bucket '{bucket_name}' removed", "success")
    except (StorageError, IamError) as exc:
        flash(_friendly_error_message(exc), "danger")
    return redirect(url_for("ui.buckets_overview"))


@ui_bp.post("/buckets/<bucket_name>/objects/<path:object_key>/delete")
@limiter.limit("60 per minute")
def delete_object(bucket_name: str, object_key: str):
    principal = _current_principal()
    purge_versions = request.form.get("purge_versions") == "1"
    try:
        _authorize_ui(principal, bucket_name, "delete", object_key=object_key)
        if purge_versions:
            _storage().purge_object(bucket_name, object_key)
            flash(f"Permanently deleted '{object_key}' and all versions", "success")
        else:
            _storage().delete_object(bucket_name, object_key)
            _replication_manager().trigger_replication(bucket_name, object_key, action="delete")
            flash(f"Deleted '{object_key}'", "success")
    except (IamError, StorageError) as exc:
        flash(_friendly_error_message(exc), "danger")
    return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name))


@ui_bp.post("/buckets/<bucket_name>/objects/bulk-delete")
@limiter.limit("40 per minute")
def bulk_delete_objects(bucket_name: str):
    principal = _current_principal()
    wants_json = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json
    payload = request.get_json(silent=True) or {}
    keys_payload = payload.get("keys")
    purge_versions = bool(payload.get("purge_versions"))

    def _respond(success: bool, message: str, *, deleted=None, errors=None, status_code: int = 200):
        if wants_json:
            body = {
                "status": "ok" if success else "partial",
                "message": message,
                "deleted": deleted or [],
                "errors": errors or [],
            }
            if not success and not errors:
                body["status"] = "error"
            return jsonify(body), status_code
        flash(message, "success" if success and not errors else "warning")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name))

    if not isinstance(keys_payload, list):
        return _respond(False, "keys must be provided as a JSON array", status_code=400)

    cleaned: list[str] = []
    for entry in keys_payload:
        if isinstance(entry, str):
            candidate = entry.strip()
            if candidate:
                cleaned.append(candidate)
    if not cleaned:
        return _respond(False, "Select at least one object to delete", status_code=400)

    MAX_KEYS = current_app.config.get("BULK_DELETE_MAX_KEYS", 500)
    if len(cleaned) > MAX_KEYS:
        return _respond(False, f"A maximum of {MAX_KEYS} objects can be deleted per request", status_code=400)

    unique_keys = list(dict.fromkeys(cleaned))
    storage = _storage()
    try:
        _authorize_ui(principal, bucket_name, "delete")
    except IamError as exc:
        return _respond(False, _friendly_error_message(exc), status_code=403)

    deleted: list[str] = []
    errors: list[dict[str, str]] = []
    for key in unique_keys:
        try:
            if purge_versions:
                storage.purge_object(bucket_name, key)
            else:
                storage.delete_object(bucket_name, key)
                _replication_manager().trigger_replication(bucket_name, key, action="delete")
            deleted.append(key)
        except StorageError as exc:
            errors.append({"key": key, "error": str(exc)})

    if not deleted and errors:
        return _respond(False, "Unable to delete the selected objects", deleted=deleted, errors=errors, status_code=400)

    message = f"Deleted {len(deleted)} object{'s' if len(deleted) != 1 else ''}"
    if purge_versions and deleted:
        message += " (including archived versions)"
    if errors:
        message += f"; {len(errors)} failed"
    return _respond(not errors, message, deleted=deleted, errors=errors)


@ui_bp.post("/buckets/<bucket_name>/objects/bulk-download")
@limiter.limit("10 per minute")
def bulk_download_objects(bucket_name: str):
    import io
    import zipfile

    principal = _current_principal()
    payload = request.get_json(silent=True) or {}
    keys_payload = payload.get("keys")

    if not isinstance(keys_payload, list):
        return jsonify({"error": "keys must be provided as a JSON array"}), 400

    cleaned: list[str] = []
    for entry in keys_payload:
        if isinstance(entry, str):
            candidate = entry.strip()
            if candidate:
                cleaned.append(candidate)
    if not cleaned:
        return jsonify({"error": "Select at least one object to download"}), 400

    MAX_KEYS = current_app.config.get("BULK_DELETE_MAX_KEYS", 500)  # Reuse same limit for now
    if len(cleaned) > MAX_KEYS:
        return jsonify({"error": f"A maximum of {MAX_KEYS} objects can be downloaded per request"}), 400

    unique_keys = list(dict.fromkeys(cleaned))
    storage = _storage()
    
    # Verify permission to read bucket contents
    try:
        _authorize_ui(principal, bucket_name, "read")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    # Create ZIP archive of selected objects
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for key in unique_keys:
            try:
                _authorize_ui(principal, bucket_name, "read", object_key=key)
                
                metadata = storage.get_object_metadata(bucket_name, key)
                is_encrypted = "x-amz-server-side-encryption" in metadata
                
                if is_encrypted and hasattr(storage, 'get_object_data'):
                    data, _ = storage.get_object_data(bucket_name, key)
                    zf.writestr(key, data)
                else:
                    path = storage.get_object_path(bucket_name, key)
                    zf.write(path, arcname=key)
            except (StorageError, IamError):
                # Skip objects that can't be accessed
                continue
    
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{bucket_name}-download.zip",
        mimetype="application/zip"
    )


@ui_bp.post("/buckets/<bucket_name>/objects/<path:object_key>/purge")
@limiter.limit("30 per minute")
def purge_object_versions(bucket_name: str, object_key: str):
    principal = _current_principal()
    wants_json = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    try:
        _authorize_ui(principal, bucket_name, "delete", object_key=object_key)
        _storage().purge_object(bucket_name, object_key)
    except IamError as exc:
        if wants_json:
            return jsonify({"error": str(exc)}), 403
        flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name))
    except StorageError as exc:
        if wants_json:
            return jsonify({"error": str(exc)}), 400
        flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name))
    message = f"Removed archived versions for '{object_key}'"
    if wants_json:
        return jsonify({"status": "ok", "message": message})
    flash(message, "success")
    return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name))


@ui_bp.get("/buckets/<bucket_name>/objects/<path:object_key>/preview")
def object_preview(bucket_name: str, object_key: str) -> Response:
    principal = _current_principal()
    storage = _storage()
    try:
        _authorize_ui(principal, bucket_name, "read", object_key=object_key)
        path = storage.get_object_path(bucket_name, object_key)
        metadata = storage.get_object_metadata(bucket_name, object_key)
    except (StorageError, IamError) as exc:
        status = 403 if isinstance(exc, IamError) else 404
        return Response(str(exc), status=status)
    
    download = request.args.get("download") == "1"
    
    # Check if object is encrypted and needs decryption
    is_encrypted = "x-amz-server-side-encryption" in metadata
    if is_encrypted and hasattr(storage, 'get_object_data'):
        try:
            data, _ = storage.get_object_data(bucket_name, object_key)
            import io
            import mimetypes
            mimetype = mimetypes.guess_type(object_key)[0] or "application/octet-stream"
            return send_file(
                io.BytesIO(data),
                mimetype=mimetype,
                as_attachment=download,
                download_name=path.name
            )
        except StorageError as exc:
            return Response(f"Decryption failed: {exc}", status=500)
    
    return send_file(path, as_attachment=download, download_name=path.name)


@ui_bp.post("/buckets/<bucket_name>/objects/<path:object_key>/presign")
def object_presign(bucket_name: str, object_key: str):
    principal = _current_principal()
    payload = request.get_json(silent=True) or {}
    method = str(payload.get("method", "GET")).upper()
    action = "read" if method == "GET" else ("delete" if method == "DELETE" else "write")
    try:
        _authorize_ui(principal, bucket_name, action, object_key=object_key)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403
    
    api_base = current_app.config.get("API_BASE_URL") or "http://127.0.0.1:5000"
    api_base = api_base.rstrip("/")
    encoded_key = quote(object_key, safe="/")
    url = f"{api_base}/presign/{bucket_name}/{encoded_key}"
    
    # Use API base URL for forwarded headers so presigned URLs point to API, not UI
    parsed_api = urlparse(api_base)
    headers = _api_headers()
    headers["X-Forwarded-Host"] = parsed_api.netloc or "127.0.0.1:5000"
    headers["X-Forwarded-Proto"] = parsed_api.scheme or "http"
    headers["X-Forwarded-For"] = request.remote_addr or "127.0.0.1"
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=5)
    except requests.RequestException as exc:
        return jsonify({"error": f"API unavailable: {exc}"}), 502
    try:
        body = response.json()
    except ValueError:
        text = response.text or ""
        if text.strip().startswith("<"):
            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(text)
                message = root.findtext(".//Message") or root.findtext(".//Code") or "Unknown S3 error"
                body = {"error": message}
            except ET.ParseError:
                body = {"error": text or "API returned an empty response"}
        else:
            body = {"error": text or "API returned an empty response"}
    return jsonify(body), response.status_code


@ui_bp.get("/buckets/<bucket_name>/objects/<path:object_key>/versions")
def object_versions(bucket_name: str, object_key: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "read", object_key=object_key)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403
    try:
        versions = _storage().list_object_versions(bucket_name, object_key)
    except StorageError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"versions": versions})


@ui_bp.get("/buckets/<bucket_name>/archived")
def archived_objects(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "list")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403
    try:
        entries = _storage().list_orphaned_objects(bucket_name)
    except StorageError as exc:
        return jsonify({"error": str(exc)}), 400
    payload: list[dict[str, Any]] = []
    for entry in entries:
        latest = entry.get("latest") or {}
        restore_url = None
        if latest.get("version_id"):
            restore_url = url_for(
                "ui.restore_object_version",
                bucket_name=bucket_name,
                object_key=entry["key"],
                version_id=latest["version_id"],
            )
        purge_url = url_for("ui.purge_object_versions", bucket_name=bucket_name, object_key=entry["key"])
        payload.append(
            {
                "key": entry["key"],
                "versions": entry.get("versions", 0),
                "total_size": entry.get("total_size", 0),
                "latest": entry.get("latest"),
                "restore_url": restore_url,
                "purge_url": purge_url,
            }
        )
    return jsonify({"objects": payload})


@ui_bp.post("/buckets/<bucket_name>/objects/<path:object_key>/versions/<version_id>/restore")
def restore_object_version(bucket_name: str, object_key: str, version_id: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "write", object_key=object_key)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403
    try:
        meta = _storage().restore_object_version(bucket_name, object_key, version_id)
    except StorageError as exc:
        return jsonify({"error": str(exc)}), 400
    message = f"Restored '{meta.key}'" if meta else "Object restored"
    return jsonify({"status": "ok", "message": message})


@ui_bp.post("/buckets/<bucket_name>/policy")
@limiter.limit("10 per minute")
def update_bucket_policy(bucket_name: str):
    principal = _current_principal()
    action = request.form.get("mode", "upsert")
    try:
        _authorize_ui(principal, bucket_name, "policy")
    except IamError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name))
    store = _bucket_policies()
    if action == "delete":
        store.delete_policy(bucket_name)
        flash("Bucket policy removed", "info")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="permissions"))
    document = request.form.get("policy_document", "").strip()
    if not document:
        flash("Provide a JSON policy document", "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="permissions"))
    try:
        payload = json.loads(document)
        store.set_policy(bucket_name, payload)
        flash("Bucket policy saved", "success")
    except (json.JSONDecodeError, ValueError) as exc:
        flash(f"Policy error: {exc}", "danger")
    return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="permissions"))


@ui_bp.post("/buckets/<bucket_name>/versioning")
def update_bucket_versioning(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "write")
    except IamError as exc:
        flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))
    state = request.form.get("state", "enable")
    enable = state == "enable"
    try:
        _storage().set_bucket_versioning(bucket_name, enable)
    except StorageError as exc:
        flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))
    flash("Versioning enabled" if enable else "Versioning suspended", "success")
    return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))


@ui_bp.post("/buckets/<bucket_name>/quota")
def update_bucket_quota(bucket_name: str):
    """Update bucket quota configuration (admin only)."""
    principal = _current_principal()
    
    # Quota management is admin-only
    is_admin = False
    try:
        _iam().authorize(principal, None, "iam:list_users")
        is_admin = True
    except IamError:
        pass
    
    if not is_admin:
        flash("Only administrators can manage bucket quotas", "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))
    
    action = request.form.get("action", "set")
    
    if action == "remove":
        try:
            _storage().set_bucket_quota(bucket_name, max_bytes=None, max_objects=None)
            flash("Bucket quota removed", "info")
        except StorageError as exc:
            flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))
    
    # Parse quota values
    max_mb_str = request.form.get("max_mb", "").strip()
    max_objects_str = request.form.get("max_objects", "").strip()
    
    max_bytes = None
    max_objects = None
    
    if max_mb_str:
        try:
            max_mb = int(max_mb_str)
            if max_mb < 1:
                raise ValueError("Size must be at least 1 MB")
            max_bytes = max_mb * 1024 * 1024  # Convert MB to bytes
        except ValueError as exc:
            flash(f"Invalid size value: {exc}", "danger")
            return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))
    
    if max_objects_str:
        try:
            max_objects = int(max_objects_str)
            if max_objects < 0:
                raise ValueError("Object count must be non-negative")
        except ValueError as exc:
            flash(f"Invalid object count: {exc}", "danger")
            return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))
    
    try:
        _storage().set_bucket_quota(bucket_name, max_bytes=max_bytes, max_objects=max_objects)
        if max_bytes is None and max_objects is None:
            flash("Bucket quota removed", "info")
        else:
            flash("Bucket quota updated", "success")
    except StorageError as exc:
        flash(_friendly_error_message(exc), "danger")
    
    return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))


@ui_bp.post("/buckets/<bucket_name>/encryption")
def update_bucket_encryption(bucket_name: str):
    """Update bucket default encryption configuration."""
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "write")
    except IamError as exc:
        flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))
    
    action = request.form.get("action", "enable")
    
    if action == "disable":
        try:
            _storage().set_bucket_encryption(bucket_name, None)
            flash("Default encryption disabled", "info")
        except StorageError as exc:
            flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))
    
    algorithm = request.form.get("algorithm", "AES256")
    kms_key_id = request.form.get("kms_key_id", "").strip() or None
    
    if algorithm not in ("AES256", "aws:kms"):
        flash("Invalid encryption algorithm", "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))
    
    # Build encryption configuration in AWS S3 format
    encryption_config: dict[str, Any] = {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": algorithm,
                }
            }
        ]
    }
    
    if algorithm == "aws:kms" and kms_key_id:
        encryption_config["Rules"][0]["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"] = kms_key_id
    
    try:
        _storage().set_bucket_encryption(bucket_name, encryption_config)
        if algorithm == "aws:kms":
            flash("Default KMS encryption enabled", "success")
        else:
            flash("Default AES-256 encryption enabled", "success")
    except StorageError as exc:
        flash(_friendly_error_message(exc), "danger")
    
    return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))


@ui_bp.get("/iam")
def iam_dashboard():
    principal = _current_principal()
    iam_service = _iam()
    secret_token = request.args.get("secret_token")
    disclosed_secret: dict[str, str] | None = None
    if secret_token:
        payload = _secret_store().pop(secret_token)
        if isinstance(payload, dict):
            access_key = str(payload.get("access_key", ""))
            secret_key = payload.get("secret_key")
            if secret_key:
                disclosed_secret = {
                    "access_key": access_key,
                    "secret_key": str(secret_key),
                    "operation": str(payload.get("operation", "create")),
                }
    locked = False
    locked_reason = None
    try:
        iam_service.authorize(principal, None, "iam:list_users")
    except IamError as exc:
        locked = True
        locked_reason = str(exc)
    users = iam_service.list_users() if not locked else []
    config_summary = iam_service.config_summary()
    config_document = json.dumps(iam_service.export_config(mask_secrets=True), indent=2)
    return render_template(
        "iam.html",
        users=users,
        principal=principal,
        iam_locked=locked,
        locked_reason=locked_reason,
        config_summary=config_summary,
        config_document=config_document,
        disclosed_secret=disclosed_secret,
    )


@ui_bp.post("/iam/users")
def create_iam_user():
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:create_user")
    except IamError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("ui.iam_dashboard"))
    display_name = request.form.get("display_name", "").strip() or "Unnamed"
    if len(display_name) > 64:
        flash("Display name must be 64 characters or fewer", "danger")
        return redirect(url_for("ui.iam_dashboard"))
    policies_text = request.form.get("policies", "").strip()
    policies = None
    if policies_text:
        try:
            policies = json.loads(policies_text)
        except json.JSONDecodeError as exc:
            flash(f"Invalid JSON: {exc}", "danger")
            return redirect(url_for("ui.iam_dashboard"))
    try:
        created = _iam().create_user(display_name=display_name, policies=policies)
    except IamError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("ui.iam_dashboard"))

    token = _secret_store().remember(
        {
            "access_key": created["access_key"],
            "secret_key": created["secret_key"],
            "operation": "create",
        }
    )
    flash(f"Created user {created['access_key']}. Copy the secret below.", "success")
    return redirect(url_for("ui.iam_dashboard", secret_token=token))


@ui_bp.post("/iam/users/<access_key>/rotate")
def rotate_iam_secret(access_key: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:rotate_key")
    except IamError as exc:
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({"error": str(exc)}), 403
        flash(str(exc), "danger")
        return redirect(url_for("ui.iam_dashboard"))
    try:
        new_secret = _iam().rotate_secret(access_key)
        if principal and principal.access_key == access_key:
            creds = session.get("credentials", {})
            creds["secret_key"] = new_secret
            session["credentials"] = creds
            session.modified = True
    except IamError as exc:
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({"error": str(exc)}), 400
        flash(str(exc), "danger")
        return redirect(url_for("ui.iam_dashboard"))

    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({
            "access_key": access_key,
            "secret_key": new_secret,
            "message": f"Secret rotated for {access_key}",
        })

    token = _secret_store().remember(
        {
            "access_key": access_key,
            "secret_key": new_secret,
            "operation": "rotate",
        }
    )
    flash(f"Rotated secret for {access_key}. Copy the secret below.", "info")
    return redirect(url_for("ui.iam_dashboard", secret_token=token))


@ui_bp.post("/iam/users/<access_key>/update")
def update_iam_user(access_key: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:create_user")
    except IamError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("ui.iam_dashboard"))

    display_name = request.form.get("display_name", "").strip()
    if display_name:
        if len(display_name) > 64:
            flash("Display name must be 64 characters or fewer", "danger")
        else:
            try:
                _iam().update_user(access_key, display_name)
                flash(f"Updated user {access_key}", "success")
            except IamError as exc:
                flash(str(exc), "danger")

    return redirect(url_for("ui.iam_dashboard"))


@ui_bp.post("/iam/users/<access_key>/delete")
def delete_iam_user(access_key: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:delete_user")
    except IamError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("ui.iam_dashboard"))

    if access_key == principal.access_key:
        try:
            _iam().delete_user(access_key)
            session.pop("credentials", None)
            flash("Your account has been deleted.", "info")
            return redirect(url_for("ui.login"))
        except IamError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("ui.iam_dashboard"))

    try:
        _iam().delete_user(access_key)
        flash(f"Deleted user {access_key}", "success")
    except IamError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("ui.iam_dashboard"))


@ui_bp.post("/iam/users/<access_key>/policies")
def update_iam_policies(access_key: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:update_policy")
    except IamError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("ui.iam_dashboard"))

    policies_raw = request.form.get("policies", "").strip()
    if not policies_raw:
        policies = []
    else:
        try:
            policies = json.loads(policies_raw)
            if not isinstance(policies, list):
                raise ValueError("Policies must be a list")
        except (ValueError, json.JSONDecodeError):
            flash("Invalid JSON format for policies", "danger")
            return redirect(url_for("ui.iam_dashboard"))

    try:
        _iam().update_user_policies(access_key, policies)
        flash(f"Updated policies for {access_key}", "success")
    except IamError as exc:
        flash(str(exc), "danger")

    return redirect(url_for("ui.iam_dashboard"))


@ui_bp.post("/connections")
def create_connection():
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        flash("Access denied", "danger")
        return redirect(url_for("ui.buckets_overview"))
        
    name = request.form.get("name", "").strip()
    endpoint = request.form.get("endpoint_url", "").strip()
    access_key = request.form.get("access_key", "").strip()
    secret_key = request.form.get("secret_key", "").strip()
    region = request.form.get("region", "us-east-1").strip()
    
    if not all([name, endpoint, access_key, secret_key]):
        flash("All fields are required", "danger")
        return redirect(url_for("ui.connections_dashboard"))
        
    conn = RemoteConnection(
        id=str(uuid.uuid4()),
        name=name,
        endpoint_url=endpoint,
        access_key=access_key,
        secret_key=secret_key,
        region=region
    )
    _connections().add(conn)
    flash(f"Connection '{name}' created", "success")
    return redirect(url_for("ui.connections_dashboard"))


@ui_bp.post("/connections/test")
def test_connection():
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import ConnectTimeoutError, EndpointConnectionError, ReadTimeoutError
    
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        return jsonify({"status": "error", "message": "Access denied"}), 403

    data = request.get_json(silent=True) or request.form
    endpoint = data.get("endpoint_url", "").strip()
    access_key = data.get("access_key", "").strip()
    secret_key = data.get("secret_key", "").strip()
    region = data.get("region", "us-east-1").strip()

    if not all([endpoint, access_key, secret_key]):
        return jsonify({"status": "error", "message": "Missing credentials"}), 400

    try:
        config = BotoConfig(
            connect_timeout=5,
            read_timeout=10,
            retries={'max_attempts': 1}
        )
        s3 = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            config=config,
        )

        s3.list_buckets()
        return jsonify({"status": "ok", "message": "Connection successful"})
    except (ConnectTimeoutError, ReadTimeoutError):
        return jsonify({"status": "error", "message": f"Connection timed out - endpoint may be down or unreachable: {endpoint}"}), 400
    except EndpointConnectionError:
        return jsonify({"status": "error", "message": f"Could not connect to endpoint: {endpoint}"}), 400
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        return jsonify({"status": "error", "message": f"Connection failed ({error_code}): {error_msg}"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Connection failed: {str(e)}"}), 400


@ui_bp.post("/connections/<connection_id>/update")
def update_connection(connection_id: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        flash("Access denied", "danger")
        return redirect(url_for("ui.buckets_overview"))

    conn = _connections().get(connection_id)
    if not conn:
        flash("Connection not found", "danger")
        return redirect(url_for("ui.connections_dashboard"))

    name = request.form.get("name", "").strip()
    endpoint = request.form.get("endpoint_url", "").strip()
    access_key = request.form.get("access_key", "").strip()
    secret_key = request.form.get("secret_key", "").strip()
    region = request.form.get("region", "us-east-1").strip()

    if not all([name, endpoint, access_key, secret_key]):
        flash("All fields are required", "danger")
        return redirect(url_for("ui.connections_dashboard"))

    conn.name = name
    conn.endpoint_url = endpoint
    conn.access_key = access_key
    conn.secret_key = secret_key
    conn.region = region
    
    _connections().save()
    flash(f"Connection '{name}' updated", "success")
    return redirect(url_for("ui.connections_dashboard"))


@ui_bp.post("/connections/<connection_id>/delete")
def delete_connection(connection_id: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        flash("Access denied", "danger")
        return redirect(url_for("ui.buckets_overview"))
        
    _connections().delete(connection_id)
    flash("Connection deleted", "success")
    return redirect(url_for("ui.connections_dashboard"))


@ui_bp.post("/buckets/<bucket_name>/replication")
def update_bucket_replication(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "replication")
    except IamError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="replication"))
    
    is_admin = False
    try:
        _iam().authorize(principal, None, "iam:list_users")
        is_admin = True
    except IamError:
        is_admin = False
        
    action = request.form.get("action")
    
    if action == "delete":
        if not is_admin:
            flash("Only administrators can remove replication configuration", "danger")
            return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="replication"))
        _replication().delete_rule(bucket_name)
        flash("Replication configuration removed", "info")
    elif action == "pause":
        rule = _replication().get_rule(bucket_name)
        if rule:
            rule.enabled = False
            _replication().set_rule(rule)
            flash("Replication paused", "info")
        else:
            flash("No replication configuration to pause", "warning")
    elif action == "resume":
        from .replication import REPLICATION_MODE_ALL
        rule = _replication().get_rule(bucket_name)
        if rule:
            rule.enabled = True
            _replication().set_rule(rule)
            # When resuming, sync any pending objects that accumulated while paused
            if rule.mode == REPLICATION_MODE_ALL:
                _replication().replicate_existing_objects(bucket_name)
                flash("Replication resumed. Syncing pending objects in background.", "success")
            else:
                flash("Replication resumed", "success")
        else:
            flash("No replication configuration to resume", "warning")
    elif action == "create":
        if not is_admin:
            flash("Only administrators can configure replication settings", "danger")
            return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="replication"))
            
        from .replication import REPLICATION_MODE_NEW_ONLY, REPLICATION_MODE_ALL
        import time
        
        target_conn_id = request.form.get("target_connection_id")
        target_bucket = request.form.get("target_bucket", "").strip()
        replication_mode = request.form.get("replication_mode", REPLICATION_MODE_NEW_ONLY)
        
        if not target_conn_id or not target_bucket:
            flash("Target connection and bucket are required", "danger")
        else:
            rule = ReplicationRule(
                bucket_name=bucket_name,
                target_connection_id=target_conn_id,
                target_bucket=target_bucket,
                enabled=True,
                mode=replication_mode,
                created_at=time.time(),
            )
            _replication().set_rule(rule)
            
            if replication_mode == REPLICATION_MODE_ALL:
                _replication().replicate_existing_objects(bucket_name)
                flash("Replication configured. Existing objects are being replicated in the background.", "success")
            else:
                flash("Replication configured. Only new uploads will be replicated.", "success")
    else:
        flash("Invalid action", "danger")
            
    return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="replication"))


@ui_bp.get("/buckets/<bucket_name>/replication/status")
def get_replication_status(bucket_name: str):
    """Async endpoint to fetch replication sync status without blocking page load."""
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "replication")
    except IamError:
        return jsonify({"error": "Access denied"}), 403
    
    rule = _replication().get_rule(bucket_name)
    if not rule:
        return jsonify({"error": "No replication rule"}), 404
    
    connection = _connections().get(rule.target_connection_id)
    endpoint_healthy = False
    endpoint_error = None
    if connection:
        endpoint_healthy = _replication().check_endpoint_health(connection)
        if not endpoint_healthy:
            endpoint_error = f"Cannot reach endpoint: {connection.endpoint_url}"
    else:
        endpoint_error = "Target connection not found"
    
    stats = None
    if endpoint_healthy:
        stats = _replication().get_sync_status(bucket_name)
    
    if not stats:
        return jsonify({
            "objects_synced": 0,
            "objects_pending": 0,
            "objects_orphaned": 0,
            "bytes_synced": 0,
            "last_sync_at": rule.stats.last_sync_at if rule.stats else None,
            "last_sync_key": rule.stats.last_sync_key if rule.stats else None,
            "endpoint_healthy": endpoint_healthy,
            "endpoint_error": endpoint_error,
        })
    
    return jsonify({
        "objects_synced": stats.objects_synced,
        "objects_pending": stats.objects_pending,
        "objects_orphaned": stats.objects_orphaned,
        "bytes_synced": stats.bytes_synced,
        "last_sync_at": stats.last_sync_at,
        "last_sync_key": stats.last_sync_key,
        "endpoint_healthy": endpoint_healthy,
        "endpoint_error": endpoint_error,
    })


@ui_bp.get("/connections/<connection_id>/health")
def check_connection_health(connection_id: str):
    """Check if a connection endpoint is reachable."""
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        return jsonify({"error": "Access denied"}), 403
    
    conn = _connections().get(connection_id)
    if not conn:
        return jsonify({"healthy": False, "error": "Connection not found"}), 404
    
    healthy = _replication().check_endpoint_health(conn)
    return jsonify({
        "healthy": healthy,
        "error": None if healthy else f"Cannot reach endpoint: {conn.endpoint_url}"
    })


@ui_bp.get("/connections")
def connections_dashboard():
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        flash("Access denied", "danger")
        return redirect(url_for("ui.buckets_overview"))
        
    connections = _connections().list()
    return render_template("connections.html", connections=connections, principal=principal)


@ui_bp.get("/metrics")
def metrics_dashboard():
    principal = _current_principal()
    
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        flash("Access denied: Metrics require admin permissions", "danger")
        return redirect(url_for("ui.buckets_overview"))
    
    from app.version import APP_VERSION
    import time
    
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    
    storage_root = current_app.config["STORAGE_ROOT"]
    disk = psutil.disk_usage(storage_root)
    
    storage = _storage()
    buckets = storage.list_buckets()
    total_buckets = len(buckets)
    
    total_objects = 0
    total_bytes_used = 0
    total_versions = 0
    
    cache_ttl = current_app.config.get("BUCKET_STATS_CACHE_TTL", 60)
    for bucket in buckets:
        stats = storage.bucket_stats(bucket.name, cache_ttl=cache_ttl)
        total_objects += stats.get("total_objects", stats.get("objects", 0))
        total_bytes_used += stats.get("total_bytes", stats.get("bytes", 0))
        total_versions += stats.get("version_count", 0)
    
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time
    uptime_days = int(uptime_seconds / 86400)
        
    return render_template(
        "metrics.html",
        principal=principal,
        cpu_percent=cpu_percent,
        memory={
            "total": _format_bytes(memory.total),
            "available": _format_bytes(memory.available),
            "used": _format_bytes(memory.used),
            "percent": memory.percent,
        },
        disk={
            "total": _format_bytes(disk.total),
            "free": _format_bytes(disk.free),
            "used": _format_bytes(disk.used),
            "percent": disk.percent,
        },
        app={
            "buckets": total_buckets,
            "objects": total_objects,
            "versions": total_versions,
            "storage_used": _format_bytes(total_bytes_used),
            "storage_raw": total_bytes_used,
            "version": APP_VERSION,
            "uptime_days": uptime_days,
        }
    )


@ui_bp.app_errorhandler(404)
def ui_not_found(error):  # type: ignore[override]
    prefix = ui_bp.url_prefix or ""
    path = request.path or ""
    wants_html = request.accept_mimetypes.accept_html
    if wants_html and (not prefix or path.startswith(prefix)):
        return render_template("404.html"), 404
    return error
