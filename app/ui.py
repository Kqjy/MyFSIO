from __future__ import annotations

import io
import json
import uuid
import psutil
import shutil
from datetime import datetime, timezone as dt_timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse
from zoneinfo import ZoneInfo

import boto3
import requests
from botocore.exceptions import ClientError, EndpointConnectionError, ConnectionClosedError
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

from .acl import AclService, create_canned_acl, CANNED_ACLS
from .bucket_policies import BucketPolicyStore
from .connections import ConnectionStore, RemoteConnection
from .extensions import limiter, csrf
from .iam import IamError
from .kms import KMSManager
from .replication import ReplicationManager, ReplicationRule
from .s3_client import (
    get_session_s3_client,
    get_upload_registry,
    handle_client_error,
    handle_connection_error,
    build_url_templates,
    translate_list_objects,
    get_versioning_via_s3,
    stream_objects_ndjson,
    format_datetime_display as _s3_format_display,
    format_datetime_iso as _s3_format_iso,
)
from .secret_store import EphemeralSecretStore
from .site_registry import SiteRegistry, SiteInfo, PeerSite
from .storage import ObjectStorage, StorageError

ui_bp = Blueprint("ui", __name__, template_folder="../templates", url_prefix="/ui")


def _convert_to_display_tz(dt: datetime, display_tz: str | None = None) -> datetime:
    """Convert a datetime to the configured display timezone.
    
    Args:
        dt: The datetime to convert
        display_tz: Optional timezone string. If not provided, reads from current_app.config.
    """
    if display_tz is None:
        display_tz = current_app.config.get("DISPLAY_TIMEZONE", "UTC")
    if display_tz and display_tz != "UTC":
        try:
            tz = ZoneInfo(display_tz)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=dt_timezone.utc)
            dt = dt.astimezone(tz)
        except (KeyError, ValueError):
            pass
    return dt


def _format_datetime_display(dt: datetime, display_tz: str | None = None) -> str:
    """Format a datetime for display using the configured timezone.

    Args:
        dt: The datetime to format
        display_tz: Optional timezone string. If not provided, reads from current_app.config.
    """
    dt = _convert_to_display_tz(dt, display_tz)
    tz_abbr = dt.strftime("%Z") or "UTC"
    return f"{dt.strftime('%b %d, %Y %H:%M')} ({tz_abbr})"


def _format_datetime_iso(dt: datetime, display_tz: str | None = None) -> str:
    """Format a datetime as ISO format using the configured timezone.
    
    Args:
        dt: The datetime to format
        display_tz: Optional timezone string. If not provided, reads from current_app.config.
    """
    dt = _convert_to_display_tz(dt, display_tz)
    return dt.isoformat()



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


def _build_policy_context() -> dict[str, Any]:
    ctx: dict[str, Any] = {}
    if request.headers.get("Referer"):
        ctx["aws:Referer"] = request.headers.get("Referer")
    if request.access_route:
        ctx["aws:SourceIp"] = request.access_route[0]
    elif request.remote_addr:
        ctx["aws:SourceIp"] = request.remote_addr
    ctx["aws:SecureTransport"] = str(request.is_secure).lower()
    if request.headers.get("User-Agent"):
        ctx["aws:UserAgent"] = request.headers.get("User-Agent")
    return ctx


def _connections() -> ConnectionStore:
    return current_app.extensions["connections"]


def _replication() -> ReplicationManager:
    return current_app.extensions["replication"]


def _secret_store() -> EphemeralSecretStore:
    store: EphemeralSecretStore = current_app.extensions["secret_store"]
    store.purge_expired()
    return store


def _acl() -> AclService:
    return current_app.extensions["acl"]


def _operation_metrics():
    return current_app.extensions.get("operation_metrics")


def _site_registry() -> SiteRegistry:
    return current_app.extensions["site_registry"]


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


def _wants_json() -> bool:
    return request.accept_mimetypes.best_match(
        ["application/json", "text/html"]
    ) == "application/json"


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
    token = session.get("cred_token")
    creds = _secret_store().peek(token) if token else None
    if not creds:
        return None
    try:
        return _iam().authenticate(creds["access_key"], creds["secret_key"])
    except IamError:
        session.pop("cred_token", None)
        if token:
            _secret_store().pop(token)
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
        policy_context = _build_policy_context()
        decision = _bucket_policies().evaluate(access_key, bucket_name, object_key, action, policy_context)
        if decision == "deny":
            raise IamError("Access denied by bucket policy")
    if not iam_allowed and decision != "allow":
        raise iam_error or IamError("Access denied")


def _api_headers() -> dict[str, str]:
    token = session.get("cred_token")
    creds = _secret_store().peek(token) or {}
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
        "website_hosting_nav": can_manage and current_app.config.get("WEBSITE_HOSTING_ENABLED", False),
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
        creds = {"access_key": access_key, "secret_key": secret_key}
        ttl = int(current_app.permanent_session_lifetime.total_seconds())
        token = _secret_store().remember(creds, ttl=ttl)
        session["cred_token"] = token
        session.permanent = True
        flash(f"Welcome back, {principal.display_name}", "success")
        return redirect(url_for("ui.buckets_overview"))
    return render_template("login.html")


@ui_bp.post("/logout")
def logout():
    token = session.pop("cred_token", None)
    if token:
        _secret_store().pop(token)
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
    try:
        client = get_session_s3_client()
        resp = client.list_buckets()
        bucket_names = [b["Name"] for b in resp.get("Buckets", [])]
        bucket_creation = {b["Name"]: b.get("CreationDate") for b in resp.get("Buckets", [])}
    except PermissionError:
        return redirect(url_for("ui.login"))
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            flash(exc.response.get("Error", {}).get("Message", "S3 operation failed"), "danger")
        else:
            flash("S3 API server is unreachable. Ensure the API server is running.", "danger")
        return render_template("buckets.html", buckets=[], principal=principal)

    allowed_names = set(_iam().buckets_for_principal(principal, bucket_names))
    visible_buckets = []
    policy_store = _bucket_policies()
    for name in bucket_names:
        if name not in allowed_names:
            continue
        policy = policy_store.get_policy(name)
        cache_ttl = current_app.config.get("BUCKET_STATS_CACHE_TTL", 60)
        stats = _storage().bucket_stats(name, cache_ttl=cache_ttl)
        access_label, access_badge = _bucket_access_descriptor(policy)

        class _BucketMeta:
            def __init__(self, n, cd):
                self.name = n
                self.creation_date = cd
        meta = _BucketMeta(name, bucket_creation.get(name))

        visible_buckets.append({
            "meta": meta,
            "summary": {
                "objects": stats["total_objects"],
                "total_bytes": stats["total_bytes"],
                "human_size": _format_bytes(stats["total_bytes"]),
            },
            "access_label": access_label,
            "access_badge": access_badge,
            "has_policy": bool(policy),
            "detail_url": url_for("ui.bucket_detail", bucket_name=name),
        })
    return render_template("buckets.html", buckets=visible_buckets, principal=principal)

@ui_bp.get("/buckets")
def buckets_redirect():
    return redirect(url_for("ui.buckets_overview"))

@ui_bp.post("/buckets")
def create_bucket():
    principal = _current_principal()
    bucket_name = request.form.get("bucket_name", "").strip()
    if not bucket_name:
        if _wants_json():
            return jsonify({"error": "Bucket name is required"}), 400
        flash("Bucket name is required", "danger")
        return redirect(url_for("ui.buckets_overview"))
    try:
        _authorize_ui(principal, bucket_name, "write")
        client = get_session_s3_client()
        client.create_bucket(Bucket=bucket_name)
        if _wants_json():
            return jsonify({"success": True, "message": f"Bucket '{bucket_name}' created", "bucket_name": bucket_name})
        flash(f"Bucket '{bucket_name}' created", "success")
    except PermissionError:
        return redirect(url_for("ui.login"))
    except IamError as exc:
        if _wants_json():
            return jsonify({"error": _friendly_error_message(exc)}), 400
        flash(_friendly_error_message(exc), "danger")
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            if _wants_json():
                return jsonify(err), status
            flash(err["error"], "danger")
        else:
            msg = "S3 API server is unreachable"
            if _wants_json():
                return jsonify({"error": msg}), 502
            flash(msg, "danger")
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
    iam = _iam()
    bucket_perms = iam.check_permissions(
        principal, bucket_name, ["policy", "lifecycle", "cors", "write", "replication"],
    ) if principal else {}
    admin_perms = iam.check_permissions(
        principal, None, ["iam:list_users"],
    ) if principal else {}

    can_edit_policy = bucket_perms.get("policy", False)
    can_manage_lifecycle = bucket_perms.get("lifecycle", False)
    can_manage_cors = bucket_perms.get("cors", False)
    can_manage_versioning = bucket_perms.get("write", False)
    can_manage_replication = bucket_perms.get("replication", False)
    is_replication_admin = admin_perms.get("iam:list_users", False)

    try:
        versioning_enabled = storage.is_versioning_enabled(bucket_name)
    except StorageError:
        versioning_enabled = False

    replication_rule = _replication().get_rule(bucket_name)
    connections = _connections().list() if (is_replication_admin or replication_rule) else []

    encryption_config = storage.get_bucket_encryption(bucket_name)
    kms_manager = _kms()
    kms_keys = kms_manager.list_keys() if kms_manager else []
    kms_enabled = current_app.config.get("KMS_ENABLED", False)
    encryption_enabled = current_app.config.get("ENCRYPTION_ENABLED", False)
    lifecycle_enabled = current_app.config.get("LIFECYCLE_ENABLED", False)
    site_sync_enabled = current_app.config.get("SITE_SYNC_ENABLED", False)
    website_hosting_enabled = current_app.config.get("WEBSITE_HOSTING_ENABLED", False)
    can_manage_encryption = can_manage_versioning

    bucket_quota = storage.get_bucket_quota(bucket_name)
    bucket_stats = storage.bucket_stats(bucket_name)
    can_manage_quota = is_replication_admin

    website_config = None
    if website_hosting_enabled:
        try:
            website_config = storage.get_bucket_website(bucket_name)
        except StorageError:
            website_config = None

    objects_api_url = url_for("ui.list_bucket_objects", bucket_name=bucket_name)
    objects_stream_url = url_for("ui.stream_bucket_objects", bucket_name=bucket_name)

    lifecycle_url = url_for("ui.bucket_lifecycle", bucket_name=bucket_name)
    cors_url = url_for("ui.bucket_cors", bucket_name=bucket_name)
    acl_url = url_for("ui.bucket_acl", bucket_name=bucket_name)
    folders_url = url_for("ui.create_folder", bucket_name=bucket_name)
    buckets_for_copy_url = url_for("ui.list_buckets_for_copy", bucket_name=bucket_name)

    return render_template(
        "bucket_detail.html",
        bucket_name=bucket_name,
        objects_api_url=objects_api_url,
        objects_stream_url=objects_stream_url,
        lifecycle_url=lifecycle_url,
        cors_url=cors_url,
        acl_url=acl_url,
        folders_url=folders_url,
        buckets_for_copy_url=buckets_for_copy_url,
        principal=principal,
        bucket_policy_text=policy_text,
        bucket_policy=bucket_policy,
        can_edit_policy=can_edit_policy,
        can_manage_lifecycle=can_manage_lifecycle,
        can_manage_cors=can_manage_cors,
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
        lifecycle_enabled=lifecycle_enabled,
        bucket_quota=bucket_quota,
        bucket_stats=bucket_stats,
        can_manage_quota=can_manage_quota,
        site_sync_enabled=site_sync_enabled,
        website_hosting_enabled=website_hosting_enabled,
        website_config=website_config,
        can_manage_website=can_edit_policy,
    )


@ui_bp.get("/buckets/<bucket_name>/objects")
def list_bucket_objects(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "list")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    try:
        max_keys = max(1, min(int(request.args.get("max_keys", 1000)), 100000))
    except ValueError:
        return jsonify({"error": "max_keys must be an integer"}), 400
    continuation_token = request.args.get("continuation_token") or None
    prefix = request.args.get("prefix") or None

    try:
        client = get_session_s3_client()
        kwargs: dict[str, Any] = {"Bucket": bucket_name, "MaxKeys": max_keys}
        if continuation_token:
            kwargs["ContinuationToken"] = continuation_token
        if prefix:
            kwargs["Prefix"] = prefix
        boto_resp = client.list_objects_v2(**kwargs)
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 401
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))

    versioning_enabled = get_versioning_via_s3(client, bucket_name)
    url_templates = build_url_templates(bucket_name)
    display_tz = current_app.config.get("DISPLAY_TIMEZONE", "UTC")
    data = translate_list_objects(boto_resp, url_templates, display_tz, versioning_enabled)
    response = jsonify(data)
    response.headers["Cache-Control"] = "no-store"
    return response


@ui_bp.get("/buckets/<bucket_name>/objects/stream")
def stream_bucket_objects(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "list")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    prefix = request.args.get("prefix") or None

    try:
        client = get_session_s3_client()
    except (PermissionError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 403

    versioning_enabled = get_versioning_via_s3(client, bucket_name)
    url_templates = build_url_templates(bucket_name)
    display_tz = current_app.config.get("DISPLAY_TIMEZONE", "UTC")

    return Response(
        stream_objects_ndjson(
            client, bucket_name, prefix, url_templates, display_tz, versioning_enabled,
        ),
        mimetype='application/x-ndjson',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'X-Stream-Response': 'true',
        }
    )


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
        client = get_session_s3_client()
        put_kwargs: dict[str, Any] = {
            "Bucket": bucket_name,
            "Key": object_key,
            "Body": file.stream,
        }
        if file.content_type:
            put_kwargs["ContentType"] = file.content_type
        if metadata:
            put_kwargs["Metadata"] = metadata
        client.put_object(**put_kwargs)
        _replication().trigger_replication(bucket_name, object_key)

        message = f"Uploaded '{object_key}'"
        if metadata:
            message += " with metadata"
        return _response(True, message)
    except PermissionError as exc:
        return _response(False, str(exc), 401)
    except IamError as exc:
        return _response(False, _friendly_error_message(exc), 400)
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            return _response(False, err["error"], status)
        return _response(False, "S3 API server is unreachable", 502)


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
    if "\x00" in object_key:
        return jsonify({"error": "Object key cannot contain null bytes"}), 400
    max_key_len = current_app.config.get("OBJECT_KEY_MAX_LENGTH_BYTES", 1024)
    if len(object_key.encode("utf-8")) > max_key_len:
        return jsonify({"error": f"Object key exceeds maximum length of {max_key_len} bytes"}), 400
    metadata_payload = payload.get("metadata")
    metadata = None
    if metadata_payload is not None:
        if not isinstance(metadata_payload, dict):
            return jsonify({"error": "metadata must be an object"}), 400
        metadata = {str(k): str(v) for k, v in metadata_payload.items()}
    try:
        client = get_session_s3_client()
        create_kwargs: dict[str, Any] = {"Bucket": bucket_name, "Key": object_key}
        if metadata:
            create_kwargs["Metadata"] = metadata
        resp = client.create_multipart_upload(**create_kwargs)
        upload_id = resp["UploadId"]
        get_upload_registry().register(upload_id, bucket_name, object_key)
        return jsonify({"upload_id": upload_id})
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 401
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))


@ui_bp.put("/buckets/<bucket_name>/multipart/<upload_id>/parts")
@limiter.exempt
@csrf.exempt
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
    if part_number < 1 or part_number > 10000:
        return jsonify({"error": "partNumber must be between 1 and 10000"}), 400
    object_key = get_upload_registry().get_key(upload_id, bucket_name)
    if not object_key:
        return jsonify({"error": "Unknown upload ID or upload expired"}), 404
    try:
        data = request.get_data()
        if not data:
            return jsonify({"error": "Empty request body"}), 400
        client = get_session_s3_client()
        resp = client.upload_part(
            Bucket=bucket_name,
            Key=object_key,
            UploadId=upload_id,
            PartNumber=part_number,
            Body=data,
        )
        etag = resp.get("ETag", "").strip('"')
        return jsonify({"etag": etag, "part_number": part_number})
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))


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
        normalized.append({"PartNumber": number, "ETag": etag})
    object_key = get_upload_registry().get_key(upload_id, bucket_name)
    if not object_key:
        return jsonify({"error": "Unknown upload ID or upload expired"}), 404
    try:
        client = get_session_s3_client()
        resp = client.complete_multipart_upload(
            Bucket=bucket_name,
            Key=object_key,
            UploadId=upload_id,
            MultipartUpload={"Parts": normalized},
        )
        get_upload_registry().remove(upload_id)
        result_key = resp.get("Key", object_key)
        _replication().trigger_replication(bucket_name, result_key)
        return jsonify({
            "key": result_key,
            "size": 0,
            "etag": resp.get("ETag", "").strip('"'),
            "last_modified": None,
        })
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 401
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchUpload",):
                get_upload_registry().remove(upload_id)
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))


@ui_bp.delete("/buckets/<bucket_name>/multipart/<upload_id>")
def abort_multipart_upload(bucket_name: str, upload_id: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "write")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403
    object_key = get_upload_registry().get_key(upload_id, bucket_name)
    if not object_key:
        return jsonify({"error": "Unknown upload ID or upload expired"}), 404
    try:
        client = get_session_s3_client()
        client.abort_multipart_upload(Bucket=bucket_name, Key=object_key, UploadId=upload_id)
        get_upload_registry().remove(upload_id)
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchUpload",):
                get_upload_registry().remove(upload_id)
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))
    return jsonify({"status": "aborted"})


@ui_bp.post("/buckets/<bucket_name>/delete")
@limiter.limit("20 per minute")
def delete_bucket(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "delete")
        client = get_session_s3_client()
        client.delete_bucket(Bucket=bucket_name)
        try:
            _bucket_policies().delete_policy(bucket_name)
        except Exception:
            pass
        try:
            _replication_manager().delete_rule(bucket_name)
        except Exception:
            pass
        if _wants_json():
            return jsonify({"success": True, "message": f"Bucket '{bucket_name}' removed"})
        flash(f"Bucket '{bucket_name}' removed", "success")
    except PermissionError:
        return redirect(url_for("ui.login"))
    except IamError as exc:
        if _wants_json():
            return jsonify({"error": _friendly_error_message(exc)}), 400
        flash(_friendly_error_message(exc), "danger")
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            if _wants_json():
                return jsonify(err), status
            flash(err["error"], "danger")
        else:
            msg = "S3 API server is unreachable"
            if _wants_json():
                return jsonify({"error": msg}), 502
            flash(msg, "danger")
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
            message = f"Permanently deleted '{object_key}' and all versions"
        else:
            client = get_session_s3_client()
            client.delete_object(Bucket=bucket_name, Key=object_key)
            _replication_manager().trigger_replication(bucket_name, object_key, action="delete")
            message = f"Deleted '{object_key}'"
        if _wants_json():
            return jsonify({"success": True, "message": message})
        flash(message, "success")
    except PermissionError:
        return redirect(url_for("ui.login"))
    except IamError as exc:
        if _wants_json():
            return jsonify({"error": _friendly_error_message(exc)}), 400
        flash(_friendly_error_message(exc), "danger")
    except StorageError as exc:
        if _wants_json():
            return jsonify({"error": _friendly_error_message(exc)}), 400
        flash(_friendly_error_message(exc), "danger")
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
        else:
            err, status = handle_connection_error(exc)
        if _wants_json():
            return jsonify(err), status
        flash(err["error"], "danger")
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
    try:
        _authorize_ui(principal, bucket_name, "delete")
    except IamError as exc:
        return _respond(False, _friendly_error_message(exc), status_code=403)

    authorized_keys = []
    denied_keys = []
    for key in unique_keys:
        try:
            _authorize_ui(principal, bucket_name, "delete", object_key=key)
            authorized_keys.append(key)
        except IamError:
            denied_keys.append(key)
    if not authorized_keys:
        return _respond(False, "Access denied for all selected objects", status_code=403)
    unique_keys = authorized_keys

    if purge_versions:
        storage = _storage()
        deleted: list[str] = []
        errors: list[dict[str, str]] = []
        for key in unique_keys:
            try:
                storage.purge_object(bucket_name, key)
                deleted.append(key)
            except StorageError as exc:
                errors.append({"key": key, "error": str(exc)})
    else:
        try:
            client = get_session_s3_client()
            objects_to_delete = [{"Key": k} for k in unique_keys]
            resp = client.delete_objects(
                Bucket=bucket_name,
                Delete={"Objects": objects_to_delete, "Quiet": False},
            )
            deleted = [d["Key"] for d in resp.get("Deleted", [])]
            errors = [{"key": e["Key"], "error": e.get("Message", e.get("Code", "Unknown error"))} for e in resp.get("Errors", [])]
            for key in deleted:
                _replication_manager().trigger_replication(bucket_name, key, action="delete")
        except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
            if isinstance(exc, ClientError):
                err, status = handle_client_error(exc)
                return _respond(False, err["error"], status_code=status)
            return _respond(False, "S3 API server is unreachable", status_code=502)

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

    MAX_KEYS = current_app.config.get("BULK_DELETE_MAX_KEYS", 500)
    if len(cleaned) > MAX_KEYS:
        return jsonify({"error": f"A maximum of {MAX_KEYS} objects can be downloaded per request"}), 400

    unique_keys = list(dict.fromkeys(cleaned))
    storage = _storage()

    try:
        _authorize_ui(principal, bucket_name, "read")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    max_total_bytes = current_app.config.get("BULK_DOWNLOAD_MAX_BYTES", 1024 * 1024 * 1024)
    total_size = 0
    for key in unique_keys:
        try:
            path = storage.get_object_path(bucket_name, key)
            total_size += path.stat().st_size
        except (StorageError, OSError):
            continue
    if total_size > max_total_bytes:
        limit_mb = max_total_bytes // (1024 * 1024)
        return jsonify({"error": f"Total download size exceeds {limit_mb} MB limit. Select fewer objects."}), 400

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
    import mimetypes as _mimetypes
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "read", object_key=object_key)
    except IamError as exc:
        return Response(str(exc), status=403)

    download = request.args.get("download") == "1"
    raw_filename = object_key.rsplit("/", 1)[-1] or object_key
    safe_filename = raw_filename.replace('"', "'").replace("\\", "_")
    safe_filename = "".join(c for c in safe_filename if c.isprintable() and c not in "\r\n")
    if not safe_filename:
        safe_filename = "download"
    try:
        safe_filename.encode("latin-1")
        ascii_safe = True
    except UnicodeEncodeError:
        ascii_safe = False

    range_header = request.headers.get("Range")

    try:
        client = get_session_s3_client()
        get_kwargs: dict[str, Any] = {"Bucket": bucket_name, "Key": object_key}
        if range_header:
            get_kwargs["Range"] = range_header
        resp = client.get_object(**get_kwargs)
    except PermissionError as exc:
        return Response(str(exc), status=401)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        status = 404 if code == "NoSuchKey" else 400
        return Response(exc.response.get("Error", {}).get("Message", "S3 operation failed"), status=status)
    except (EndpointConnectionError, ConnectionClosedError):
        return Response("S3 API server is unreachable", status=502)

    content_type = resp.get("ContentType") or _mimetypes.guess_type(object_key)[0] or "application/octet-stream"
    content_length = resp.get("ContentLength", 0)
    body_stream = resp["Body"]
    is_partial = resp.get("ResponseMetadata", {}).get("HTTPStatusCode") == 206
    content_range = resp.get("ContentRange")

    _DANGEROUS_TYPES = {
        "text/html", "text/xml", "application/xhtml+xml",
        "application/xml", "image/svg+xml",
    }
    base_ct = content_type.split(";")[0].strip().lower()
    if not download and base_ct in _DANGEROUS_TYPES:
        content_type = "text/plain; charset=utf-8"

    def generate():
        try:
            for chunk in body_stream.iter_chunks(chunk_size=65536):
                yield chunk
        finally:
            body_stream.close()

    status_code = 206 if is_partial else 200
    headers = {
        "Content-Type": content_type,
        "X-Content-Type-Options": "nosniff",
        "Accept-Ranges": "bytes",
    }
    if content_length:
        headers["Content-Length"] = str(content_length)
    if content_range:
        headers["Content-Range"] = content_range
    disposition = "attachment" if download else "inline"
    if ascii_safe:
        headers["Content-Disposition"] = f'{disposition}; filename="{safe_filename}"'
    else:
        from urllib.parse import quote
        encoded = quote(safe_filename, safe="")
        ascii_fallback = safe_filename.encode("ascii", "replace").decode("ascii").replace("?", "_")
        headers["Content-Disposition"] = f'{disposition}; filename="{ascii_fallback}"; filename*=UTF-8\'\'{encoded}'

    return Response(generate(), status=status_code, headers=headers)


@ui_bp.post("/buckets/<bucket_name>/objects/<path:object_key>/presign")
def object_presign(bucket_name: str, object_key: str):
    principal = _current_principal()
    payload = request.get_json(silent=True) or {}
    method = str(payload.get("method", "GET")).upper()
    allowed_methods = {"GET", "PUT", "DELETE"}
    if method not in allowed_methods:
        return jsonify({"error": "Method must be GET, PUT, or DELETE"}), 400
    action = "read" if method == "GET" else ("delete" if method == "DELETE" else "write")
    try:
        _authorize_ui(principal, bucket_name, action, object_key=object_key)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403
    try:
        expires = int(payload.get("expires_in", 900))
    except (TypeError, ValueError):
        return jsonify({"error": "expires_in must be an integer"}), 400
    min_expiry = current_app.config.get("PRESIGNED_URL_MIN_EXPIRY_SECONDS", 1)
    max_expiry = current_app.config.get("PRESIGNED_URL_MAX_EXPIRY_SECONDS", 604800)
    expires = max(min_expiry, min(expires, max_expiry))

    method_to_client_method = {"GET": "get_object", "PUT": "put_object", "DELETE": "delete_object"}
    client_method = method_to_client_method[method]

    try:
        client = get_session_s3_client()
        url = client.generate_presigned_url(
            ClientMethod=client_method,
            Params={"Bucket": bucket_name, "Key": object_key},
            ExpiresIn=expires,
        )
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 401
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))
    current_app.logger.info(
        "Presigned URL generated",
        extra={"bucket": bucket_name, "key": object_key, "method": method},
    )
    return jsonify({"url": url, "method": method, "expires_in": expires})


@ui_bp.get("/buckets/<bucket_name>/objects/<path:object_key>/metadata")
def object_metadata(bucket_name: str, object_key: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "read", object_key=object_key)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403
    try:
        client = get_session_s3_client()
        resp = client.head_object(Bucket=bucket_name, Key=object_key)
        metadata = resp.get("Metadata", {})
        if resp.get("ContentType"):
            metadata["Content-Type"] = resp["ContentType"]
        if resp.get("ContentLength") is not None:
            metadata["Content-Length"] = str(resp["ContentLength"])
        if resp.get("ServerSideEncryption"):
            metadata["x-amz-server-side-encryption"] = resp["ServerSideEncryption"]
        return jsonify({"metadata": metadata})
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 401
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404", "NotFound"):
            return jsonify({"error": "Object not found"}), 404
        err, status = handle_client_error(exc)
        return jsonify(err), status
    except (EndpointConnectionError, ConnectionClosedError) as exc:
        return jsonify(*handle_connection_error(exc))


@ui_bp.get("/buckets/<bucket_name>/objects/<path:object_key>/versions")
def object_versions(bucket_name: str, object_key: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "read", object_key=object_key)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403
    try:
        client = get_session_s3_client()
        resp = client.list_object_versions(Bucket=bucket_name, Prefix=object_key, MaxKeys=1000)
        versions = []
        for v in resp.get("Versions", []):
            if v.get("Key") != object_key:
                continue
            versions.append({
                "version_id": v.get("VersionId", ""),
                "last_modified": v["LastModified"].isoformat() if v.get("LastModified") else None,
                "size": v.get("Size", 0),
                "etag": v.get("ETag", "").strip('"'),
                "is_latest": v.get("IsLatest", False),
            })
        return jsonify({"versions": versions})
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))


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
        if _wants_json():
            return jsonify({"error": str(exc)}), 403
        flash(str(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name))

    try:
        client = get_session_s3_client()
    except (PermissionError, RuntimeError) as exc:
        if _wants_json():
            return jsonify({"error": str(exc)}), 403
        flash(str(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name))

    if action == "delete":
        try:
            client.delete_bucket_policy(Bucket=bucket_name)
        except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
            if isinstance(exc, ClientError):
                err, status = handle_client_error(exc)
            else:
                err, status = handle_connection_error(exc)
            if _wants_json():
                return jsonify(err), status
            flash(err["error"], "danger")
            return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="permissions"))
        if _wants_json():
            return jsonify({"success": True, "message": "Bucket policy removed"})
        flash("Bucket policy removed", "info")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="permissions"))

    document = request.form.get("policy_document", "").strip()
    if not document:
        if _wants_json():
            return jsonify({"error": "Provide a JSON policy document"}), 400
        flash("Provide a JSON policy document", "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="permissions"))
    try:
        json.loads(document)
    except json.JSONDecodeError as exc:
        if _wants_json():
            return jsonify({"error": f"Policy error: {exc}"}), 400
        flash(f"Policy error: {exc}", "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="permissions"))
    try:
        client.put_bucket_policy(Bucket=bucket_name, Policy=document)
        if _wants_json():
            return jsonify({"success": True, "message": "Bucket policy saved"})
        flash("Bucket policy saved", "success")
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
        else:
            err, status = handle_connection_error(exc)
        if _wants_json():
            return jsonify(err), status
        flash(err["error"], "danger")
    return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="permissions"))


@ui_bp.post("/buckets/<bucket_name>/versioning")
def update_bucket_versioning(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "write")
    except IamError as exc:
        if _wants_json():
            return jsonify({"error": _friendly_error_message(exc)}), 403
        flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))
    state = request.form.get("state", "enable")
    if state not in ("enable", "suspend"):
        if _wants_json():
            return jsonify({"error": "state must be 'enable' or 'suspend'"}), 400
        flash("Invalid versioning state", "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))
    enable = state == "enable"
    try:
        client = get_session_s3_client()
        client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled" if enable else "Suspended"},
        )
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
        else:
            err, status = handle_connection_error(exc)
        if _wants_json():
            return jsonify(err), status
        flash(err["error"], "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))
    message = "Versioning enabled" if enable else "Versioning suspended"
    if _wants_json():
        return jsonify({"success": True, "message": message, "enabled": enable})
    flash(message, "success")
    return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))


@ui_bp.post("/buckets/<bucket_name>/quota")
def update_bucket_quota(bucket_name: str):
    """Update bucket quota configuration (admin only)."""
    principal = _current_principal()

    is_admin = False
    try:
        _iam().authorize(principal, None, "iam:list_users")
        is_admin = True
    except IamError:
        pass

    if not is_admin:
        if _wants_json():
            return jsonify({"error": "Only administrators can manage bucket quotas"}), 403
        flash("Only administrators can manage bucket quotas", "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))

    action = request.form.get("action", "set")

    if action == "remove":
        try:
            _storage().set_bucket_quota(bucket_name, max_bytes=None, max_objects=None)
            if _wants_json():
                return jsonify({"success": True, "message": "Bucket quota removed"})
            flash("Bucket quota removed", "info")
        except StorageError as exc:
            if _wants_json():
                return jsonify({"error": _friendly_error_message(exc)}), 400
            flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))

    max_mb_str = request.form.get("max_mb", "").strip()
    max_objects_str = request.form.get("max_objects", "").strip()

    max_bytes = None
    max_objects = None

    if max_mb_str:
        try:
            max_mb = int(max_mb_str)
            if max_mb < 1:
                raise ValueError("Size must be at least 1 MB")
            max_bytes = max_mb * 1024 * 1024
        except ValueError as exc:
            if _wants_json():
                return jsonify({"error": f"Invalid size value: {exc}"}), 400
            flash(f"Invalid size value: {exc}", "danger")
            return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))

    if max_objects_str:
        try:
            max_objects = int(max_objects_str)
            if max_objects < 0:
                raise ValueError("Object count must be non-negative")
        except ValueError as exc:
            if _wants_json():
                return jsonify({"error": f"Invalid object count: {exc}"}), 400
            flash(f"Invalid object count: {exc}", "danger")
            return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))

    try:
        _storage().set_bucket_quota(bucket_name, max_bytes=max_bytes, max_objects=max_objects)
        if max_bytes is None and max_objects is None:
            message = "Bucket quota removed"
        else:
            message = "Bucket quota updated"
        if _wants_json():
            return jsonify({
                "success": True,
                "message": message,
                "max_bytes": max_bytes,
                "max_objects": max_objects,
                "has_quota": max_bytes is not None or max_objects is not None
            })
        flash(message, "success" if max_bytes or max_objects else "info")
    except StorageError as exc:
        if _wants_json():
            return jsonify({"error": _friendly_error_message(exc)}), 400
        flash(_friendly_error_message(exc), "danger")

    return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))


@ui_bp.post("/buckets/<bucket_name>/encryption")
def update_bucket_encryption(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "write")
    except IamError as exc:
        if _wants_json():
            return jsonify({"error": _friendly_error_message(exc)}), 403
        flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))

    action = request.form.get("action", "enable")

    if action == "disable":
        try:
            client = get_session_s3_client()
            client.delete_bucket_encryption(Bucket=bucket_name)
            if _wants_json():
                return jsonify({"success": True, "message": "Default encryption disabled", "enabled": False})
            flash("Default encryption disabled", "info")
        except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
            if isinstance(exc, ClientError):
                err, status = handle_client_error(exc)
            else:
                err, status = handle_connection_error(exc)
            if _wants_json():
                return jsonify(err), status
            flash(err["error"], "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))

    algorithm = request.form.get("algorithm", "AES256")
    kms_key_id = request.form.get("kms_key_id", "").strip() or None

    if algorithm not in ("AES256", "aws:kms"):
        if _wants_json():
            return jsonify({"error": "Invalid encryption algorithm"}), 400
        flash("Invalid encryption algorithm", "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))

    sse_rule: dict[str, Any] = {"SSEAlgorithm": algorithm}
    if algorithm == "aws:kms" and kms_key_id:
        sse_rule["KMSMasterKeyID"] = kms_key_id

    try:
        client = get_session_s3_client()
        client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": sse_rule}]
            },
        )
        if algorithm == "aws:kms":
            message = "Default KMS encryption enabled"
        else:
            message = "Default AES-256 encryption enabled"
        if _wants_json():
            return jsonify({"success": True, "message": message, "enabled": True, "algorithm": algorithm})
        flash(message, "success")
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
        else:
            err, status = handle_connection_error(exc)
        if _wants_json():
            return jsonify(err), status
        flash(err["error"], "danger")

    return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))


@ui_bp.post("/buckets/<bucket_name>/website")
def update_bucket_website(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "policy")
    except IamError as exc:
        if _wants_json():
            return jsonify({"error": _friendly_error_message(exc)}), 403
        flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))

    if not current_app.config.get("WEBSITE_HOSTING_ENABLED", False):
        if _wants_json():
            return jsonify({"error": "Website hosting is not enabled"}), 400
        flash("Website hosting is not enabled", "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))

    action = request.form.get("action", "enable")

    if action == "disable":
        try:
            _storage().set_bucket_website(bucket_name, None)
            if _wants_json():
                return jsonify({"success": True, "message": "Static website hosting disabled", "enabled": False})
            flash("Static website hosting disabled", "info")
        except StorageError as exc:
            if _wants_json():
                return jsonify({"error": _friendly_error_message(exc)}), 400
            flash(_friendly_error_message(exc), "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))

    index_document = request.form.get("index_document", "").strip()
    error_document = request.form.get("error_document", "").strip()

    if not index_document:
        if _wants_json():
            return jsonify({"error": "Index document is required"}), 400
        flash("Index document is required", "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))

    if "/" in index_document:
        if _wants_json():
            return jsonify({"error": "Index document must not contain '/'"}), 400
        flash("Index document must not contain '/'", "danger")
        return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="properties"))

    website_cfg: dict[str, Any] = {"index_document": index_document}
    if error_document:
        website_cfg["error_document"] = error_document

    try:
        _storage().set_bucket_website(bucket_name, website_cfg)
        if _wants_json():
            return jsonify({
                "success": True,
                "message": "Static website hosting enabled",
                "enabled": True,
                "index_document": index_document,
                "error_document": error_document,
            })
        flash("Static website hosting enabled", "success")
    except StorageError as exc:
        if _wants_json():
            return jsonify({"error": _friendly_error_message(exc)}), 400
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
        if _wants_json():
            return jsonify({"error": str(exc)}), 403
        flash(str(exc), "danger")
        return redirect(url_for("ui.iam_dashboard"))
    display_name = request.form.get("display_name", "").strip() or "Unnamed"
    if len(display_name) > 64:
        if _wants_json():
            return jsonify({"error": "Display name must be 64 characters or fewer"}), 400
        flash("Display name must be 64 characters or fewer", "danger")
        return redirect(url_for("ui.iam_dashboard"))
    policies_text = request.form.get("policies", "").strip()
    policies = None
    if policies_text:
        try:
            policies = json.loads(policies_text)
        except json.JSONDecodeError as exc:
            if _wants_json():
                return jsonify({"error": f"Invalid JSON: {exc}"}), 400
            flash(f"Invalid JSON: {exc}", "danger")
            return redirect(url_for("ui.iam_dashboard"))
    try:
        created = _iam().create_user(display_name=display_name, policies=policies)
    except IamError as exc:
        if _wants_json():
            return jsonify({"error": str(exc)}), 400
        flash(str(exc), "danger")
        return redirect(url_for("ui.iam_dashboard"))

    token = _secret_store().remember(
        {
            "access_key": created["access_key"],
            "secret_key": created["secret_key"],
            "operation": "create",
        }
    )
    if _wants_json():
        return jsonify({
            "success": True,
            "message": f"Created user {created['access_key']}",
            "access_key": created["access_key"],
            "secret_key": created["secret_key"],
            "display_name": display_name,
            "policies": policies or []
        })
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
        if _wants_json():
            return jsonify({"error": str(exc)}), 403
        flash(str(exc), "danger")
        return redirect(url_for("ui.iam_dashboard"))

    display_name = request.form.get("display_name", "").strip()
    if display_name:
        if len(display_name) > 64:
            if _wants_json():
                return jsonify({"error": "Display name must be 64 characters or fewer"}), 400
            flash("Display name must be 64 characters or fewer", "danger")
        else:
            try:
                _iam().update_user(access_key, display_name)
                if _wants_json():
                    return jsonify({"success": True, "message": f"Updated user {access_key}", "display_name": display_name})
                flash(f"Updated user {access_key}", "success")
            except IamError as exc:
                if _wants_json():
                    return jsonify({"error": str(exc)}), 400
                flash(str(exc), "danger")

    return redirect(url_for("ui.iam_dashboard"))


@ui_bp.post("/iam/users/<access_key>/delete")
def delete_iam_user(access_key: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:delete_user")
    except IamError as exc:
        if _wants_json():
            return jsonify({"error": str(exc)}), 403
        flash(str(exc), "danger")
        return redirect(url_for("ui.iam_dashboard"))

    if access_key == principal.access_key:
        try:
            _iam().delete_user(access_key)
            session.pop("credentials", None)
            if _wants_json():
                return jsonify({"success": True, "message": "Your account has been deleted", "redirect": url_for("ui.login")})
            flash("Your account has been deleted.", "info")
            return redirect(url_for("ui.login"))
        except IamError as exc:
            if _wants_json():
                return jsonify({"error": str(exc)}), 400
            flash(str(exc), "danger")
            return redirect(url_for("ui.iam_dashboard"))

    try:
        _iam().delete_user(access_key)
        if _wants_json():
            return jsonify({"success": True, "message": f"Deleted user {access_key}"})
        flash(f"Deleted user {access_key}", "success")
    except IamError as exc:
        if _wants_json():
            return jsonify({"error": str(exc)}), 400
        flash(str(exc), "danger")
    return redirect(url_for("ui.iam_dashboard"))


@ui_bp.post("/iam/users/<access_key>/policies")
def update_iam_policies(access_key: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:update_policy")
    except IamError as exc:
        if _wants_json():
            return jsonify({"error": str(exc)}), 403
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
            if _wants_json():
                return jsonify({"error": "Invalid JSON format for policies"}), 400
            flash("Invalid JSON format for policies", "danger")
            return redirect(url_for("ui.iam_dashboard"))

    try:
        _iam().update_user_policies(access_key, policies)
        if _wants_json():
            return jsonify({"success": True, "message": f"Updated policies for {access_key}", "policies": policies})
        flash(f"Updated policies for {access_key}", "success")
    except IamError as exc:
        if _wants_json():
            return jsonify({"error": str(exc)}), 400
        flash(str(exc), "danger")

    return redirect(url_for("ui.iam_dashboard"))


@ui_bp.post("/connections")
def create_connection():
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        if _wants_json():
            return jsonify({"error": "Access denied"}), 403
        flash("Access denied", "danger")
        return redirect(url_for("ui.buckets_overview"))

    name = request.form.get("name", "").strip()
    endpoint = request.form.get("endpoint_url", "").strip()
    access_key = request.form.get("access_key", "").strip()
    secret_key = request.form.get("secret_key", "").strip()
    region = request.form.get("region", "us-east-1").strip()

    if not all([name, endpoint, access_key, secret_key]):
        if _wants_json():
            return jsonify({"error": "All fields are required"}), 400
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
    if _wants_json():
        return jsonify({"success": True, "message": f"Connection '{name}' created", "connection_id": conn.id})
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
        if _wants_json():
            return jsonify({"error": "Access denied"}), 403
        flash("Access denied", "danger")
        return redirect(url_for("ui.buckets_overview"))

    conn = _connections().get(connection_id)
    if not conn:
        if _wants_json():
            return jsonify({"error": "Connection not found"}), 404
        flash("Connection not found", "danger")
        return redirect(url_for("ui.connections_dashboard"))

    name = request.form.get("name", "").strip()
    endpoint = request.form.get("endpoint_url", "").strip()
    access_key = request.form.get("access_key", "").strip()
    secret_key = request.form.get("secret_key", "").strip()
    region = request.form.get("region", "us-east-1").strip()

    if not all([name, endpoint, access_key]):
        if _wants_json():
            return jsonify({"error": "Name, endpoint, and access key are required"}), 400
        flash("Name, endpoint, and access key are required", "danger")
        return redirect(url_for("ui.connections_dashboard"))

    conn.name = name
    conn.endpoint_url = endpoint
    conn.access_key = access_key
    if secret_key:
        conn.secret_key = secret_key
    conn.region = region

    _connections().save()
    if _wants_json():
        return jsonify({
            "success": True,
            "message": f"Connection '{name}' updated",
            "connection": {
                "id": connection_id,
                "name": name,
                "endpoint_url": endpoint,
                "access_key": access_key,
                "region": region
            }
        })
    flash(f"Connection '{name}' updated", "success")
    return redirect(url_for("ui.connections_dashboard"))


@ui_bp.post("/connections/<connection_id>/delete")
def delete_connection(connection_id: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        if _wants_json():
            return jsonify({"error": "Access denied"}), 403
        flash("Access denied", "danger")
        return redirect(url_for("ui.buckets_overview"))

    _connections().delete(connection_id)
    if _wants_json():
        return jsonify({"success": True, "message": "Connection deleted"})
    flash("Connection deleted", "success")
    return redirect(url_for("ui.connections_dashboard"))


@ui_bp.post("/buckets/<bucket_name>/replication")
def update_bucket_replication(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "replication")
    except IamError as exc:
        if _wants_json():
            return jsonify({"error": str(exc)}), 403
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
            if _wants_json():
                return jsonify({"error": "Only administrators can remove replication configuration"}), 403
            flash("Only administrators can remove replication configuration", "danger")
            return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="replication"))
        _replication().delete_rule(bucket_name)
        if _wants_json():
            return jsonify({"success": True, "message": "Replication configuration removed", "action": "delete"})
        flash("Replication configuration removed", "info")
    elif action == "pause":
        rule = _replication().get_rule(bucket_name)
        if rule:
            rule.enabled = False
            _replication().set_rule(rule)
            if _wants_json():
                return jsonify({"success": True, "message": "Replication paused", "action": "pause", "enabled": False})
            flash("Replication paused", "info")
        else:
            if _wants_json():
                return jsonify({"error": "No replication configuration to pause"}), 404
            flash("No replication configuration to pause", "warning")
    elif action == "resume":
        from .replication import REPLICATION_MODE_ALL
        rule = _replication().get_rule(bucket_name)
        if rule:
            rule.enabled = True
            _replication().set_rule(rule)
            if rule.mode == REPLICATION_MODE_ALL:
                _replication().replicate_existing_objects(bucket_name)
                message = "Replication resumed. Syncing pending objects in background."
            else:
                message = "Replication resumed"
            if _wants_json():
                return jsonify({"success": True, "message": message, "action": "resume", "enabled": True})
            flash(message, "success")
        else:
            if _wants_json():
                return jsonify({"error": "No replication configuration to resume"}), 404
            flash("No replication configuration to resume", "warning")
    elif action == "create":
        if not is_admin:
            if _wants_json():
                return jsonify({"error": "Only administrators can configure replication settings"}), 403
            flash("Only administrators can configure replication settings", "danger")
            return redirect(url_for("ui.bucket_detail", bucket_name=bucket_name, tab="replication"))

        from .replication import REPLICATION_MODE_NEW_ONLY, REPLICATION_MODE_ALL
        import time

        target_conn_id = request.form.get("target_connection_id")
        target_bucket = request.form.get("target_bucket", "").strip()
        replication_mode = request.form.get("replication_mode", REPLICATION_MODE_NEW_ONLY)

        if not target_conn_id or not target_bucket:
            if _wants_json():
                return jsonify({"error": "Target connection and bucket are required"}), 400
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
                message = "Replication configured. Existing objects are being replicated in the background."
            else:
                message = "Replication configured. Only new uploads will be replicated."
            if _wants_json():
                return jsonify({"success": True, "message": message, "action": "create", "enabled": True})
            flash(message, "success")
    else:
        if _wants_json():
            return jsonify({"error": "Invalid action"}), 400
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


@ui_bp.get("/buckets/<bucket_name>/replication/failures")
def get_replication_failures(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "replication")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)

    failures = _replication().get_failed_items(bucket_name, limit, offset)
    total = _replication().get_failure_count(bucket_name)

    return jsonify({
        "failures": [f.to_dict() for f in failures],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@ui_bp.post("/buckets/<bucket_name>/replication/failures/<path:object_key>/retry")
def retry_replication_failure(bucket_name: str, object_key: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "replication")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    success = _replication().retry_failed_item(bucket_name, object_key)
    if success:
        return jsonify({"status": "submitted", "object_key": object_key})
    return jsonify({"error": "Failed to submit retry"}), 400


@ui_bp.post("/buckets/<bucket_name>/replication/failures/retry-all")
def retry_all_replication_failures(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "replication")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    result = _replication().retry_all_failed(bucket_name)
    return jsonify({
        "status": "submitted",
        "submitted": result["submitted"],
        "skipped": result["skipped"],
    })


@ui_bp.delete("/buckets/<bucket_name>/replication/failures/<path:object_key>")
def dismiss_replication_failure(bucket_name: str, object_key: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "replication")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    success = _replication().dismiss_failure(bucket_name, object_key)
    if success:
        return jsonify({"status": "dismissed", "object_key": object_key})
    return jsonify({"error": "Failure not found"}), 404


@ui_bp.delete("/buckets/<bucket_name>/replication/failures")
def clear_replication_failures(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "replication")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    _replication().clear_failures(bucket_name)
    return jsonify({"status": "cleared"})


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


@ui_bp.get("/website-domains")
def website_domains_dashboard():
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        flash("Access denied", "danger")
        return redirect(url_for("ui.buckets_overview"))

    if not current_app.config.get("WEBSITE_HOSTING_ENABLED", False):
        flash("Website hosting is not enabled", "warning")
        return redirect(url_for("ui.buckets_overview"))

    store = current_app.extensions.get("website_domains")
    mappings = store.list_all() if store else []
    storage = _storage()
    buckets = [b.name for b in storage.list_buckets()]
    return render_template(
        "website_domains.html",
        mappings=mappings,
        buckets=buckets,
        principal=principal,
        can_manage_iam=True,
    )


@ui_bp.post("/website-domains/create")
def create_website_domain():
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        if _wants_json():
            return jsonify({"error": "Access denied"}), 403
        flash("Access denied", "danger")
        return redirect(url_for("ui.website_domains_dashboard"))

    if not current_app.config.get("WEBSITE_HOSTING_ENABLED", False):
        if _wants_json():
            return jsonify({"error": "Website hosting is not enabled"}), 400
        flash("Website hosting is not enabled", "warning")
        return redirect(url_for("ui.buckets_overview"))

    domain = (request.form.get("domain") or "").strip().lower()
    bucket = (request.form.get("bucket") or "").strip()

    if not domain:
        if _wants_json():
            return jsonify({"error": "Domain is required"}), 400
        flash("Domain is required", "danger")
        return redirect(url_for("ui.website_domains_dashboard"))

    if not bucket:
        if _wants_json():
            return jsonify({"error": "Bucket is required"}), 400
        flash("Bucket is required", "danger")
        return redirect(url_for("ui.website_domains_dashboard"))

    storage = _storage()
    if not storage.bucket_exists(bucket):
        if _wants_json():
            return jsonify({"error": f"Bucket '{bucket}' does not exist"}), 404
        flash(f"Bucket '{bucket}' does not exist", "danger")
        return redirect(url_for("ui.website_domains_dashboard"))

    store = current_app.extensions.get("website_domains")
    if store.get_bucket(domain):
        if _wants_json():
            return jsonify({"error": f"Domain '{domain}' is already mapped"}), 409
        flash(f"Domain '{domain}' is already mapped", "danger")
        return redirect(url_for("ui.website_domains_dashboard"))

    store.set_mapping(domain, bucket)
    if _wants_json():
        return jsonify({"success": True, "domain": domain, "bucket": bucket}), 201
    flash(f"Domain '{domain}' mapped to bucket '{bucket}'", "success")
    return redirect(url_for("ui.website_domains_dashboard"))


@ui_bp.post("/website-domains/<domain>/update")
def update_website_domain(domain: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        if _wants_json():
            return jsonify({"error": "Access denied"}), 403
        flash("Access denied", "danger")
        return redirect(url_for("ui.website_domains_dashboard"))

    bucket = (request.form.get("bucket") or "").strip()
    if not bucket:
        if _wants_json():
            return jsonify({"error": "Bucket is required"}), 400
        flash("Bucket is required", "danger")
        return redirect(url_for("ui.website_domains_dashboard"))

    storage = _storage()
    if not storage.bucket_exists(bucket):
        if _wants_json():
            return jsonify({"error": f"Bucket '{bucket}' does not exist"}), 404
        flash(f"Bucket '{bucket}' does not exist", "danger")
        return redirect(url_for("ui.website_domains_dashboard"))

    store = current_app.extensions.get("website_domains")
    store.set_mapping(domain, bucket)
    if _wants_json():
        return jsonify({"success": True, "domain": domain.lower(), "bucket": bucket})
    flash(f"Domain '{domain}' updated to bucket '{bucket}'", "success")
    return redirect(url_for("ui.website_domains_dashboard"))


@ui_bp.post("/website-domains/<domain>/delete")
def delete_website_domain(domain: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        if _wants_json():
            return jsonify({"error": "Access denied"}), 403
        flash("Access denied", "danger")
        return redirect(url_for("ui.website_domains_dashboard"))

    store = current_app.extensions.get("website_domains")
    if not store.delete_mapping(domain):
        if _wants_json():
            return jsonify({"error": f"No mapping for domain '{domain}'"}), 404
        flash(f"No mapping for domain '{domain}'", "danger")
        return redirect(url_for("ui.website_domains_dashboard"))

    if _wants_json():
        return jsonify({"success": True})
    flash(f"Domain '{domain}' mapping deleted", "success")
    return redirect(url_for("ui.website_domains_dashboard"))


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
        cpu_percent=round(cpu_percent, 2),
        memory={
            "total": _format_bytes(memory.total),
            "available": _format_bytes(memory.available),
            "used": _format_bytes(memory.used),
            "percent": round(memory.percent, 2),
        },
        disk={
            "total": _format_bytes(disk.total),
            "free": _format_bytes(disk.free),
            "used": _format_bytes(disk.used),
            "percent": round(disk.percent, 2),
        },
        app={
            "buckets": total_buckets,
            "objects": total_objects,
            "versions": total_versions,
            "storage_used": _format_bytes(total_bytes_used),
            "storage_raw": total_bytes_used,
            "version": APP_VERSION,
            "uptime_days": uptime_days,
        },
        metrics_history_enabled=current_app.config.get("METRICS_HISTORY_ENABLED", False),
        operation_metrics_enabled=current_app.config.get("OPERATION_METRICS_ENABLED", False),
    )


@ui_bp.route("/metrics/api")
def metrics_api():
    principal = _current_principal()

    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

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

    return jsonify({
        "cpu_percent": round(cpu_percent, 2),
        "memory": {
            "total": _format_bytes(memory.total),
            "available": _format_bytes(memory.available),
            "used": _format_bytes(memory.used),
            "percent": round(memory.percent, 2),
        },
        "disk": {
            "total": _format_bytes(disk.total),
            "free": _format_bytes(disk.free),
            "used": _format_bytes(disk.used),
            "percent": round(disk.percent, 2),
        },
        "app": {
            "buckets": total_buckets,
            "objects": total_objects,
            "versions": total_versions,
            "storage_used": _format_bytes(total_bytes_used),
            "storage_raw": total_bytes_used,
            "uptime_days": uptime_days,
        }
    })


@ui_bp.route("/metrics/history")
def metrics_history():
    principal = _current_principal()

    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    system_metrics = current_app.extensions.get("system_metrics")
    if not system_metrics:
        return jsonify({"enabled": False, "history": []})

    hours = request.args.get("hours", type=int)
    if hours is None:
        hours = current_app.config.get("METRICS_HISTORY_RETENTION_HOURS", 24)

    history = system_metrics.get_history(hours=hours)

    return jsonify({
        "enabled": True,
        "retention_hours": current_app.config.get("METRICS_HISTORY_RETENTION_HOURS", 24),
        "interval_minutes": current_app.config.get("METRICS_HISTORY_INTERVAL_MINUTES", 5),
        "history": history,
    })


@ui_bp.route("/metrics/settings", methods=["GET", "PUT"])
def metrics_settings():
    principal = _current_principal()

    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    if request.method == "GET":
        return jsonify({
            "enabled": current_app.config.get("METRICS_HISTORY_ENABLED", False),
            "retention_hours": current_app.config.get("METRICS_HISTORY_RETENTION_HOURS", 24),
            "interval_minutes": current_app.config.get("METRICS_HISTORY_INTERVAL_MINUTES", 5),
        })

    data = request.get_json() or {}

    if "enabled" in data:
        current_app.config["METRICS_HISTORY_ENABLED"] = bool(data["enabled"])
    if "retention_hours" in data:
        current_app.config["METRICS_HISTORY_RETENTION_HOURS"] = max(1, int(data["retention_hours"]))
    if "interval_minutes" in data:
        current_app.config["METRICS_HISTORY_INTERVAL_MINUTES"] = max(1, int(data["interval_minutes"]))

    return jsonify({
        "enabled": current_app.config.get("METRICS_HISTORY_ENABLED", False),
        "retention_hours": current_app.config.get("METRICS_HISTORY_RETENTION_HOURS", 24),
        "interval_minutes": current_app.config.get("METRICS_HISTORY_INTERVAL_MINUTES", 5),
    })


@ui_bp.get("/metrics/operations")
def metrics_operations():
    principal = _current_principal()

    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    collector = _operation_metrics()
    if not collector:
        return jsonify({
            "enabled": False,
            "stats": None,
        })

    return jsonify({
        "enabled": True,
        "stats": collector.get_current_stats(),
    })


@ui_bp.get("/metrics/operations/history")
def metrics_operations_history():
    principal = _current_principal()

    try:
        _iam().authorize(principal, None, "iam:list_users")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    collector = _operation_metrics()
    if not collector:
        return jsonify({
            "enabled": False,
            "history": [],
        })

    hours = request.args.get("hours", type=int)
    return jsonify({
        "enabled": True,
        "history": collector.get_history(hours),
        "interval_minutes": current_app.config.get("OPERATION_METRICS_INTERVAL_MINUTES", 5),
    })


@ui_bp.route("/buckets/<bucket_name>/lifecycle", methods=["GET", "POST", "DELETE"])
def bucket_lifecycle(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "lifecycle")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    try:
        client = get_session_s3_client()
    except (PermissionError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 403

    if request.method == "GET":
        try:
            resp = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            rules = resp.get("Rules", [])
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NoSuchLifecycleConfiguration":
                rules = []
            else:
                err, status = handle_client_error(exc)
                return jsonify(err), status
        except (EndpointConnectionError, ConnectionClosedError) as exc:
            return jsonify(*handle_connection_error(exc))
        return jsonify({"rules": rules})

    if request.method == "DELETE":
        try:
            client.delete_bucket_lifecycle(Bucket=bucket_name)
        except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
            if isinstance(exc, ClientError):
                err, status = handle_client_error(exc)
                return jsonify(err), status
            return jsonify(*handle_connection_error(exc))
        return jsonify({"status": "ok", "message": "Lifecycle configuration deleted"})

    payload = request.get_json(silent=True) or {}
    rules = payload.get("rules", [])
    if not isinstance(rules, list):
        return jsonify({"error": "rules must be a list"}), 400

    validated_rules = []
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            return jsonify({"error": f"Rule {i} must be an object"}), 400
        validated = {
            "ID": str(rule.get("ID", f"rule-{i+1}")),
            "Status": "Enabled" if rule.get("Status", "Enabled") == "Enabled" else "Disabled",
        }
        filt = {}
        if rule.get("Prefix"):
            filt["Prefix"] = str(rule["Prefix"])
        if filt:
            validated["Filter"] = filt
        if rule.get("Expiration"):
            exp = rule["Expiration"]
            if isinstance(exp, dict) and exp.get("Days"):
                validated["Expiration"] = {"Days": int(exp["Days"])}
        if rule.get("NoncurrentVersionExpiration"):
            nve = rule["NoncurrentVersionExpiration"]
            if isinstance(nve, dict) and nve.get("NoncurrentDays"):
                validated["NoncurrentVersionExpiration"] = {"NoncurrentDays": int(nve["NoncurrentDays"])}
        if rule.get("AbortIncompleteMultipartUpload"):
            aimu = rule["AbortIncompleteMultipartUpload"]
            if isinstance(aimu, dict) and aimu.get("DaysAfterInitiation"):
                validated["AbortIncompleteMultipartUpload"] = {"DaysAfterInitiation": int(aimu["DaysAfterInitiation"])}
        validated_rules.append(validated)

    try:
        if validated_rules:
            client.put_bucket_lifecycle_configuration(
                Bucket=bucket_name,
                LifecycleConfiguration={"Rules": validated_rules},
            )
        else:
            client.delete_bucket_lifecycle(Bucket=bucket_name)
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))
    return jsonify({"status": "ok", "message": "Lifecycle configuration saved", "rules": validated_rules})


@ui_bp.get("/buckets/<bucket_name>/lifecycle/history")
def get_lifecycle_history(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "lifecycle")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)

    lifecycle_manager = current_app.extensions.get("lifecycle")
    if not lifecycle_manager:
        return jsonify({
            "executions": [],
            "total": 0,
            "limit": limit,
            "offset": offset,
            "enabled": False,
        })

    records = lifecycle_manager.get_execution_history(bucket_name, limit, offset)
    return jsonify({
        "executions": [r.to_dict() for r in records],
        "total": len(lifecycle_manager.get_execution_history(bucket_name, 1000, 0)),
        "limit": limit,
        "offset": offset,
        "enabled": True,
    })


@ui_bp.route("/buckets/<bucket_name>/cors", methods=["GET", "POST", "DELETE"])
def bucket_cors(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "cors")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    try:
        client = get_session_s3_client()
    except (PermissionError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 403

    if request.method == "GET":
        try:
            resp = client.get_bucket_cors(Bucket=bucket_name)
            rules = resp.get("CORSRules", [])
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NoSuchCORSConfiguration":
                rules = []
            else:
                err, status = handle_client_error(exc)
                return jsonify(err), status
        except (EndpointConnectionError, ConnectionClosedError) as exc:
            return jsonify(*handle_connection_error(exc))
        return jsonify({"rules": rules})

    if request.method == "DELETE":
        try:
            client.delete_bucket_cors(Bucket=bucket_name)
        except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
            if isinstance(exc, ClientError):
                err, status = handle_client_error(exc)
                return jsonify(err), status
            return jsonify(*handle_connection_error(exc))
        return jsonify({"status": "ok", "message": "CORS configuration deleted"})

    payload = request.get_json(silent=True) or {}
    rules = payload.get("rules", [])
    if not isinstance(rules, list):
        return jsonify({"error": "rules must be a list"}), 400

    validated_rules = []
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            return jsonify({"error": f"Rule {i} must be an object"}), 400
        origins = rule.get("AllowedOrigins", [])
        methods = rule.get("AllowedMethods", [])
        if not origins or not methods:
            return jsonify({"error": f"Rule {i} must have AllowedOrigins and AllowedMethods"}), 400
        validated = {
            "AllowedOrigins": [str(o) for o in origins if o],
            "AllowedMethods": [str(m).upper() for m in methods if m],
        }
        if rule.get("AllowedHeaders"):
            validated["AllowedHeaders"] = [str(h) for h in rule["AllowedHeaders"] if h]
        if rule.get("ExposeHeaders"):
            validated["ExposeHeaders"] = [str(h) for h in rule["ExposeHeaders"] if h]
        if rule.get("MaxAgeSeconds") is not None:
            try:
                validated["MaxAgeSeconds"] = int(rule["MaxAgeSeconds"])
            except (ValueError, TypeError):
                pass
        validated_rules.append(validated)

    try:
        if validated_rules:
            client.put_bucket_cors(
                Bucket=bucket_name,
                CORSConfiguration={"CORSRules": validated_rules},
            )
        else:
            client.delete_bucket_cors(Bucket=bucket_name)
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))
    return jsonify({"status": "ok", "message": "CORS configuration saved", "rules": validated_rules})


@ui_bp.route("/buckets/<bucket_name>/acl", methods=["GET", "POST"])
def bucket_acl(bucket_name: str):
    principal = _current_principal()
    action = "read" if request.method == "GET" else "write"
    try:
        _authorize_ui(principal, bucket_name, action)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    try:
        client = get_session_s3_client()
    except (PermissionError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 403

    owner_id = principal.access_key if principal else "anonymous"

    if request.method == "GET":
        try:
            resp = client.get_bucket_acl(Bucket=bucket_name)
            owner = resp.get("Owner", {}).get("ID", owner_id)
            grants = []
            for grant in resp.get("Grants", []):
                grantee = grant.get("Grantee", {})
                grantee_display = grantee.get("DisplayName") or grantee.get("ID", "")
                if not grantee_display:
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri:
                        grantee_display = "Everyone (public)"
                    elif "AuthenticatedUsers" in uri:
                        grantee_display = "Authenticated users"
                    else:
                        grantee_display = uri or "unknown"
                grants.append({
                    "grantee": grantee_display,
                    "permission": grant.get("Permission", ""),
                })
            return jsonify({
                "owner": owner,
                "grants": grants,
                "canned_acls": list(CANNED_ACLS.keys()),
            })
        except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
            if isinstance(exc, ClientError):
                err, status = handle_client_error(exc)
                return jsonify(err), status
            return jsonify(*handle_connection_error(exc))

    payload = request.get_json(silent=True) or {}
    canned_acl = payload.get("canned_acl")
    if canned_acl:
        if canned_acl not in CANNED_ACLS:
            return jsonify({"error": f"Invalid canned ACL: {canned_acl}"}), 400
        try:
            client.put_bucket_acl(Bucket=bucket_name, ACL=canned_acl)
            return jsonify({"status": "ok", "message": f"ACL set to {canned_acl}"})
        except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
            if isinstance(exc, ClientError):
                err, status = handle_client_error(exc)
                return jsonify(err), status
            return jsonify(*handle_connection_error(exc))

    return jsonify({"error": "canned_acl is required"}), 400


@ui_bp.route("/buckets/<bucket_name>/objects/<path:object_key>/tags", methods=["GET", "POST"])
def object_tags(bucket_name: str, object_key: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "read", object_key=object_key)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    try:
        client = get_session_s3_client()
    except (PermissionError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 403

    if request.method == "GET":
        try:
            resp = client.get_object_tagging(Bucket=bucket_name, Key=object_key)
            tags = resp.get("TagSet", [])
            return jsonify({"tags": tags})
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NoSuchKey":
                return jsonify({"error": "Object not found"}), 404
            err, status = handle_client_error(exc)
            return jsonify(err), status
        except (EndpointConnectionError, ConnectionClosedError) as exc:
            return jsonify(*handle_connection_error(exc))

    try:
        _authorize_ui(principal, bucket_name, "write", object_key=object_key)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    payload = request.get_json(silent=True) or {}
    tags = payload.get("tags", [])
    if not isinstance(tags, list):
        return jsonify({"error": "tags must be a list"}), 400
    tag_limit = current_app.config.get("OBJECT_TAG_LIMIT", 50)
    if len(tags) > tag_limit:
        return jsonify({"error": f"Maximum {tag_limit} tags allowed"}), 400

    validated_tags = []
    for i, tag in enumerate(tags):
        if not isinstance(tag, dict) or not tag.get("Key"):
            return jsonify({"error": f"Tag at index {i} must have a Key field"}), 400
        validated_tags.append({
            "Key": str(tag["Key"]),
            "Value": str(tag.get("Value", ""))
        })

    try:
        if validated_tags:
            client.put_object_tagging(
                Bucket=bucket_name,
                Key=object_key,
                Tagging={"TagSet": validated_tags},
            )
        else:
            client.delete_object_tagging(Bucket=bucket_name, Key=object_key)
        return jsonify({"status": "ok", "message": "Tags saved", "tags": validated_tags})
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))


@ui_bp.post("/buckets/<bucket_name>/folders")
def create_folder(bucket_name: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "write")
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    payload = request.get_json(silent=True) or {}
    folder_name = str(payload.get("folder_name", "")).strip()
    prefix = str(payload.get("prefix", "")).strip()

    if not folder_name:
        return jsonify({"error": "folder_name is required"}), 400

    folder_name = folder_name.rstrip("/")
    if "/" in folder_name:
        return jsonify({"error": "Folder name cannot contain /"}), 400
    if "\x00" in folder_name or "\x00" in prefix:
        return jsonify({"error": "Null bytes not allowed"}), 400
    if ".." in prefix.split("/"):
        return jsonify({"error": "Invalid prefix"}), 400

    folder_key = f"{prefix}{folder_name}/" if prefix else f"{folder_name}/"

    max_key_len = current_app.config.get("OBJECT_KEY_MAX_LENGTH_BYTES", 1024)
    if len(folder_key.encode("utf-8")) > max_key_len:
        return jsonify({"error": f"Key exceeds maximum length of {max_key_len} bytes"}), 400

    try:
        client = get_session_s3_client()
        client.put_object(Bucket=bucket_name, Key=folder_key, Body=b"")
        return jsonify({"status": "ok", "message": f"Folder '{folder_name}' created", "key": folder_key})
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 401
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))


@ui_bp.post("/buckets/<bucket_name>/objects/<path:object_key>/copy")
def copy_object(bucket_name: str, object_key: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "read", object_key=object_key)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    payload = request.get_json(silent=True) or {}
    dest_bucket = str(payload.get("dest_bucket", bucket_name)).strip()
    dest_key = str(payload.get("dest_key", "")).strip()

    if not dest_key:
        return jsonify({"error": "dest_key is required"}), 400
    if "\x00" in dest_key:
        return jsonify({"error": "Destination key cannot contain null bytes"}), 400
    max_key_len = current_app.config.get("OBJECT_KEY_MAX_LENGTH_BYTES", 1024)
    if len(dest_key.encode("utf-8")) > max_key_len:
        return jsonify({"error": f"Destination key exceeds maximum length of {max_key_len} bytes"}), 400

    try:
        _authorize_ui(principal, dest_bucket, "write", object_key=dest_key)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    try:
        client = get_session_s3_client()
        client.copy_object(
            Bucket=dest_bucket,
            Key=dest_key,
            CopySource={"Bucket": bucket_name, "Key": object_key},
        )
        return jsonify({
            "status": "ok",
            "message": f"Copied to {dest_bucket}/{dest_key}",
            "dest_bucket": dest_bucket,
            "dest_key": dest_key,
        })
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 401
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))


@ui_bp.post("/buckets/<bucket_name>/objects/<path:object_key>/move")
def move_object(bucket_name: str, object_key: str):
    principal = _current_principal()
    try:
        _authorize_ui(principal, bucket_name, "read", object_key=object_key)
        _authorize_ui(principal, bucket_name, "delete", object_key=object_key)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    payload = request.get_json(silent=True) or {}
    dest_bucket = str(payload.get("dest_bucket", bucket_name)).strip()
    dest_key = str(payload.get("dest_key", "")).strip()

    if not dest_key:
        return jsonify({"error": "dest_key is required"}), 400
    if "\x00" in dest_key:
        return jsonify({"error": "Destination key cannot contain null bytes"}), 400
    max_key_len = current_app.config.get("OBJECT_KEY_MAX_LENGTH_BYTES", 1024)
    if len(dest_key.encode("utf-8")) > max_key_len:
        return jsonify({"error": f"Destination key exceeds maximum length of {max_key_len} bytes"}), 400

    if dest_bucket == bucket_name and dest_key == object_key:
        return jsonify({"error": "Cannot move object to the same location"}), 400

    try:
        _authorize_ui(principal, dest_bucket, "write", object_key=dest_key)
    except IamError as exc:
        return jsonify({"error": str(exc)}), 403

    try:
        client = get_session_s3_client()
        client.copy_object(
            Bucket=dest_bucket,
            Key=dest_key,
            CopySource={"Bucket": bucket_name, "Key": object_key},
        )
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 401
    except (ClientError, EndpointConnectionError, ConnectionClosedError) as exc:
        if isinstance(exc, ClientError):
            err, status = handle_client_error(exc)
            return jsonify(err), status
        return jsonify(*handle_connection_error(exc))

    try:
        client.delete_object(Bucket=bucket_name, Key=object_key)
    except (ClientError, EndpointConnectionError, ConnectionClosedError):
        return jsonify({
            "status": "partial",
            "message": f"Copied to {dest_bucket}/{dest_key} but failed to delete source",
            "dest_bucket": dest_bucket,
            "dest_key": dest_key,
        }), 200

    return jsonify({
        "status": "ok",
        "message": f"Moved to {dest_bucket}/{dest_key}",
        "dest_bucket": dest_bucket,
        "dest_key": dest_key,
    })


@ui_bp.get("/buckets/<bucket_name>/list-for-copy")
def list_buckets_for_copy(bucket_name: str):
    principal = _current_principal()
    try:
        client = get_session_s3_client()
        resp = client.list_buckets()
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 401
    except ClientError as exc:
        return jsonify(*handle_client_error(exc))
    except (EndpointConnectionError, ConnectionClosedError) as exc:
        return jsonify(*handle_connection_error(exc))
    allowed = []
    for b in resp.get("Buckets", []):
        try:
            _authorize_ui(principal, b["Name"], "write")
            allowed.append(b["Name"])
        except IamError:
            pass
    return jsonify({"buckets": allowed})


@ui_bp.get("/sites")
def sites_dashboard():
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:*")
    except IamError:
        flash("Access denied: Site management requires admin permissions", "danger")
        return redirect(url_for("ui.buckets_overview"))

    registry = _site_registry()
    local_site = registry.get_local_site()
    peers = registry.list_peers()
    connections = _connections().list()

    replication = _replication()
    all_rules = replication.list_rules()

    peers_with_stats = []
    for peer in peers:
        buckets_syncing = 0
        has_bidirectional = False
        if peer.connection_id:
            for rule in all_rules:
                if rule.target_connection_id == peer.connection_id:
                    buckets_syncing += 1
                    if rule.mode == "bidirectional":
                        has_bidirectional = True
        peers_with_stats.append({
            "peer": peer,
            "buckets_syncing": buckets_syncing,
            "has_connection": bool(peer.connection_id),
            "has_bidirectional": has_bidirectional,
        })

    return render_template(
        "sites.html",
        principal=principal,
        local_site=local_site,
        peers=peers,
        peers_with_stats=peers_with_stats,
        connections=connections,
        config_site_id=current_app.config.get("SITE_ID"),
        config_site_endpoint=current_app.config.get("SITE_ENDPOINT"),
        config_site_region=current_app.config.get("SITE_REGION", "us-east-1"),
    )


@ui_bp.post("/sites/local")
def update_local_site():
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:*")
    except IamError:
        flash("Access denied", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    site_id = request.form.get("site_id", "").strip()
    endpoint = request.form.get("endpoint", "").strip()
    region = request.form.get("region", "us-east-1").strip()
    priority = request.form.get("priority", "100")
    display_name = request.form.get("display_name", "").strip()

    if not site_id:
        flash("Site ID is required", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    try:
        priority_int = int(priority)
    except ValueError:
        priority_int = 100

    registry = _site_registry()
    existing = registry.get_local_site()

    site = SiteInfo(
        site_id=site_id,
        endpoint=endpoint,
        region=region,
        priority=priority_int,
        display_name=display_name or site_id,
        created_at=existing.created_at if existing else None,
    )
    registry.set_local_site(site)

    flash("Local site configuration updated", "success")
    return redirect(url_for("ui.sites_dashboard"))


@ui_bp.post("/sites/peers")
def add_peer_site():
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:*")
    except IamError:
        flash("Access denied", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    site_id = request.form.get("site_id", "").strip()
    endpoint = request.form.get("endpoint", "").strip()
    region = request.form.get("region", "us-east-1").strip()
    priority = request.form.get("priority", "100")
    display_name = request.form.get("display_name", "").strip()
    connection_id = request.form.get("connection_id", "").strip() or None

    if not site_id:
        flash("Site ID is required", "danger")
        return redirect(url_for("ui.sites_dashboard"))
    if not endpoint:
        flash("Endpoint is required", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    try:
        priority_int = int(priority)
    except ValueError:
        priority_int = 100

    registry = _site_registry()

    if registry.get_peer(site_id):
        flash(f"Peer site '{site_id}' already exists", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    if connection_id and not _connections().get(connection_id):
        flash(f"Connection '{connection_id}' not found", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    peer = PeerSite(
        site_id=site_id,
        endpoint=endpoint,
        region=region,
        priority=priority_int,
        display_name=display_name or site_id,
        connection_id=connection_id,
    )
    registry.add_peer(peer)

    flash(f"Peer site '{site_id}' added", "success")

    if connection_id:
        return redirect(url_for("ui.replication_wizard", site_id=site_id))
    return redirect(url_for("ui.sites_dashboard"))


@ui_bp.post("/sites/peers/<site_id>/update")
def update_peer_site(site_id: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:*")
    except IamError:
        flash("Access denied", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    registry = _site_registry()
    existing = registry.get_peer(site_id)

    if not existing:
        flash(f"Peer site '{site_id}' not found", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    endpoint = request.form.get("endpoint", existing.endpoint).strip()
    region = request.form.get("region", existing.region).strip()
    priority = request.form.get("priority", str(existing.priority))
    display_name = request.form.get("display_name", existing.display_name).strip()
    connection_id = request.form.get("connection_id", "").strip() or existing.connection_id

    try:
        priority_int = int(priority)
    except ValueError:
        priority_int = existing.priority

    if connection_id and not _connections().get(connection_id):
        flash(f"Connection '{connection_id}' not found", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    peer = PeerSite(
        site_id=site_id,
        endpoint=endpoint,
        region=region,
        priority=priority_int,
        display_name=display_name or site_id,
        connection_id=connection_id,
        created_at=existing.created_at,
        is_healthy=existing.is_healthy,
        last_health_check=existing.last_health_check,
    )
    registry.update_peer(peer)

    flash(f"Peer site '{site_id}' updated", "success")
    return redirect(url_for("ui.sites_dashboard"))


@ui_bp.post("/sites/peers/<site_id>/delete")
def delete_peer_site(site_id: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:*")
    except IamError:
        flash("Access denied", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    registry = _site_registry()
    if registry.delete_peer(site_id):
        flash(f"Peer site '{site_id}' deleted", "success")
    else:
        flash(f"Peer site '{site_id}' not found", "danger")

    return redirect(url_for("ui.sites_dashboard"))


@ui_bp.get("/sites/peers/<site_id>/health")
def check_peer_site_health(site_id: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:*")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    registry = _site_registry()
    peer = registry.get_peer(site_id)

    if not peer:
        return jsonify({"error": f"Peer site '{site_id}' not found"}), 404

    is_healthy = False
    error_message = None

    if peer.connection_id:
        connection = _connections().get(peer.connection_id)
        if connection:
            is_healthy = _replication().check_endpoint_health(connection)
        else:
            error_message = f"Connection '{peer.connection_id}' not found"
    else:
        error_message = "No connection configured for this peer"

    registry.update_health(site_id, is_healthy)

    result = {
        "site_id": site_id,
        "is_healthy": is_healthy,
    }
    if error_message:
        result["error"] = error_message

    return jsonify(result)


@ui_bp.get("/sites/peers/<site_id>/bidirectional-status")
def check_peer_bidirectional_status(site_id: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:*")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    registry = _site_registry()
    peer = registry.get_peer(site_id)

    if not peer:
        return jsonify({"error": f"Peer site '{site_id}' not found"}), 404

    local_site = registry.get_local_site()
    replication = _replication()
    local_rules = replication.list_rules()

    local_bidir_rules = []
    for rule in local_rules:
        if rule.target_connection_id == peer.connection_id and rule.mode == "bidirectional":
            local_bidir_rules.append({
                "bucket_name": rule.bucket_name,
                "target_bucket": rule.target_bucket,
                "enabled": rule.enabled,
            })

    result = {
        "site_id": site_id,
        "local_site_id": local_site.site_id if local_site else None,
        "local_endpoint": local_site.endpoint if local_site else None,
        "local_bidirectional_rules": local_bidir_rules,
        "local_site_sync_enabled": current_app.config.get("SITE_SYNC_ENABLED", False),
        "remote_status": None,
        "issues": [],
        "is_fully_configured": False,
    }

    if not local_site or not local_site.site_id:
        result["issues"].append({
            "code": "NO_LOCAL_SITE_ID",
            "message": "Local site identity not configured",
            "severity": "error",
        })

    if not local_site or not local_site.endpoint:
        result["issues"].append({
            "code": "NO_LOCAL_ENDPOINT",
            "message": "Local site endpoint not configured (remote site cannot reach back)",
            "severity": "error",
        })

    if not peer.connection_id:
        result["issues"].append({
            "code": "NO_CONNECTION",
            "message": "No connection configured for this peer",
            "severity": "error",
        })
        return jsonify(result)

    connection = _connections().get(peer.connection_id)
    if not connection:
        result["issues"].append({
            "code": "CONNECTION_NOT_FOUND",
            "message": f"Connection '{peer.connection_id}' not found",
            "severity": "error",
        })
        return jsonify(result)

    if not local_bidir_rules:
        result["issues"].append({
            "code": "NO_LOCAL_BIDIRECTIONAL_RULES",
            "message": "No bidirectional replication rules configured on this site",
            "severity": "warning",
        })

    if not result["local_site_sync_enabled"]:
        result["issues"].append({
            "code": "SITE_SYNC_DISABLED",
            "message": "Site sync worker is disabled (SITE_SYNC_ENABLED=false). Pull operations will not work.",
            "severity": "warning",
        })

    if not replication.check_endpoint_health(connection):
        result["issues"].append({
            "code": "REMOTE_UNREACHABLE",
            "message": "Remote endpoint is not reachable",
            "severity": "error",
        })
        return jsonify(result)

    try:
        parsed = urlparse(peer.endpoint)
        hostname = parsed.hostname or ""
        import ipaddress
        cloud_metadata_hosts = {"metadata.google.internal", "169.254.169.254"}
        if hostname.lower() in cloud_metadata_hosts:
            result["issues"].append({
                "code": "ENDPOINT_NOT_ALLOWED",
                "message": "Peer endpoint points to cloud metadata service (SSRF protection)",
                "severity": "error",
            })
            return jsonify(result)
        allow_internal = current_app.config.get("ALLOW_INTERNAL_ENDPOINTS", False)
        if not allow_internal:
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                    result["issues"].append({
                        "code": "ENDPOINT_NOT_ALLOWED",
                        "message": "Peer endpoint points to internal or private address (set ALLOW_INTERNAL_ENDPOINTS=true for self-hosted deployments)",
                        "severity": "error",
                    })
                    return jsonify(result)
            except ValueError:
                blocked_patterns = ["localhost", "127.", "10.", "192.168.", "172.16."]
                if any(hostname.startswith(p) or hostname == p.rstrip(".") for p in blocked_patterns):
                    result["issues"].append({
                        "code": "ENDPOINT_NOT_ALLOWED",
                        "message": "Peer endpoint points to internal or private address (set ALLOW_INTERNAL_ENDPOINTS=true for self-hosted deployments)",
                        "severity": "error",
                    })
                    return jsonify(result)
    except Exception:
        pass

    try:
        admin_url = peer.endpoint.rstrip("/") + "/admin/sites"
        resp = requests.get(
            admin_url,
            timeout=10,
            headers={
                "Accept": "application/json",
                "X-Access-Key": connection.access_key,
                "X-Secret-Key": connection.secret_key,
            },
        )

        if resp.status_code == 200:
            try:
                remote_data = resp.json()
                if not isinstance(remote_data, dict):
                    raise ValueError("Expected JSON object")
                remote_local = remote_data.get("local")
                if remote_local is not None and not isinstance(remote_local, dict):
                    raise ValueError("Expected 'local' to be an object")
                remote_peers = remote_data.get("peers", [])
                if not isinstance(remote_peers, list):
                    raise ValueError("Expected 'peers' to be a list")
            except (ValueError, json.JSONDecodeError) as e:
                result["remote_status"] = {"reachable": True, "invalid_response": True}
                result["issues"].append({
                    "code": "REMOTE_INVALID_RESPONSE",
                    "message": "Remote admin API returned invalid JSON",
                    "severity": "warning",
                })
                return jsonify(result)

            result["remote_status"] = {
                "reachable": True,
                "local_site": remote_local,
                "site_sync_enabled": None,
                "has_peer_for_us": False,
                "peer_connection_configured": False,
                "has_bidirectional_rules_for_us": False,
            }

            for rp in remote_peers:
                if not isinstance(rp, dict):
                    continue
                if local_site and (
                    rp.get("site_id") == local_site.site_id or
                    rp.get("endpoint") == local_site.endpoint
                ):
                    result["remote_status"]["has_peer_for_us"] = True
                    result["remote_status"]["peer_connection_configured"] = bool(rp.get("connection_id"))
                    break

            if not result["remote_status"]["has_peer_for_us"]:
                result["issues"].append({
                    "code": "REMOTE_NO_PEER_FOR_US",
                    "message": "Remote site does not have this site registered as a peer",
                    "severity": "error",
                })
            elif not result["remote_status"]["peer_connection_configured"]:
                result["issues"].append({
                    "code": "REMOTE_NO_CONNECTION_FOR_US",
                    "message": "Remote site has us as peer but no connection configured (cannot push back)",
                    "severity": "error",
                })
        elif resp.status_code == 401 or resp.status_code == 403:
            result["remote_status"] = {
                "reachable": True,
                "admin_access_denied": True,
            }
            result["issues"].append({
                "code": "REMOTE_ADMIN_ACCESS_DENIED",
                "message": "Cannot verify remote configuration (admin access denied)",
                "severity": "warning",
            })
        else:
            result["remote_status"] = {
                "reachable": True,
                "admin_api_error": resp.status_code,
            }
            result["issues"].append({
                "code": "REMOTE_ADMIN_API_ERROR",
                "message": f"Remote admin API returned status {resp.status_code}",
                "severity": "warning",
            })
    except requests.RequestException:
        result["remote_status"] = {
            "reachable": False,
            "error": "Connection failed",
        }
        result["issues"].append({
            "code": "REMOTE_ADMIN_UNREACHABLE",
            "message": "Could not reach remote admin API",
            "severity": "warning",
        })
    except Exception:
        result["issues"].append({
            "code": "VERIFICATION_ERROR",
            "message": "Internal error during verification",
            "severity": "warning",
        })

    error_issues = [i for i in result["issues"] if i["severity"] == "error"]
    result["is_fully_configured"] = len(error_issues) == 0 and len(local_bidir_rules) > 0

    return jsonify(result)


@ui_bp.get("/sites/peers/<site_id>/replication-wizard")
def replication_wizard(site_id: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:*")
    except IamError:
        flash("Access denied", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    registry = _site_registry()
    peer = registry.get_peer(site_id)
    if not peer:
        flash(f"Peer site '{site_id}' not found", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    if not peer.connection_id:
        flash("This peer has no connection configured. Add a connection first to set up replication.", "warning")
        return redirect(url_for("ui.sites_dashboard"))

    connection = _connections().get(peer.connection_id)
    if not connection:
        flash(f"Connection '{peer.connection_id}' not found", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    buckets = _storage().list_buckets()
    replication = _replication()

    bucket_info = []
    for bucket in buckets:
        existing_rule = replication.get_rule(bucket.name)
        has_rule_for_peer = (
            existing_rule and
            existing_rule.target_connection_id == peer.connection_id
        )
        bucket_info.append({
            "name": bucket.name,
            "has_rule": has_rule_for_peer,
            "existing_mode": existing_rule.mode if has_rule_for_peer else None,
            "existing_target": existing_rule.target_bucket if has_rule_for_peer else None,
        })

    local_site = registry.get_local_site()

    return render_template(
        "replication_wizard.html",
        principal=principal,
        peer=peer,
        connection=connection,
        buckets=bucket_info,
        local_site=local_site,
        csrf_token=generate_csrf,
    )


@ui_bp.post("/sites/peers/<site_id>/replication-rules")
def create_peer_replication_rules(site_id: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:*")
    except IamError:
        flash("Access denied", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    registry = _site_registry()
    peer = registry.get_peer(site_id)
    if not peer or not peer.connection_id:
        flash("Invalid peer site or no connection configured", "danger")
        return redirect(url_for("ui.sites_dashboard"))

    from .replication import REPLICATION_MODE_NEW_ONLY, REPLICATION_MODE_ALL
    import time as time_module

    selected_buckets = request.form.getlist("buckets")
    mode = request.form.get("mode", REPLICATION_MODE_NEW_ONLY)

    if not selected_buckets:
        flash("No buckets selected", "warning")
        return redirect(url_for("ui.sites_dashboard"))

    created = 0
    failed = 0
    replication = _replication()

    for bucket_name in selected_buckets:
        target_bucket = request.form.get(f"target_{bucket_name}", bucket_name).strip()
        if not target_bucket:
            target_bucket = bucket_name

        try:
            rule = ReplicationRule(
                bucket_name=bucket_name,
                target_connection_id=peer.connection_id,
                target_bucket=target_bucket,
                enabled=True,
                mode=mode,
                created_at=time_module.time(),
            )
            replication.set_rule(rule)

            if mode == REPLICATION_MODE_ALL:
                replication.replicate_existing_objects(bucket_name)

            created += 1
        except Exception:
            failed += 1

    if created > 0:
        flash(f"Created {created} replication rule(s) for {peer.display_name or peer.site_id}", "success")
    if failed > 0:
        flash(f"Failed to create {failed} rule(s)", "danger")

    return redirect(url_for("ui.sites_dashboard"))


@ui_bp.get("/sites/peers/<site_id>/sync-stats")
def get_peer_sync_stats(site_id: str):
    principal = _current_principal()
    try:
        _iam().authorize(principal, None, "iam:*")
    except IamError:
        return jsonify({"error": "Access denied"}), 403

    registry = _site_registry()
    peer = registry.get_peer(site_id)
    if not peer:
        return jsonify({"error": "Peer not found"}), 404

    if not peer.connection_id:
        return jsonify({"error": "No connection configured"}), 400

    replication = _replication()
    all_rules = replication.list_rules()

    stats = {
        "buckets_syncing": 0,
        "objects_synced": 0,
        "objects_pending": 0,
        "objects_failed": 0,
        "bytes_synced": 0,
        "last_sync_at": None,
        "buckets": [],
    }

    for rule in all_rules:
        if rule.target_connection_id != peer.connection_id:
            continue

        stats["buckets_syncing"] += 1

        bucket_stats = {
            "bucket_name": rule.bucket_name,
            "target_bucket": rule.target_bucket,
            "mode": rule.mode,
            "enabled": rule.enabled,
        }

        if rule.stats:
            stats["objects_synced"] += rule.stats.objects_synced
            stats["objects_pending"] += rule.stats.objects_pending
            stats["bytes_synced"] += rule.stats.bytes_synced

            if rule.stats.last_sync_at:
                if not stats["last_sync_at"] or rule.stats.last_sync_at > stats["last_sync_at"]:
                    stats["last_sync_at"] = rule.stats.last_sync_at

            bucket_stats["last_sync_at"] = rule.stats.last_sync_at
            bucket_stats["objects_synced"] = rule.stats.objects_synced
            bucket_stats["objects_pending"] = rule.stats.objects_pending

        failure_count = replication.get_failure_count(rule.bucket_name)
        stats["objects_failed"] += failure_count
        bucket_stats["failures"] = failure_count

        stats["buckets"].append(bucket_stats)

    return jsonify(stats)


@ui_bp.app_errorhandler(404)
def ui_not_found(error):  # type: ignore[override]
    prefix = ui_bp.url_prefix or ""
    path = request.path or ""
    wants_html = request.accept_mimetypes.accept_html
    if wants_html and (not prefix or path.startswith(prefix)):
        return render_template("404.html"), 404
    return error
