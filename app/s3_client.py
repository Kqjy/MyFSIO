from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Generator, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError, ConnectionClosedError
from flask import current_app, session

logger = logging.getLogger(__name__)

UI_PROXY_USER_AGENT = "MyFSIO-UIProxy/1.0"

_BOTO_ERROR_MAP = {
    "NoSuchBucket": 404,
    "NoSuchKey": 404,
    "NoSuchUpload": 404,
    "BucketAlreadyExists": 409,
    "BucketAlreadyOwnedByYou": 409,
    "BucketNotEmpty": 409,
    "AccessDenied": 403,
    "InvalidAccessKeyId": 403,
    "SignatureDoesNotMatch": 403,
    "InvalidBucketName": 400,
    "InvalidArgument": 400,
    "MalformedXML": 400,
    "EntityTooLarge": 400,
    "QuotaExceeded": 403,
}

_UPLOAD_REGISTRY_MAX_AGE = 86400
_UPLOAD_REGISTRY_CLEANUP_INTERVAL = 3600


class UploadRegistry:
    def __init__(self) -> None:
        self._entries: dict[str, tuple[str, str, float]] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

    def register(self, upload_id: str, bucket_name: str, object_key: str) -> None:
        with self._lock:
            self._entries[upload_id] = (bucket_name, object_key, time.monotonic())
            self._maybe_cleanup()

    def get_key(self, upload_id: str, bucket_name: str) -> Optional[str]:
        with self._lock:
            entry = self._entries.get(upload_id)
            if entry is None:
                return None
            stored_bucket, key, created_at = entry
            if stored_bucket != bucket_name:
                return None
            if time.monotonic() - created_at > _UPLOAD_REGISTRY_MAX_AGE:
                del self._entries[upload_id]
                return None
            return key

    def remove(self, upload_id: str) -> None:
        with self._lock:
            self._entries.pop(upload_id, None)

    def _maybe_cleanup(self) -> None:
        now = time.monotonic()
        if now - self._last_cleanup < _UPLOAD_REGISTRY_CLEANUP_INTERVAL:
            return
        self._last_cleanup = now
        cutoff = now - _UPLOAD_REGISTRY_MAX_AGE
        stale = [uid for uid, (_, _, ts) in self._entries.items() if ts < cutoff]
        for uid in stale:
            del self._entries[uid]


class S3ProxyClient:
    def __init__(self, api_base_url: str, region: str = "us-east-1") -> None:
        if not api_base_url:
            raise ValueError("api_base_url is required for S3ProxyClient")
        self._api_base_url = api_base_url.rstrip("/")
        self._region = region
        self.upload_registry = UploadRegistry()

    @property
    def api_base_url(self) -> str:
        return self._api_base_url

    def get_client(self, access_key: str, secret_key: str) -> Any:
        if not access_key or not secret_key:
            raise ValueError("Both access_key and secret_key are required")
        config = Config(
            user_agent_extra=UI_PROXY_USER_AGENT,
            connect_timeout=5,
            read_timeout=30,
            retries={"max_attempts": 0},
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        )
        return boto3.client(
            "s3",
            endpoint_url=self._api_base_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=self._region,
            config=config,
        )


def _get_proxy() -> S3ProxyClient:
    proxy = current_app.extensions.get("s3_proxy")
    if proxy is None:
        raise RuntimeError(
            "S3 proxy not configured. Set API_BASE_URL or run both API and UI servers."
        )
    return proxy


def _get_session_creds() -> tuple[str, str]:
    secret_store = current_app.extensions["secret_store"]
    secret_store.purge_expired()
    token = session.get("cred_token")
    if not token:
        raise PermissionError("Not authenticated")
    creds = secret_store.peek(token)
    if not creds:
        raise PermissionError("Session expired")
    access_key = creds.get("access_key", "")
    secret_key = creds.get("secret_key", "")
    if not access_key or not secret_key:
        raise PermissionError("Invalid session credentials")
    return access_key, secret_key


def get_session_s3_client() -> Any:
    proxy = _get_proxy()
    access_key, secret_key = _get_session_creds()
    return proxy.get_client(access_key, secret_key)


def get_upload_registry() -> UploadRegistry:
    return _get_proxy().upload_registry


def handle_client_error(exc: ClientError) -> tuple[dict[str, str], int]:
    error_info = exc.response.get("Error", {})
    code = error_info.get("Code", "InternalError")
    message = error_info.get("Message") or "S3 operation failed"
    http_status = _BOTO_ERROR_MAP.get(code)
    if http_status is None:
        http_status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 500)
    return {"error": message}, http_status


def handle_connection_error(exc: Exception) -> tuple[dict[str, str], int]:
    logger.error("S3 API connection failed: %s", exc)
    return {"error": "S3 API server is unreachable. Ensure the API server is running."}, 502


def format_datetime_display(dt: Any, display_tz: str = "UTC") -> str:
    from .ui import _format_datetime_display
    return _format_datetime_display(dt, display_tz)


def format_datetime_iso(dt: Any, display_tz: str = "UTC") -> str:
    from .ui import _format_datetime_iso
    return _format_datetime_iso(dt, display_tz)


def build_url_templates(bucket_name: str) -> dict[str, str]:
    from flask import url_for
    preview_t = url_for("ui.object_preview", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER")
    delete_t = url_for("ui.delete_object", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER")
    presign_t = url_for("ui.object_presign", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER")
    versions_t = url_for("ui.object_versions", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER")
    restore_t = url_for(
        "ui.restore_object_version",
        bucket_name=bucket_name,
        object_key="KEY_PLACEHOLDER",
        version_id="VERSION_ID_PLACEHOLDER",
    )
    tags_t = url_for("ui.object_tags", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER")
    copy_t = url_for("ui.copy_object", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER")
    move_t = url_for("ui.move_object", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER")
    metadata_t = url_for("ui.object_metadata", bucket_name=bucket_name, object_key="KEY_PLACEHOLDER")
    return {
        "preview": preview_t,
        "download": preview_t + "?download=1",
        "presign": presign_t,
        "delete": delete_t,
        "versions": versions_t,
        "restore": restore_t,
        "tags": tags_t,
        "copy": copy_t,
        "move": move_t,
        "metadata": metadata_t,
    }


def translate_list_objects(
    boto3_response: dict[str, Any],
    url_templates: dict[str, str],
    display_tz: str = "UTC",
    versioning_enabled: bool = False,
) -> dict[str, Any]:
    objects_data = []
    for obj in boto3_response.get("Contents", []):
        last_mod = obj["LastModified"]
        objects_data.append({
            "key": obj["Key"],
            "size": obj["Size"],
            "last_modified": last_mod.isoformat(),
            "last_modified_display": format_datetime_display(last_mod, display_tz),
            "last_modified_iso": format_datetime_iso(last_mod, display_tz),
            "etag": obj.get("ETag", "").strip('"'),
        })
    return {
        "objects": objects_data,
        "is_truncated": boto3_response.get("IsTruncated", False),
        "next_continuation_token": boto3_response.get("NextContinuationToken"),
        "total_count": boto3_response.get("KeyCount", len(objects_data)),
        "versioning_enabled": versioning_enabled,
        "url_templates": url_templates,
    }


def get_versioning_via_s3(client: Any, bucket_name: str) -> bool:
    try:
        resp = client.get_bucket_versioning(Bucket=bucket_name)
        return resp.get("Status") == "Enabled"
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code != "NoSuchBucket":
            logger.warning("Failed to check versioning for %s: %s", bucket_name, code)
        return False


def stream_objects_ndjson(
    client: Any,
    bucket_name: str,
    prefix: Optional[str],
    url_templates: dict[str, str],
    display_tz: str = "UTC",
    versioning_enabled: bool = False,
) -> Generator[str, None, None]:
    meta_line = json.dumps({
        "type": "meta",
        "versioning_enabled": versioning_enabled,
        "url_templates": url_templates,
    }) + "\n"
    yield meta_line

    yield json.dumps({"type": "count", "total_count": 0}) + "\n"

    kwargs: dict[str, Any] = {"Bucket": bucket_name, "MaxKeys": 1000}
    if prefix:
        kwargs["Prefix"] = prefix

    try:
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(**kwargs):
            for obj in page.get("Contents", []):
                last_mod = obj["LastModified"]
                yield json.dumps({
                    "type": "object",
                    "key": obj["Key"],
                    "size": obj["Size"],
                    "last_modified": last_mod.isoformat(),
                    "last_modified_display": format_datetime_display(last_mod, display_tz),
                    "last_modified_iso": format_datetime_iso(last_mod, display_tz),
                    "etag": obj.get("ETag", "").strip('"'),
                }) + "\n"
    except ClientError as exc:
        error_msg = exc.response.get("Error", {}).get("Message", "S3 operation failed")
        yield json.dumps({"type": "error", "error": error_msg}) + "\n"
        return
    except (EndpointConnectionError, ConnectionClosedError):
        yield json.dumps({"type": "error", "error": "S3 API server is unreachable"}) + "\n"
        return

    yield json.dumps({"type": "done"}) + "\n"
