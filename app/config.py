"""Configuration helpers for the S3 clone application."""
from __future__ import annotations

import os
import secrets
import shutil
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

if getattr(sys, "frozen", False):
    # Running in a PyInstaller bundle
    PROJECT_ROOT = Path(sys._MEIPASS)
else:
    # Running in a normal Python environment
    PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _prepare_config_file(active_path: Path, legacy_path: Optional[Path] = None) -> Path:
    """Ensure config directories exist and migrate legacy files when possible."""
    active_path = Path(active_path)
    active_path.parent.mkdir(parents=True, exist_ok=True)
    if legacy_path:
        legacy_path = Path(legacy_path)
        if not active_path.exists() and legacy_path.exists():
            legacy_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.move(str(legacy_path), str(active_path))
            except OSError:
                shutil.copy2(legacy_path, active_path)
                try:
                    legacy_path.unlink(missing_ok=True)
                except OSError:
                    pass
    return active_path


@dataclass
class AppConfig:
    storage_root: Path
    max_upload_size: int
    ui_page_size: int
    secret_key: str
    iam_config_path: Path
    bucket_policy_path: Path
    api_base_url: Optional[str]
    aws_region: str
    aws_service: str
    ui_enforce_bucket_policies: bool
    log_level: str
    log_path: Path
    log_max_bytes: int
    log_backup_count: int
    ratelimit_default: str
    ratelimit_storage_uri: str
    cors_origins: list[str]
    cors_methods: list[str]
    cors_allow_headers: list[str]
    session_lifetime_days: int
    auth_max_attempts: int
    auth_lockout_minutes: int
    bulk_delete_max_keys: int
    secret_ttl_seconds: int
    stream_chunk_size: int
    multipart_min_part_size: int

    @classmethod
    def from_env(cls, overrides: Optional[Dict[str, Any]] = None) -> "AppConfig":
        overrides = overrides or {}

        def _get(name: str, default: Any) -> Any:
            return overrides.get(name, os.getenv(name, default))

        storage_root = Path(_get("STORAGE_ROOT", PROJECT_ROOT / "data")).resolve()
        max_upload_size = int(_get("MAX_UPLOAD_SIZE", 1024 * 1024 * 1024))  # 1 GiB default
        ui_page_size = int(_get("UI_PAGE_SIZE", 100))
        auth_max_attempts = int(_get("AUTH_MAX_ATTEMPTS", 5))
        auth_lockout_minutes = int(_get("AUTH_LOCKOUT_MINUTES", 15))
        bulk_delete_max_keys = int(_get("BULK_DELETE_MAX_KEYS", 500))
        secret_ttl_seconds = int(_get("SECRET_TTL_SECONDS", 300))
        stream_chunk_size = int(_get("STREAM_CHUNK_SIZE", 64 * 1024))
        multipart_min_part_size = int(_get("MULTIPART_MIN_PART_SIZE", 5 * 1024 * 1024))
        default_secret = "dev-secret-key"
        secret_key = str(_get("SECRET_KEY", default_secret))
        
        # If using default/missing secret, try to load/persist a generated one from disk
        # This ensures consistency across Gunicorn workers
        if not secret_key or secret_key == default_secret:
            secret_file = storage_root / ".myfsio.sys" / "config" / ".secret"
            if secret_file.exists():
                secret_key = secret_file.read_text().strip()
            else:
                generated = secrets.token_urlsafe(32)
                if secret_key == default_secret:
                    warnings.warn("Using insecure default SECRET_KEY. A random value has been generated and persisted; set SECRET_KEY for production", RuntimeWarning)
                try:
                    secret_file.parent.mkdir(parents=True, exist_ok=True)
                    secret_file.write_text(generated)
                    secret_key = generated
                except OSError:
                    # Fallback if we can't write to disk (e.g. read-only fs)
                    secret_key = generated

        iam_env_override = "IAM_CONFIG" in overrides or "IAM_CONFIG" in os.environ
        bucket_policy_override = "BUCKET_POLICY_PATH" in overrides or "BUCKET_POLICY_PATH" in os.environ

        default_iam_path = PROJECT_ROOT / "data" / ".myfsio.sys" / "config" / "iam.json"
        default_bucket_policy_path = PROJECT_ROOT / "data" / ".myfsio.sys" / "config" / "bucket_policies.json"

        iam_config_path = Path(_get("IAM_CONFIG", default_iam_path)).resolve()
        bucket_policy_path = Path(_get("BUCKET_POLICY_PATH", default_bucket_policy_path)).resolve()

        iam_config_path = _prepare_config_file(
            iam_config_path,
            legacy_path=None if iam_env_override else PROJECT_ROOT / "data" / "iam.json",
        )
        bucket_policy_path = _prepare_config_file(
            bucket_policy_path,
            legacy_path=None if bucket_policy_override else PROJECT_ROOT / "data" / "bucket_policies.json",
        )
        api_base_url = _get("API_BASE_URL", None)
        if api_base_url:
            api_base_url = str(api_base_url)
        
        aws_region = str(_get("AWS_REGION", "us-east-1"))
        aws_service = str(_get("AWS_SERVICE", "s3"))
        enforce_ui_policies = str(_get("UI_ENFORCE_BUCKET_POLICIES", "0")).lower() in {"1", "true", "yes", "on"}
        log_level = str(_get("LOG_LEVEL", "INFO")).upper()
        log_dir = Path(_get("LOG_DIR", PROJECT_ROOT / "logs")).resolve()
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / str(_get("LOG_FILE", "app.log"))
        log_max_bytes = int(_get("LOG_MAX_BYTES", 5 * 1024 * 1024))
        log_backup_count = int(_get("LOG_BACKUP_COUNT", 3))
        ratelimit_default = str(_get("RATE_LIMIT_DEFAULT", "200 per minute"))
        ratelimit_storage_uri = str(_get("RATE_LIMIT_STORAGE_URI", "memory://"))

        def _csv(value: str, default: list[str]) -> list[str]:
            if not value:
                return default
            parts = [segment.strip() for segment in value.split(",") if segment.strip()]
            return parts or default

        cors_origins = _csv(str(_get("CORS_ORIGINS", "*")), ["*"])
        cors_methods = _csv(str(_get("CORS_METHODS", "GET,PUT,POST,DELETE,OPTIONS")), ["GET", "PUT", "POST", "DELETE", "OPTIONS"])
        cors_allow_headers = _csv(str(_get("CORS_ALLOW_HEADERS", "Content-Type,X-Access-Key,X-Secret-Key,X-Amz-Algorithm,X-Amz-Credential,X-Amz-Date,X-Amz-Expires,X-Amz-SignedHeaders,X-Amz-Signature")), [
            "Content-Type",
            "X-Access-Key",
            "X-Secret-Key",
            "X-Amz-Algorithm",
            "X-Amz-Credential",
            "X-Amz-Date",
            "X-Amz-Expires",
            "X-Amz-SignedHeaders",
            "X-Amz-Signature",
        ])
        session_lifetime_days = int(_get("SESSION_LIFETIME_DAYS", 30))

        return cls(storage_root=storage_root,
                   max_upload_size=max_upload_size,
                   ui_page_size=ui_page_size,
                   secret_key=secret_key,
                   iam_config_path=iam_config_path,
                   bucket_policy_path=bucket_policy_path,
                   api_base_url=api_base_url,
                   aws_region=aws_region,
                   aws_service=aws_service,
                   ui_enforce_bucket_policies=enforce_ui_policies,
                   log_level=log_level,
                   log_path=log_path,
                   log_max_bytes=log_max_bytes,
                   log_backup_count=log_backup_count,
                   ratelimit_default=ratelimit_default,
                   ratelimit_storage_uri=ratelimit_storage_uri,
                   cors_origins=cors_origins,
                   cors_methods=cors_methods,
                   cors_allow_headers=cors_allow_headers,
                   session_lifetime_days=session_lifetime_days,
                   auth_max_attempts=auth_max_attempts,
                   auth_lockout_minutes=auth_lockout_minutes,
                   bulk_delete_max_keys=bulk_delete_max_keys,
                   secret_ttl_seconds=secret_ttl_seconds,
                   stream_chunk_size=stream_chunk_size,
                   multipart_min_part_size=multipart_min_part_size)

    def to_flask_config(self) -> Dict[str, Any]:
        return {
            "STORAGE_ROOT": str(self.storage_root),
            "MAX_CONTENT_LENGTH": self.max_upload_size,
            "UI_PAGE_SIZE": self.ui_page_size,
            "SECRET_KEY": self.secret_key,
            "IAM_CONFIG": str(self.iam_config_path),
            "BUCKET_POLICY_PATH": str(self.bucket_policy_path),
            "API_BASE_URL": self.api_base_url,
            "AWS_REGION": self.aws_region,
            "AWS_SERVICE": self.aws_service,
            "UI_ENFORCE_BUCKET_POLICIES": self.ui_enforce_bucket_policies,
            "AUTH_MAX_ATTEMPTS": self.auth_max_attempts,
            "AUTH_LOCKOUT_MINUTES": self.auth_lockout_minutes,
            "BULK_DELETE_MAX_KEYS": self.bulk_delete_max_keys,
            "SECRET_TTL_SECONDS": self.secret_ttl_seconds,
            "STREAM_CHUNK_SIZE": self.stream_chunk_size,
            "MULTIPART_MIN_PART_SIZE": self.multipart_min_part_size,
            "LOG_LEVEL": self.log_level,
            "LOG_FILE": str(self.log_path),
            "LOG_MAX_BYTES": self.log_max_bytes,
            "LOG_BACKUP_COUNT": self.log_backup_count,
            "RATELIMIT_DEFAULT": self.ratelimit_default,
            "RATELIMIT_STORAGE_URI": self.ratelimit_storage_uri,
            "CORS_ORIGINS": self.cors_origins,
            "CORS_METHODS": self.cors_methods,
            "CORS_ALLOW_HEADERS": self.cors_allow_headers,
            "SESSION_LIFETIME_DAYS": self.session_lifetime_days,
        }
