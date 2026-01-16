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
    log_to_file: bool
    log_path: Path
    log_max_bytes: int
    log_backup_count: int
    ratelimit_default: str
    ratelimit_storage_uri: str
    cors_origins: list[str]
    cors_methods: list[str]
    cors_allow_headers: list[str]
    cors_expose_headers: list[str]
    session_lifetime_days: int
    auth_max_attempts: int
    auth_lockout_minutes: int
    bulk_delete_max_keys: int
    secret_ttl_seconds: int
    stream_chunk_size: int
    multipart_min_part_size: int
    bucket_stats_cache_ttl: int
    object_cache_ttl: int
    encryption_enabled: bool
    encryption_master_key_path: Path
    kms_enabled: bool
    kms_keys_path: Path
    default_encryption_algorithm: str
    display_timezone: str
    lifecycle_enabled: bool
    lifecycle_interval_seconds: int
    metrics_history_enabled: bool
    metrics_history_retention_hours: int
    metrics_history_interval_minutes: int

    @classmethod
    def from_env(cls, overrides: Optional[Dict[str, Any]] = None) -> "AppConfig":
        overrides = overrides or {}

        def _get(name: str, default: Any) -> Any:
            return overrides.get(name, os.getenv(name, default))

        storage_root = Path(_get("STORAGE_ROOT", PROJECT_ROOT / "data")).resolve()
        max_upload_size = int(_get("MAX_UPLOAD_SIZE", 1024 * 1024 * 1024)) 
        ui_page_size = int(_get("UI_PAGE_SIZE", 100))
        auth_max_attempts = int(_get("AUTH_MAX_ATTEMPTS", 5))
        auth_lockout_minutes = int(_get("AUTH_LOCKOUT_MINUTES", 15))
        bulk_delete_max_keys = int(_get("BULK_DELETE_MAX_KEYS", 500))
        secret_ttl_seconds = int(_get("SECRET_TTL_SECONDS", 300))
        stream_chunk_size = int(_get("STREAM_CHUNK_SIZE", 64 * 1024))
        multipart_min_part_size = int(_get("MULTIPART_MIN_PART_SIZE", 5 * 1024 * 1024))
        lifecycle_enabled = _get("LIFECYCLE_ENABLED", "false").lower() in ("true", "1", "yes")
        lifecycle_interval_seconds = int(_get("LIFECYCLE_INTERVAL_SECONDS", 3600))
        default_secret = "dev-secret-key"
        secret_key = str(_get("SECRET_KEY", default_secret))
        
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
                    try:
                        os.chmod(secret_file, 0o600)
                    except OSError:
                        pass
                    secret_key = generated
                except OSError:
                    secret_key = generated

        iam_env_override = "IAM_CONFIG" in overrides or "IAM_CONFIG" in os.environ
        bucket_policy_override = "BUCKET_POLICY_PATH" in overrides or "BUCKET_POLICY_PATH" in os.environ

        default_iam_path = storage_root / ".myfsio.sys" / "config" / "iam.json"
        default_bucket_policy_path = storage_root / ".myfsio.sys" / "config" / "bucket_policies.json"

        iam_config_path = Path(_get("IAM_CONFIG", default_iam_path)).resolve()
        bucket_policy_path = Path(_get("BUCKET_POLICY_PATH", default_bucket_policy_path)).resolve()

        iam_config_path = _prepare_config_file(
            iam_config_path,
            legacy_path=None if iam_env_override else storage_root / "iam.json",
        )
        bucket_policy_path = _prepare_config_file(
            bucket_policy_path,
            legacy_path=None if bucket_policy_override else storage_root / "bucket_policies.json",
        )
        api_base_url = _get("API_BASE_URL", None)
        if api_base_url:
            api_base_url = str(api_base_url)
        
        aws_region = str(_get("AWS_REGION", "us-east-1"))
        aws_service = str(_get("AWS_SERVICE", "s3"))
        enforce_ui_policies = str(_get("UI_ENFORCE_BUCKET_POLICIES", "0")).lower() in {"1", "true", "yes", "on"}
        log_level = str(_get("LOG_LEVEL", "INFO")).upper()
        log_to_file = str(_get("LOG_TO_FILE", "1")).lower() in {"1", "true", "yes", "on"}
        log_dir = Path(_get("LOG_DIR", storage_root.parent / "logs")).resolve()
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
        cors_methods = _csv(str(_get("CORS_METHODS", "GET,PUT,POST,DELETE,OPTIONS,HEAD")), ["GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD"])
        cors_allow_headers = _csv(str(_get("CORS_ALLOW_HEADERS", "*")), ["*"])
        cors_expose_headers = _csv(str(_get("CORS_EXPOSE_HEADERS", "*")), ["*"])
        session_lifetime_days = int(_get("SESSION_LIFETIME_DAYS", 30))
        bucket_stats_cache_ttl = int(_get("BUCKET_STATS_CACHE_TTL", 60))
        object_cache_ttl = int(_get("OBJECT_CACHE_TTL", 5))

        encryption_enabled = str(_get("ENCRYPTION_ENABLED", "0")).lower() in {"1", "true", "yes", "on"}
        encryption_keys_dir = storage_root / ".myfsio.sys" / "keys"
        encryption_master_key_path = Path(_get("ENCRYPTION_MASTER_KEY_PATH", encryption_keys_dir / "master.key")).resolve()
        kms_enabled = str(_get("KMS_ENABLED", "0")).lower() in {"1", "true", "yes", "on"}
        kms_keys_path = Path(_get("KMS_KEYS_PATH", encryption_keys_dir / "kms_keys.json")).resolve()
        default_encryption_algorithm = str(_get("DEFAULT_ENCRYPTION_ALGORITHM", "AES256"))
        display_timezone = str(_get("DISPLAY_TIMEZONE", "UTC"))
        metrics_history_enabled = str(_get("METRICS_HISTORY_ENABLED", "0")).lower() in {"1", "true", "yes", "on"}
        metrics_history_retention_hours = int(_get("METRICS_HISTORY_RETENTION_HOURS", 24))
        metrics_history_interval_minutes = int(_get("METRICS_HISTORY_INTERVAL_MINUTES", 5))

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
                   log_to_file=log_to_file,
                   log_path=log_path,
                   log_max_bytes=log_max_bytes,
                   log_backup_count=log_backup_count,
                   ratelimit_default=ratelimit_default,
                   ratelimit_storage_uri=ratelimit_storage_uri,
                   cors_origins=cors_origins,
                   cors_methods=cors_methods,
                   cors_allow_headers=cors_allow_headers,
                   cors_expose_headers=cors_expose_headers,
                   session_lifetime_days=session_lifetime_days,
                   auth_max_attempts=auth_max_attempts,
                   auth_lockout_minutes=auth_lockout_minutes,
                   bulk_delete_max_keys=bulk_delete_max_keys,
                   secret_ttl_seconds=secret_ttl_seconds,
                   stream_chunk_size=stream_chunk_size,
                   multipart_min_part_size=multipart_min_part_size,
                   bucket_stats_cache_ttl=bucket_stats_cache_ttl,
                   object_cache_ttl=object_cache_ttl,
                   encryption_enabled=encryption_enabled,
                   encryption_master_key_path=encryption_master_key_path,
                   kms_enabled=kms_enabled,
                   kms_keys_path=kms_keys_path,
                   default_encryption_algorithm=default_encryption_algorithm,
                   display_timezone=display_timezone,
                   lifecycle_enabled=lifecycle_enabled,
                   lifecycle_interval_seconds=lifecycle_interval_seconds,
                   metrics_history_enabled=metrics_history_enabled,
                   metrics_history_retention_hours=metrics_history_retention_hours,
                   metrics_history_interval_minutes=metrics_history_interval_minutes)

    def validate_and_report(self) -> list[str]:
        """Validate configuration and return a list of warnings/issues.
        
        Call this at startup to detect potential misconfigurations before
        the application fully commits to running.
        """
        issues = []
        
        try:
            test_file = self.storage_root / ".write_test"
            test_file.touch()
            test_file.unlink()
        except (OSError, PermissionError) as e:
            issues.append(f"CRITICAL: STORAGE_ROOT '{self.storage_root}' is not writable: {e}")
        
        storage_str = str(self.storage_root).lower()
        if "/tmp" in storage_str or "\\temp" in storage_str or "appdata\\local\\temp" in storage_str:
            issues.append(f"WARNING: STORAGE_ROOT '{self.storage_root}' appears to be a temporary directory. Data may be lost on reboot!")
        
        try:
            self.iam_config_path.relative_to(self.storage_root)
        except ValueError:
            issues.append(f"WARNING: IAM_CONFIG '{self.iam_config_path}' is outside STORAGE_ROOT '{self.storage_root}'. Consider setting IAM_CONFIG explicitly or ensuring paths are aligned.")
        
        try:
            self.bucket_policy_path.relative_to(self.storage_root)
        except ValueError:
            issues.append(f"WARNING: BUCKET_POLICY_PATH '{self.bucket_policy_path}' is outside STORAGE_ROOT '{self.storage_root}'. Consider setting BUCKET_POLICY_PATH explicitly.")
        
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            test_log = self.log_path.parent / ".write_test"
            test_log.touch()
            test_log.unlink()
        except (OSError, PermissionError) as e:
            issues.append(f"WARNING: Log directory '{self.log_path.parent}' is not writable: {e}")
        
        log_str = str(self.log_path).lower()
        if "/tmp" in log_str or "\\temp" in log_str or "appdata\\local\\temp" in log_str:
            issues.append(f"WARNING: LOG_DIR '{self.log_path.parent}' appears to be a temporary directory. Logs may be lost on reboot!")
        
        if self.encryption_enabled:
            try:
                self.encryption_master_key_path.relative_to(self.storage_root)
            except ValueError:
                issues.append(f"WARNING: ENCRYPTION_MASTER_KEY_PATH '{self.encryption_master_key_path}' is outside STORAGE_ROOT. Ensure proper backup procedures.")
        
        if self.kms_enabled:
            try:
                self.kms_keys_path.relative_to(self.storage_root)
            except ValueError:
                issues.append(f"WARNING: KMS_KEYS_PATH '{self.kms_keys_path}' is outside STORAGE_ROOT. Ensure proper backup procedures.")
        
        if self.secret_key == "dev-secret-key":
            issues.append("WARNING: Using default SECRET_KEY. Set SECRET_KEY environment variable for production.")
        
        if "*" in self.cors_origins:
            issues.append("INFO: CORS_ORIGINS is set to '*'. Consider restricting to specific domains in production.")
        
        return issues

    def print_startup_summary(self) -> None:
        """Print a summary of the configuration at startup."""
        print("\n" + "=" * 60)
        print("MyFSIO Configuration Summary")
        print("=" * 60)
        print(f"  STORAGE_ROOT:     {self.storage_root}")
        print(f"  IAM_CONFIG:       {self.iam_config_path}")
        print(f"  BUCKET_POLICY:    {self.bucket_policy_path}")
        print(f"  LOG_PATH:         {self.log_path}")
        if self.api_base_url:
            print(f"  API_BASE_URL:     {self.api_base_url}")
        if self.encryption_enabled:
            print(f"  ENCRYPTION:       Enabled (Master key: {self.encryption_master_key_path})")
        if self.kms_enabled:
            print(f"  KMS:              Enabled (Keys: {self.kms_keys_path})")
        print("=" * 60)
        
        issues = self.validate_and_report()
        if issues:
            print("\nConfiguration Issues Detected:")
            for issue in issues:
                print(f"  • {issue}")
            print()
        else:
            print("  ✓ Configuration validated successfully\n")

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
            "BUCKET_STATS_CACHE_TTL": self.bucket_stats_cache_ttl,
            "OBJECT_CACHE_TTL": self.object_cache_ttl,
            "LOG_LEVEL": self.log_level,
            "LOG_TO_FILE": self.log_to_file,
            "LOG_FILE": str(self.log_path),
            "LOG_MAX_BYTES": self.log_max_bytes,
            "LOG_BACKUP_COUNT": self.log_backup_count,
            "RATELIMIT_DEFAULT": self.ratelimit_default,
            "RATELIMIT_STORAGE_URI": self.ratelimit_storage_uri,
            "CORS_ORIGINS": self.cors_origins,
            "CORS_METHODS": self.cors_methods,
            "CORS_ALLOW_HEADERS": self.cors_allow_headers,
            "CORS_EXPOSE_HEADERS": self.cors_expose_headers,
            "SESSION_LIFETIME_DAYS": self.session_lifetime_days,
            "ENCRYPTION_ENABLED": self.encryption_enabled,
            "ENCRYPTION_MASTER_KEY_PATH": str(self.encryption_master_key_path),
            "KMS_ENABLED": self.kms_enabled,
            "KMS_KEYS_PATH": str(self.kms_keys_path),
            "DEFAULT_ENCRYPTION_ALGORITHM": self.default_encryption_algorithm,
            "DISPLAY_TIMEZONE": self.display_timezone,
            "LIFECYCLE_ENABLED": self.lifecycle_enabled,
            "LIFECYCLE_INTERVAL_SECONDS": self.lifecycle_interval_seconds,
            "METRICS_HISTORY_ENABLED": self.metrics_history_enabled,
            "METRICS_HISTORY_RETENTION_HOURS": self.metrics_history_retention_hours,
            "METRICS_HISTORY_INTERVAL_MINUTES": self.metrics_history_interval_minutes,
        }
