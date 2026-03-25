from __future__ import annotations

import os
import re
import secrets
import shutil
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import psutil


def _calculate_auto_threads() -> int:
    cpu_count = psutil.cpu_count(logical=True) or 4
    return max(1, min(cpu_count * 2, 64))


def _calculate_auto_connection_limit() -> int:
    available_mb = psutil.virtual_memory().available / (1024 * 1024)
    calculated = int(available_mb / 5)
    return max(20, min(calculated, 1000))


def _calculate_auto_backlog(connection_limit: int) -> int:
    return max(128, min(connection_limit * 2, 4096))


def _validate_rate_limit(value: str) -> str:
    pattern = r"^\d+\s+per\s+(second|minute|hour|day)$"
    if not re.match(pattern, value):
        raise ValueError(f"Invalid rate limit format: {value}. Expected format: '200 per minute'")
    return value

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
    ratelimit_list_buckets: str
    ratelimit_bucket_ops: str
    ratelimit_object_ops: str
    ratelimit_head_ops: str
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
    operation_metrics_enabled: bool
    operation_metrics_interval_minutes: int
    operation_metrics_retention_hours: int
    server_threads: int
    server_connection_limit: int
    server_backlog: int
    server_channel_timeout: int
    server_max_buffer_size: int
    server_threads_auto: bool
    server_connection_limit_auto: bool
    server_backlog_auto: bool
    site_sync_enabled: bool
    site_sync_interval_seconds: int
    site_sync_batch_size: int
    sigv4_timestamp_tolerance_seconds: int
    presigned_url_min_expiry_seconds: int
    presigned_url_max_expiry_seconds: int
    replication_connect_timeout_seconds: int
    replication_read_timeout_seconds: int
    replication_max_retries: int
    replication_streaming_threshold_bytes: int
    replication_max_failures_per_bucket: int
    site_sync_connect_timeout_seconds: int
    site_sync_read_timeout_seconds: int
    site_sync_max_retries: int
    site_sync_clock_skew_tolerance_seconds: float
    object_key_max_length_bytes: int
    object_cache_max_size: int
    bucket_config_cache_ttl_seconds: float
    object_tag_limit: int
    encryption_chunk_size_bytes: int
    kms_generate_data_key_min_bytes: int
    kms_generate_data_key_max_bytes: int
    lifecycle_max_history_per_bucket: int
    site_id: Optional[str]
    site_endpoint: Optional[str]
    site_region: str
    site_priority: int
    ratelimit_admin: str
    num_trusted_proxies: int
    allowed_redirect_hosts: list[str]
    allow_internal_endpoints: bool
    website_hosting_enabled: bool
    gc_enabled: bool
    gc_interval_hours: float
    gc_temp_file_max_age_hours: float
    gc_multipart_max_age_days: int
    gc_lock_file_max_age_hours: float
    gc_dry_run: bool
    gc_io_throttle_ms: int
    integrity_enabled: bool
    integrity_interval_hours: float
    integrity_batch_size: int
    integrity_auto_heal: bool
    integrity_dry_run: bool
    integrity_io_throttle_ms: int

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
        ratelimit_default = _validate_rate_limit(str(_get("RATE_LIMIT_DEFAULT", "200 per minute")))
        ratelimit_storage_uri = str(_get("RATE_LIMIT_STORAGE_URI", "memory://"))
        ratelimit_list_buckets = _validate_rate_limit(str(_get("RATE_LIMIT_LIST_BUCKETS", "60 per minute")))
        ratelimit_bucket_ops = _validate_rate_limit(str(_get("RATE_LIMIT_BUCKET_OPS", "120 per minute")))
        ratelimit_object_ops = _validate_rate_limit(str(_get("RATE_LIMIT_OBJECT_OPS", "240 per minute")))
        ratelimit_head_ops = _validate_rate_limit(str(_get("RATE_LIMIT_HEAD_OPS", "100 per minute")))

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
        object_cache_ttl = int(_get("OBJECT_CACHE_TTL", 60))

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
        operation_metrics_enabled = str(_get("OPERATION_METRICS_ENABLED", "0")).lower() in {"1", "true", "yes", "on"}
        operation_metrics_interval_minutes = int(_get("OPERATION_METRICS_INTERVAL_MINUTES", 5))
        operation_metrics_retention_hours = int(_get("OPERATION_METRICS_RETENTION_HOURS", 24))

        _raw_threads = int(_get("SERVER_THREADS", 0))
        if _raw_threads == 0:
            server_threads = _calculate_auto_threads()
            server_threads_auto = True
        else:
            server_threads = _raw_threads
            server_threads_auto = False

        _raw_conn_limit = int(_get("SERVER_CONNECTION_LIMIT", 0))
        if _raw_conn_limit == 0:
            server_connection_limit = _calculate_auto_connection_limit()
            server_connection_limit_auto = True
        else:
            server_connection_limit = _raw_conn_limit
            server_connection_limit_auto = False

        _raw_backlog = int(_get("SERVER_BACKLOG", 0))
        if _raw_backlog == 0:
            server_backlog = _calculate_auto_backlog(server_connection_limit)
            server_backlog_auto = True
        else:
            server_backlog = _raw_backlog
            server_backlog_auto = False

        server_channel_timeout = int(_get("SERVER_CHANNEL_TIMEOUT", 120))
        server_max_buffer_size = int(_get("SERVER_MAX_BUFFER_SIZE", 1024 * 1024 * 128))
        site_sync_enabled = str(_get("SITE_SYNC_ENABLED", "0")).lower() in {"1", "true", "yes", "on"}
        site_sync_interval_seconds = int(_get("SITE_SYNC_INTERVAL_SECONDS", 60))
        site_sync_batch_size = int(_get("SITE_SYNC_BATCH_SIZE", 100))

        sigv4_timestamp_tolerance_seconds = int(_get("SIGV4_TIMESTAMP_TOLERANCE_SECONDS", 900))
        presigned_url_min_expiry_seconds = int(_get("PRESIGNED_URL_MIN_EXPIRY_SECONDS", 1))
        presigned_url_max_expiry_seconds = int(_get("PRESIGNED_URL_MAX_EXPIRY_SECONDS", 604800))
        replication_connect_timeout_seconds = int(_get("REPLICATION_CONNECT_TIMEOUT_SECONDS", 5))
        replication_read_timeout_seconds = int(_get("REPLICATION_READ_TIMEOUT_SECONDS", 30))
        replication_max_retries = int(_get("REPLICATION_MAX_RETRIES", 2))
        replication_streaming_threshold_bytes = int(_get("REPLICATION_STREAMING_THRESHOLD_BYTES", 10 * 1024 * 1024))
        replication_max_failures_per_bucket = int(_get("REPLICATION_MAX_FAILURES_PER_BUCKET", 50))
        site_sync_connect_timeout_seconds = int(_get("SITE_SYNC_CONNECT_TIMEOUT_SECONDS", 10))
        site_sync_read_timeout_seconds = int(_get("SITE_SYNC_READ_TIMEOUT_SECONDS", 120))
        site_sync_max_retries = int(_get("SITE_SYNC_MAX_RETRIES", 2))
        site_sync_clock_skew_tolerance_seconds = float(_get("SITE_SYNC_CLOCK_SKEW_TOLERANCE_SECONDS", 1.0))
        object_key_max_length_bytes = int(_get("OBJECT_KEY_MAX_LENGTH_BYTES", 1024))
        object_cache_max_size = int(_get("OBJECT_CACHE_MAX_SIZE", 100))
        bucket_config_cache_ttl_seconds = float(_get("BUCKET_CONFIG_CACHE_TTL_SECONDS", 30.0))
        object_tag_limit = int(_get("OBJECT_TAG_LIMIT", 50))
        encryption_chunk_size_bytes = int(_get("ENCRYPTION_CHUNK_SIZE_BYTES", 64 * 1024))
        kms_generate_data_key_min_bytes = int(_get("KMS_GENERATE_DATA_KEY_MIN_BYTES", 1))
        kms_generate_data_key_max_bytes = int(_get("KMS_GENERATE_DATA_KEY_MAX_BYTES", 1024))
        lifecycle_max_history_per_bucket = int(_get("LIFECYCLE_MAX_HISTORY_PER_BUCKET", 50))

        site_id_raw = _get("SITE_ID", None)
        site_id = str(site_id_raw).strip() if site_id_raw else None
        site_endpoint_raw = _get("SITE_ENDPOINT", None)
        site_endpoint = str(site_endpoint_raw).strip() if site_endpoint_raw else None
        site_region = str(_get("SITE_REGION", "us-east-1"))
        site_priority = int(_get("SITE_PRIORITY", 100))
        ratelimit_admin = _validate_rate_limit(str(_get("RATE_LIMIT_ADMIN", "60 per minute")))
        num_trusted_proxies = int(_get("NUM_TRUSTED_PROXIES", 1))
        allowed_redirect_hosts_raw = _get("ALLOWED_REDIRECT_HOSTS", "")
        allowed_redirect_hosts = [h.strip() for h in str(allowed_redirect_hosts_raw).split(",") if h.strip()]
        allow_internal_endpoints = str(_get("ALLOW_INTERNAL_ENDPOINTS", "0")).lower() in {"1", "true", "yes", "on"}
        website_hosting_enabled = str(_get("WEBSITE_HOSTING_ENABLED", "0")).lower() in {"1", "true", "yes", "on"}
        gc_enabled = str(_get("GC_ENABLED", "0")).lower() in {"1", "true", "yes", "on"}
        gc_interval_hours = float(_get("GC_INTERVAL_HOURS", 6.0))
        gc_temp_file_max_age_hours = float(_get("GC_TEMP_FILE_MAX_AGE_HOURS", 24.0))
        gc_multipart_max_age_days = int(_get("GC_MULTIPART_MAX_AGE_DAYS", 7))
        gc_lock_file_max_age_hours = float(_get("GC_LOCK_FILE_MAX_AGE_HOURS", 1.0))
        gc_dry_run = str(_get("GC_DRY_RUN", "0")).lower() in {"1", "true", "yes", "on"}
        gc_io_throttle_ms = int(_get("GC_IO_THROTTLE_MS", 10))
        integrity_enabled = str(_get("INTEGRITY_ENABLED", "0")).lower() in {"1", "true", "yes", "on"}
        integrity_interval_hours = float(_get("INTEGRITY_INTERVAL_HOURS", 24.0))
        integrity_batch_size = int(_get("INTEGRITY_BATCH_SIZE", 1000))
        integrity_auto_heal = str(_get("INTEGRITY_AUTO_HEAL", "0")).lower() in {"1", "true", "yes", "on"}
        integrity_dry_run = str(_get("INTEGRITY_DRY_RUN", "0")).lower() in {"1", "true", "yes", "on"}
        integrity_io_throttle_ms = int(_get("INTEGRITY_IO_THROTTLE_MS", 10))

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
                   ratelimit_list_buckets=ratelimit_list_buckets,
                   ratelimit_bucket_ops=ratelimit_bucket_ops,
                   ratelimit_object_ops=ratelimit_object_ops,
                   ratelimit_head_ops=ratelimit_head_ops,
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
                   metrics_history_interval_minutes=metrics_history_interval_minutes,
                   operation_metrics_enabled=operation_metrics_enabled,
                   operation_metrics_interval_minutes=operation_metrics_interval_minutes,
                   operation_metrics_retention_hours=operation_metrics_retention_hours,
                   server_threads=server_threads,
                   server_connection_limit=server_connection_limit,
                   server_backlog=server_backlog,
                   server_channel_timeout=server_channel_timeout,
                   server_max_buffer_size=server_max_buffer_size,
                   server_threads_auto=server_threads_auto,
                   server_connection_limit_auto=server_connection_limit_auto,
                   server_backlog_auto=server_backlog_auto,
                   site_sync_enabled=site_sync_enabled,
                   site_sync_interval_seconds=site_sync_interval_seconds,
                   site_sync_batch_size=site_sync_batch_size,
                   sigv4_timestamp_tolerance_seconds=sigv4_timestamp_tolerance_seconds,
                   presigned_url_min_expiry_seconds=presigned_url_min_expiry_seconds,
                   presigned_url_max_expiry_seconds=presigned_url_max_expiry_seconds,
                   replication_connect_timeout_seconds=replication_connect_timeout_seconds,
                   replication_read_timeout_seconds=replication_read_timeout_seconds,
                   replication_max_retries=replication_max_retries,
                   replication_streaming_threshold_bytes=replication_streaming_threshold_bytes,
                   replication_max_failures_per_bucket=replication_max_failures_per_bucket,
                   site_sync_connect_timeout_seconds=site_sync_connect_timeout_seconds,
                   site_sync_read_timeout_seconds=site_sync_read_timeout_seconds,
                   site_sync_max_retries=site_sync_max_retries,
                   site_sync_clock_skew_tolerance_seconds=site_sync_clock_skew_tolerance_seconds,
                   object_key_max_length_bytes=object_key_max_length_bytes,
                   object_cache_max_size=object_cache_max_size,
                   bucket_config_cache_ttl_seconds=bucket_config_cache_ttl_seconds,
                   object_tag_limit=object_tag_limit,
                   encryption_chunk_size_bytes=encryption_chunk_size_bytes,
                   kms_generate_data_key_min_bytes=kms_generate_data_key_min_bytes,
                   kms_generate_data_key_max_bytes=kms_generate_data_key_max_bytes,
                   lifecycle_max_history_per_bucket=lifecycle_max_history_per_bucket,
                   site_id=site_id,
                   site_endpoint=site_endpoint,
                   site_region=site_region,
                   site_priority=site_priority,
                   ratelimit_admin=ratelimit_admin,
                   num_trusted_proxies=num_trusted_proxies,
                   allowed_redirect_hosts=allowed_redirect_hosts,
                   allow_internal_endpoints=allow_internal_endpoints,
                   website_hosting_enabled=website_hosting_enabled,
                   gc_enabled=gc_enabled,
                   gc_interval_hours=gc_interval_hours,
                   gc_temp_file_max_age_hours=gc_temp_file_max_age_hours,
                   gc_multipart_max_age_days=gc_multipart_max_age_days,
                   gc_lock_file_max_age_hours=gc_lock_file_max_age_hours,
                   gc_dry_run=gc_dry_run,
                   gc_io_throttle_ms=gc_io_throttle_ms,
                   integrity_enabled=integrity_enabled,
                   integrity_interval_hours=integrity_interval_hours,
                   integrity_batch_size=integrity_batch_size,
                   integrity_auto_heal=integrity_auto_heal,
                   integrity_dry_run=integrity_dry_run,
                   integrity_io_throttle_ms=integrity_io_throttle_ms)

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

        if not (1 <= self.server_threads <= 64):
            issues.append(f"CRITICAL: SERVER_THREADS={self.server_threads} is outside valid range (1-64). Server cannot start.")
        if not (10 <= self.server_connection_limit <= 1000):
            issues.append(f"CRITICAL: SERVER_CONNECTION_LIMIT={self.server_connection_limit} is outside valid range (10-1000). Server cannot start.")
        if not (128 <= self.server_backlog <= 4096):
            issues.append(f"CRITICAL: SERVER_BACKLOG={self.server_backlog} is outside valid range (128-4096). Server cannot start.")
        if not (10 <= self.server_channel_timeout <= 300):
            issues.append(f"CRITICAL: SERVER_CHANNEL_TIMEOUT={self.server_channel_timeout} is outside valid range (10-300). Server cannot start.")
        if self.server_max_buffer_size < 1024 * 1024:
            issues.append(f"WARNING: SERVER_MAX_BUFFER_SIZE={self.server_max_buffer_size} is less than 1MB. Large uploads will fail.")

        if sys.platform != "win32":
            try:
                import resource
                soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
                threshold = int(soft_limit * 0.8)
                if self.server_connection_limit > threshold:
                    issues.append(f"WARNING: SERVER_CONNECTION_LIMIT={self.server_connection_limit} exceeds 80% of system file descriptor limit (soft={soft_limit}). Consider running 'ulimit -n {self.server_connection_limit + 100}'.")
            except (ImportError, OSError):
                pass

        try:
            import psutil
            available_mb = psutil.virtual_memory().available / (1024 * 1024)
            estimated_mb = self.server_threads * 50
            if estimated_mb > available_mb * 0.5:
                issues.append(f"WARNING: SERVER_THREADS={self.server_threads} may require ~{estimated_mb}MB memory, exceeding 50% of available RAM ({int(available_mb)}MB).")
        except ImportError:
            pass

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
        if self.website_hosting_enabled:
            print(f"  WEBSITE_HOSTING:  Enabled")
        def _auto(flag: bool) -> str:
            return " (auto)" if flag else ""
        print(f"  SERVER_THREADS:   {self.server_threads}{_auto(self.server_threads_auto)}")
        print(f"  CONNECTION_LIMIT: {self.server_connection_limit}{_auto(self.server_connection_limit_auto)}")
        print(f"  BACKLOG:          {self.server_backlog}{_auto(self.server_backlog_auto)}")
        print(f"  CHANNEL_TIMEOUT:  {self.server_channel_timeout}s")
        print(f"  MAX_BUFFER_SIZE:  {self.server_max_buffer_size // (1024 * 1024)}MB")
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
            "RATELIMIT_LIST_BUCKETS": self.ratelimit_list_buckets,
            "RATELIMIT_BUCKET_OPS": self.ratelimit_bucket_ops,
            "RATELIMIT_OBJECT_OPS": self.ratelimit_object_ops,
            "RATELIMIT_HEAD_OPS": self.ratelimit_head_ops,
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
            "OPERATION_METRICS_ENABLED": self.operation_metrics_enabled,
            "OPERATION_METRICS_INTERVAL_MINUTES": self.operation_metrics_interval_minutes,
            "OPERATION_METRICS_RETENTION_HOURS": self.operation_metrics_retention_hours,
            "SERVER_THREADS": self.server_threads,
            "SERVER_CONNECTION_LIMIT": self.server_connection_limit,
            "SERVER_BACKLOG": self.server_backlog,
            "SERVER_CHANNEL_TIMEOUT": self.server_channel_timeout,
            "SERVER_MAX_BUFFER_SIZE": self.server_max_buffer_size,
            "SITE_SYNC_ENABLED": self.site_sync_enabled,
            "SITE_SYNC_INTERVAL_SECONDS": self.site_sync_interval_seconds,
            "SITE_SYNC_BATCH_SIZE": self.site_sync_batch_size,
            "SIGV4_TIMESTAMP_TOLERANCE_SECONDS": self.sigv4_timestamp_tolerance_seconds,
            "PRESIGNED_URL_MIN_EXPIRY_SECONDS": self.presigned_url_min_expiry_seconds,
            "PRESIGNED_URL_MAX_EXPIRY_SECONDS": self.presigned_url_max_expiry_seconds,
            "REPLICATION_CONNECT_TIMEOUT_SECONDS": self.replication_connect_timeout_seconds,
            "REPLICATION_READ_TIMEOUT_SECONDS": self.replication_read_timeout_seconds,
            "REPLICATION_MAX_RETRIES": self.replication_max_retries,
            "REPLICATION_STREAMING_THRESHOLD_BYTES": self.replication_streaming_threshold_bytes,
            "REPLICATION_MAX_FAILURES_PER_BUCKET": self.replication_max_failures_per_bucket,
            "SITE_SYNC_CONNECT_TIMEOUT_SECONDS": self.site_sync_connect_timeout_seconds,
            "SITE_SYNC_READ_TIMEOUT_SECONDS": self.site_sync_read_timeout_seconds,
            "SITE_SYNC_MAX_RETRIES": self.site_sync_max_retries,
            "SITE_SYNC_CLOCK_SKEW_TOLERANCE_SECONDS": self.site_sync_clock_skew_tolerance_seconds,
            "OBJECT_KEY_MAX_LENGTH_BYTES": self.object_key_max_length_bytes,
            "OBJECT_CACHE_MAX_SIZE": self.object_cache_max_size,
            "BUCKET_CONFIG_CACHE_TTL_SECONDS": self.bucket_config_cache_ttl_seconds,
            "OBJECT_TAG_LIMIT": self.object_tag_limit,
            "ENCRYPTION_CHUNK_SIZE_BYTES": self.encryption_chunk_size_bytes,
            "KMS_GENERATE_DATA_KEY_MIN_BYTES": self.kms_generate_data_key_min_bytes,
            "KMS_GENERATE_DATA_KEY_MAX_BYTES": self.kms_generate_data_key_max_bytes,
            "LIFECYCLE_MAX_HISTORY_PER_BUCKET": self.lifecycle_max_history_per_bucket,
            "SITE_ID": self.site_id,
            "SITE_ENDPOINT": self.site_endpoint,
            "SITE_REGION": self.site_region,
            "SITE_PRIORITY": self.site_priority,
            "RATE_LIMIT_ADMIN": self.ratelimit_admin,
            "NUM_TRUSTED_PROXIES": self.num_trusted_proxies,
            "ALLOWED_REDIRECT_HOSTS": self.allowed_redirect_hosts,
            "ALLOW_INTERNAL_ENDPOINTS": self.allow_internal_endpoints,
            "WEBSITE_HOSTING_ENABLED": self.website_hosting_enabled,
            "GC_ENABLED": self.gc_enabled,
            "GC_INTERVAL_HOURS": self.gc_interval_hours,
            "GC_TEMP_FILE_MAX_AGE_HOURS": self.gc_temp_file_max_age_hours,
            "GC_MULTIPART_MAX_AGE_DAYS": self.gc_multipart_max_age_days,
            "GC_LOCK_FILE_MAX_AGE_HOURS": self.gc_lock_file_max_age_hours,
            "GC_DRY_RUN": self.gc_dry_run,
            "GC_IO_THROTTLE_MS": self.gc_io_throttle_ms,
            "INTEGRITY_ENABLED": self.integrity_enabled,
            "INTEGRITY_INTERVAL_HOURS": self.integrity_interval_hours,
            "INTEGRITY_BATCH_SIZE": self.integrity_batch_size,
            "INTEGRITY_AUTO_HEAL": self.integrity_auto_heal,
            "INTEGRITY_DRY_RUN": self.integrity_dry_run,
            "INTEGRITY_IO_THROTTLE_MS": self.integrity_io_throttle_ms,
        }
