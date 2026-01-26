from __future__ import annotations

import logging
import shutil
import sys
import time
import uuid
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import timedelta
from typing import Any, Dict, List, Optional

from flask import Flask, g, has_request_context, redirect, render_template, request, url_for
from flask_cors import CORS
from flask_wtf.csrf import CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix

from .access_logging import AccessLoggingService
from .operation_metrics import OperationMetricsCollector, classify_endpoint
from .compression import GzipMiddleware
from .acl import AclService
from .bucket_policies import BucketPolicyStore
from .config import AppConfig
from .connections import ConnectionStore
from .encryption import EncryptionManager
from .extensions import limiter, csrf
from .iam import IamService
from .kms import KMSManager
from .lifecycle import LifecycleManager
from .notifications import NotificationService
from .object_lock import ObjectLockService
from .replication import ReplicationManager
from .secret_store import EphemeralSecretStore
from .site_registry import SiteRegistry, SiteInfo
from .storage import ObjectStorage
from .version import get_version


def _migrate_config_file(active_path: Path, legacy_paths: List[Path]) -> Path:
    """Migrate config file from legacy locations to the active path.
    
    Checks each legacy path in order and moves the first one found to the active path.
    This ensures backward compatibility for users upgrading from older versions.
    """
    active_path.parent.mkdir(parents=True, exist_ok=True)
    
    if active_path.exists():
        return active_path
    
    for legacy_path in legacy_paths:
        if legacy_path.exists():
            try:
                shutil.move(str(legacy_path), str(active_path))
            except OSError:
                shutil.copy2(legacy_path, active_path)
                try:
                    legacy_path.unlink(missing_ok=True)
                except OSError:
                    pass
            break
    
    return active_path


def create_app(
    test_config: Optional[Dict[str, Any]] = None,
    *,
    include_api: bool = True,
    include_ui: bool = True,
) -> Flask:
    """Create and configure the Flask application."""
    config = AppConfig.from_env(test_config)

    if getattr(sys, "frozen", False):
        project_root = Path(sys._MEIPASS)
    else:
        project_root = Path(__file__).resolve().parent.parent

    app = Flask(
        __name__,
        static_folder=str(project_root / "static"),
        template_folder=str(project_root / "templates"),
    )
    app.config.update(config.to_flask_config())
    if test_config:
        app.config.update(test_config)
    app.config.setdefault("APP_VERSION", get_version())
    app.permanent_session_lifetime = timedelta(days=int(app.config.get("SESSION_LIFETIME_DAYS", 30)))
    if app.config.get("TESTING"):
        app.config.setdefault("WTF_CSRF_ENABLED", False)

    # Trust X-Forwarded-* headers from proxies
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Enable gzip compression for responses (10-20x smaller JSON payloads)
    if app.config.get("ENABLE_GZIP", True):
        app.wsgi_app = GzipMiddleware(app.wsgi_app, compression_level=6)

    _configure_cors(app)
    _configure_logging(app)

    limiter.init_app(app)
    csrf.init_app(app)

    storage = ObjectStorage(
        Path(app.config["STORAGE_ROOT"]),
        cache_ttl=app.config.get("OBJECT_CACHE_TTL", 5),
        object_cache_max_size=app.config.get("OBJECT_CACHE_MAX_SIZE", 100),
        bucket_config_cache_ttl=app.config.get("BUCKET_CONFIG_CACHE_TTL_SECONDS", 30.0),
        object_key_max_length_bytes=app.config.get("OBJECT_KEY_MAX_LENGTH_BYTES", 1024),
    )

    if app.config.get("WARM_CACHE_ON_STARTUP", True) and not app.config.get("TESTING"):
        storage.warm_cache_async()

    iam = IamService(
        Path(app.config["IAM_CONFIG"]),
        auth_max_attempts=app.config.get("AUTH_MAX_ATTEMPTS", 5),
        auth_lockout_minutes=app.config.get("AUTH_LOCKOUT_MINUTES", 15),
    )
    bucket_policies = BucketPolicyStore(Path(app.config["BUCKET_POLICY_PATH"]))
    secret_store = EphemeralSecretStore(default_ttl=app.config.get("SECRET_TTL_SECONDS", 300))
    
    storage_root = Path(app.config["STORAGE_ROOT"])
    config_dir = storage_root / ".myfsio.sys" / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    
    connections_path = _migrate_config_file(
        active_path=config_dir / "connections.json",
        legacy_paths=[
            storage_root / ".myfsio.sys" / "connections.json",
            storage_root / ".connections.json",
        ],
    )
    replication_rules_path = _migrate_config_file(
        active_path=config_dir / "replication_rules.json",
        legacy_paths=[
            storage_root / ".myfsio.sys" / "replication_rules.json",
            storage_root / ".replication_rules.json",
        ],
    )
    
    connections = ConnectionStore(connections_path)
    replication = ReplicationManager(
        storage,
        connections,
        replication_rules_path,
        storage_root,
        connect_timeout=app.config.get("REPLICATION_CONNECT_TIMEOUT_SECONDS", 5),
        read_timeout=app.config.get("REPLICATION_READ_TIMEOUT_SECONDS", 30),
        max_retries=app.config.get("REPLICATION_MAX_RETRIES", 2),
        streaming_threshold_bytes=app.config.get("REPLICATION_STREAMING_THRESHOLD_BYTES", 10 * 1024 * 1024),
        max_failures_per_bucket=app.config.get("REPLICATION_MAX_FAILURES_PER_BUCKET", 50),
    )

    site_registry_path = config_dir / "site_registry.json"
    site_registry = SiteRegistry(site_registry_path)
    if app.config.get("SITE_ID") and not site_registry.get_local_site():
        site_registry.set_local_site(SiteInfo(
            site_id=app.config["SITE_ID"],
            endpoint=app.config.get("SITE_ENDPOINT") or "",
            region=app.config.get("SITE_REGION", "us-east-1"),
            priority=app.config.get("SITE_PRIORITY", 100),
        ))

    encryption_config = {
        "encryption_enabled": app.config.get("ENCRYPTION_ENABLED", False),
        "encryption_master_key_path": app.config.get("ENCRYPTION_MASTER_KEY_PATH"),
        "default_encryption_algorithm": app.config.get("DEFAULT_ENCRYPTION_ALGORITHM", "AES256"),
        "encryption_chunk_size_bytes": app.config.get("ENCRYPTION_CHUNK_SIZE_BYTES", 64 * 1024),
    }
    encryption_manager = EncryptionManager(encryption_config)
    
    kms_manager = None
    if app.config.get("KMS_ENABLED", False):
        kms_keys_path = Path(app.config.get("KMS_KEYS_PATH", ""))
        kms_master_key_path = Path(app.config.get("ENCRYPTION_MASTER_KEY_PATH", ""))
        kms_manager = KMSManager(
            kms_keys_path,
            kms_master_key_path,
            generate_data_key_min_bytes=app.config.get("KMS_GENERATE_DATA_KEY_MIN_BYTES", 1),
            generate_data_key_max_bytes=app.config.get("KMS_GENERATE_DATA_KEY_MAX_BYTES", 1024),
        )
        encryption_manager.set_kms_provider(kms_manager)

    if app.config.get("ENCRYPTION_ENABLED", False):
        from .encrypted_storage import EncryptedObjectStorage
        storage = EncryptedObjectStorage(storage, encryption_manager)

    acl_service = AclService(storage_root)
    object_lock_service = ObjectLockService(storage_root)
    notification_service = NotificationService(storage_root)
    access_logging_service = AccessLoggingService(storage_root)
    access_logging_service.set_storage(storage)

    lifecycle_manager = None
    if app.config.get("LIFECYCLE_ENABLED", False):
        base_storage = storage.storage if hasattr(storage, 'storage') else storage
        lifecycle_manager = LifecycleManager(
            base_storage,
            interval_seconds=app.config.get("LIFECYCLE_INTERVAL_SECONDS", 3600),
            storage_root=storage_root,
            max_history_per_bucket=app.config.get("LIFECYCLE_MAX_HISTORY_PER_BUCKET", 50),
        )
        lifecycle_manager.start()

    app.extensions["object_storage"] = storage
    app.extensions["iam"] = iam
    app.extensions["bucket_policies"] = bucket_policies
    app.extensions["secret_store"] = secret_store
    app.extensions["limiter"] = limiter
    app.extensions["connections"] = connections
    app.extensions["replication"] = replication
    app.extensions["encryption"] = encryption_manager
    app.extensions["kms"] = kms_manager
    app.extensions["acl"] = acl_service
    app.extensions["lifecycle"] = lifecycle_manager
    app.extensions["object_lock"] = object_lock_service
    app.extensions["notifications"] = notification_service
    app.extensions["access_logging"] = access_logging_service
    app.extensions["site_registry"] = site_registry

    operation_metrics_collector = None
    if app.config.get("OPERATION_METRICS_ENABLED", False):
        operation_metrics_collector = OperationMetricsCollector(
            storage_root,
            interval_minutes=app.config.get("OPERATION_METRICS_INTERVAL_MINUTES", 5),
            retention_hours=app.config.get("OPERATION_METRICS_RETENTION_HOURS", 24),
        )
    app.extensions["operation_metrics"] = operation_metrics_collector

    system_metrics_collector = None
    if app.config.get("METRICS_HISTORY_ENABLED", False):
        from .system_metrics import SystemMetricsCollector
        system_metrics_collector = SystemMetricsCollector(
            storage_root,
            interval_minutes=app.config.get("METRICS_HISTORY_INTERVAL_MINUTES", 5),
            retention_hours=app.config.get("METRICS_HISTORY_RETENTION_HOURS", 24),
        )
        system_metrics_collector.set_storage(storage)
    app.extensions["system_metrics"] = system_metrics_collector

    site_sync_worker = None
    if app.config.get("SITE_SYNC_ENABLED", False):
        from .site_sync import SiteSyncWorker
        site_sync_worker = SiteSyncWorker(
            storage=storage,
            connections=connections,
            replication_manager=replication,
            storage_root=storage_root,
            interval_seconds=app.config.get("SITE_SYNC_INTERVAL_SECONDS", 60),
            batch_size=app.config.get("SITE_SYNC_BATCH_SIZE", 100),
            connect_timeout=app.config.get("SITE_SYNC_CONNECT_TIMEOUT_SECONDS", 10),
            read_timeout=app.config.get("SITE_SYNC_READ_TIMEOUT_SECONDS", 120),
            max_retries=app.config.get("SITE_SYNC_MAX_RETRIES", 2),
            clock_skew_tolerance_seconds=app.config.get("SITE_SYNC_CLOCK_SKEW_TOLERANCE_SECONDS", 1.0),
        )
        site_sync_worker.start()
    app.extensions["site_sync"] = site_sync_worker

    @app.errorhandler(500)
    def internal_error(error):
        return render_template('500.html'), 500

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return render_template('csrf_error.html', reason=e.description), 400

    @app.template_filter("filesizeformat")
    def filesizeformat(value: int) -> str:
        """Format bytes as human-readable file size."""
        for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
            if abs(value) < 1024.0 or unit == "PB":
                if unit == "B":
                    return f"{int(value)} {unit}"
                return f"{value:.1f} {unit}"
            value /= 1024.0
        return f"{value:.1f} PB"

    @app.template_filter("timestamp_to_datetime")
    def timestamp_to_datetime(value: float) -> str:
        """Format Unix timestamp as human-readable datetime in configured timezone."""
        from datetime import datetime, timezone as dt_timezone
        from zoneinfo import ZoneInfo
        if not value:
            return "Never"
        try:
            dt_utc = datetime.fromtimestamp(value, dt_timezone.utc)
            display_tz = app.config.get("DISPLAY_TIMEZONE", "UTC")
            if display_tz and display_tz != "UTC":
                try:
                    tz = ZoneInfo(display_tz)
                    dt_local = dt_utc.astimezone(tz)
                    return dt_local.strftime("%Y-%m-%d %H:%M:%S")
                except (KeyError, ValueError):
                    pass 
            return dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, OSError):
            return "Unknown"

    @app.template_filter("format_datetime")
    def format_datetime_filter(dt, include_tz: bool = True) -> str:
        """Format datetime object as human-readable string in configured timezone."""
        from datetime import datetime, timezone as dt_timezone
        from zoneinfo import ZoneInfo
        if not dt:
            return ""
        try:
            display_tz = app.config.get("DISPLAY_TIMEZONE", "UTC")
            if display_tz and display_tz != "UTC":
                try:
                    tz = ZoneInfo(display_tz)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=dt_timezone.utc)
                    dt = dt.astimezone(tz)
                except (KeyError, ValueError):
                    pass
            tz_abbr = dt.strftime("%Z") or "UTC"
            if include_tz:
                return f"{dt.strftime('%b %d, %Y %H:%M')} ({tz_abbr})"
            return dt.strftime("%b %d, %Y %H:%M")
        except (ValueError, AttributeError):
            return str(dt)

    if include_api:
        from .s3_api import s3_api_bp
        from .kms_api import kms_api_bp
        from .admin_api import admin_api_bp

        app.register_blueprint(s3_api_bp)
        app.register_blueprint(kms_api_bp)
        app.register_blueprint(admin_api_bp)
        csrf.exempt(s3_api_bp)
        csrf.exempt(kms_api_bp)
        csrf.exempt(admin_api_bp)

    if include_ui:
        from .ui import ui_bp

        app.register_blueprint(ui_bp)
        if not include_api:
            @app.get("/")
            def ui_root_redirect():
                return redirect(url_for("ui.buckets_overview"))

    @app.errorhandler(404)
    def handle_not_found(error):
        wants_html = request.accept_mimetypes.accept_html
        path = request.path or ""
        if include_ui and wants_html:
            if not include_api or path.startswith("/ui") or path == "/":
                return render_template("404.html"), 404
        return error

    @app.get("/myfsio/health")
    def healthcheck() -> Dict[str, str]:
        return {"status": "ok"}

    return app


def create_api_app(test_config: Optional[Dict[str, Any]] = None) -> Flask:
    return create_app(test_config, include_api=True, include_ui=False)


def create_ui_app(test_config: Optional[Dict[str, Any]] = None) -> Flask:
    return create_app(test_config, include_api=False, include_ui=True)


def _configure_cors(app: Flask) -> None:
    origins = app.config.get("CORS_ORIGINS", ["*"])
    methods = app.config.get("CORS_METHODS", ["GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD"])
    allow_headers = app.config.get("CORS_ALLOW_HEADERS", ["*"])
    expose_headers = app.config.get("CORS_EXPOSE_HEADERS", ["*"])
    CORS(
        app,
        resources={r"/*": {"origins": origins, "methods": methods, "allow_headers": allow_headers, "expose_headers": expose_headers}},
        supports_credentials=True,
    )


class _RequestContextFilter(logging.Filter):
    """Inject request-specific attributes into log records."""

    def filter(self, record: logging.LogRecord) -> bool:  
        if has_request_context():
            record.request_id = getattr(g, "request_id", "-")
            record.path = request.path
            record.method = request.method
            record.remote_addr = request.remote_addr or "-"
        else:
            record.request_id = getattr(record, "request_id", "-")
            record.path = getattr(record, "path", "-")
            record.method = getattr(record, "method", "-")
            record.remote_addr = getattr(record, "remote_addr", "-")
        return True


def _configure_logging(app: Flask) -> None:
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(request_id)s | %(method)s %(path)s | %(message)s"
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(_RequestContextFilter())

    logger = app.logger
    for handler in logger.handlers[:]:
        handler.close()
    logger.handlers.clear()
    logger.addHandler(stream_handler)

    if app.config.get("LOG_TO_FILE"):
        log_file = Path(app.config["LOG_FILE"])
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=int(app.config.get("LOG_MAX_BYTES", 5 * 1024 * 1024)),
            backupCount=int(app.config.get("LOG_BACKUP_COUNT", 3)),
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(_RequestContextFilter())
        logger.addHandler(file_handler)

    logger.setLevel(getattr(logging, app.config.get("LOG_LEVEL", "INFO"), logging.INFO))

    @app.before_request
    def _log_request_start() -> None:
        g.request_id = uuid.uuid4().hex
        g.request_started_at = time.perf_counter()
        g.request_bytes_in = request.content_length or 0
        app.logger.info(
            "Request started",
            extra={"path": request.path, "method": request.method, "remote_addr": request.remote_addr},
        )

    @app.after_request
    def _log_request_end(response):
        duration_ms = 0.0
        if hasattr(g, "request_started_at"):
            duration_ms = (time.perf_counter() - g.request_started_at) * 1000
        request_id = getattr(g, "request_id", uuid.uuid4().hex)
        response.headers.setdefault("X-Request-ID", request_id)
        app.logger.info(
            "Request completed",
            extra={
                "path": request.path,
                "method": request.method,
                "remote_addr": request.remote_addr,
            },
        )
        response.headers["X-Request-Duration-ms"] = f"{duration_ms:.2f}"

        operation_metrics = app.extensions.get("operation_metrics")
        if operation_metrics:
            bytes_in = getattr(g, "request_bytes_in", 0)
            bytes_out = response.content_length or 0
            error_code = getattr(g, "s3_error_code", None)
            endpoint_type = classify_endpoint(request.path)
            operation_metrics.record_request(
                method=request.method,
                endpoint_type=endpoint_type,
                status_code=response.status_code,
                latency_ms=duration_ms,
                bytes_in=bytes_in,
                bytes_out=bytes_out,
                error_code=error_code,
            )

        return response
