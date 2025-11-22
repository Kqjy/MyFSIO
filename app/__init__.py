"""Application factory for the mini S3-compatible object store."""
from __future__ import annotations

import logging
import time
import uuid
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import timedelta
from typing import Any, Dict, Optional

from flask import Flask, g, has_request_context, redirect, render_template, request, url_for
from flask_cors import CORS
from flask_wtf.csrf import CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix

from .bucket_policies import BucketPolicyStore
from .config import AppConfig
from .connections import ConnectionStore
from .extensions import limiter, csrf
from .iam import IamService
from .replication import ReplicationManager
from .secret_store import EphemeralSecretStore
from .storage import ObjectStorage
from .version import get_version


def create_app(
    test_config: Optional[Dict[str, Any]] = None,
    *,
    include_api: bool = True,
    include_ui: bool = True,
) -> Flask:
    """Create and configure the Flask application."""
    config = AppConfig.from_env(test_config)

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

    _configure_cors(app)
    _configure_logging(app)

    limiter.init_app(app)
    csrf.init_app(app)

    storage = ObjectStorage(Path(app.config["STORAGE_ROOT"]))
    iam = IamService(
        Path(app.config["IAM_CONFIG"]),
        auth_max_attempts=app.config.get("AUTH_MAX_ATTEMPTS", 5),
        auth_lockout_minutes=app.config.get("AUTH_LOCKOUT_MINUTES", 15),
    )
    bucket_policies = BucketPolicyStore(Path(app.config["BUCKET_POLICY_PATH"]))
    secret_store = EphemeralSecretStore(default_ttl=app.config.get("SECRET_TTL_SECONDS", 300))
    
    # Initialize Replication components
    connections_path = Path(app.config["STORAGE_ROOT"]) / ".connections.json"
    replication_rules_path = Path(app.config["STORAGE_ROOT"]) / ".replication_rules.json"
    
    connections = ConnectionStore(connections_path)
    replication = ReplicationManager(storage, connections, replication_rules_path)

    app.extensions["object_storage"] = storage
    app.extensions["iam"] = iam
    app.extensions["bucket_policies"] = bucket_policies
    app.extensions["secret_store"] = secret_store
    app.extensions["limiter"] = limiter
    app.extensions["connections"] = connections
    app.extensions["replication"] = replication

    @app.after_request
    def set_server_header(response):
        response.headers["Server"] = "MyFSIO"
        return response

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

    if include_api:
        from .s3_api import s3_api_bp

        app.register_blueprint(s3_api_bp)
        csrf.exempt(s3_api_bp)

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

    @app.get("/healthz")
    def healthcheck() -> Dict[str, str]:
        return {"status": "ok", "version": app.config.get("APP_VERSION", "unknown")}

    return app


def create_api_app(test_config: Optional[Dict[str, Any]] = None) -> Flask:
    return create_app(test_config, include_api=True, include_ui=False)


def create_ui_app(test_config: Optional[Dict[str, Any]] = None) -> Flask:
    return create_app(test_config, include_api=False, include_ui=True)


def _configure_cors(app: Flask) -> None:
    origins = app.config.get("CORS_ORIGINS", ["*"])
    methods = app.config.get("CORS_METHODS", ["GET", "PUT", "POST", "DELETE", "OPTIONS"])
    allow_headers = app.config.get(
        "CORS_ALLOW_HEADERS",
        ["Content-Type", "X-Access-Key", "X-Secret-Key", "X-Amz-Date", "X-Amz-SignedHeaders"],
    )
    CORS(
        app,
        resources={r"/*": {"origins": origins, "methods": methods, "allow_headers": allow_headers}},
        supports_credentials=True,
    )


class _RequestContextFilter(logging.Filter):
    """Inject request-specific attributes into log records."""

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - simple boilerplate
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
    log_file = Path(app.config["LOG_FILE"])
    log_file.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        log_file,
        maxBytes=int(app.config.get("LOG_MAX_BYTES", 5 * 1024 * 1024)),
        backupCount=int(app.config.get("LOG_BACKUP_COUNT", 3)),
        encoding="utf-8",
    )
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(request_id)s | %(method)s %(path)s | %(message)s"
    )
    handler.setFormatter(formatter)
    handler.addFilter(_RequestContextFilter())

    logger = app.logger
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, app.config.get("LOG_LEVEL", "INFO"), logging.INFO))

    @app.before_request
    def _log_request_start() -> None:
        g.request_id = uuid.uuid4().hex
        g.request_started_at = time.perf_counter()
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
        response.headers["Server"] = "MyFISO"
        return response
