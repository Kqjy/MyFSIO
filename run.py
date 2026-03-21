"""Helper script to run the API server, UI server, or both."""
from __future__ import annotations

import argparse
import atexit
import os
import signal
import sys
import warnings
import multiprocessing
from multiprocessing import Process
from pathlib import Path

from dotenv import load_dotenv

for _env_file in [
    Path("/opt/myfsio/myfsio.env"),
    Path.cwd() / ".env",
    Path.cwd() / "myfsio.env",
]:
    if _env_file.exists():
        load_dotenv(_env_file, override=True)

from typing import Optional

from app import create_api_app, create_ui_app
from app.config import AppConfig
from app.iam import IamService, IamError, ALLOWED_ACTIONS, _derive_fernet_key


def _server_host() -> str:
    """Return the bind host for API and UI servers."""
    return os.getenv("APP_HOST", "0.0.0.0")


def _is_debug_enabled() -> bool:
    return os.getenv("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")


def _is_frozen() -> bool:
    """Check if running as a compiled binary (PyInstaller/Nuitka)."""
    return getattr(sys, 'frozen', False) or '__compiled__' in globals()


def _serve_granian(target: str, port: int, config: Optional[AppConfig] = None) -> None:
    from granian import Granian
    from granian.constants import Interfaces
    from granian.http import HTTP1Settings

    kwargs: dict = {
        "target": target,
        "address": _server_host(),
        "port": port,
        "interface": Interfaces.WSGI,
        "factory": True,
        "workers": 1,
    }

    if config:
        kwargs["blocking_threads"] = config.server_threads
        kwargs["backlog"] = config.server_backlog
        kwargs["backpressure"] = config.server_connection_limit
        kwargs["http1_settings"] = HTTP1Settings(
            header_read_timeout=config.server_channel_timeout * 1000,
            max_buffer_size=config.server_max_buffer_size,
        )
    else:
        kwargs["http1_settings"] = HTTP1Settings(
            max_buffer_size=1024 * 1024 * 128,
        )

    server = Granian(**kwargs)
    server.serve()


def serve_api(port: int, prod: bool = False, config: Optional[AppConfig] = None) -> None:
    if prod:
        _serve_granian("app:create_api_app", port, config)
    else:
        app = create_api_app()
        debug = _is_debug_enabled()
        if debug:
            warnings.warn("DEBUG MODE ENABLED - DO NOT USE IN PRODUCTION", RuntimeWarning)
        app.run(host=_server_host(), port=port, debug=debug)


def serve_ui(port: int, prod: bool = False, config: Optional[AppConfig] = None) -> None:
    if prod:
        _serve_granian("app:create_ui_app", port, config)
    else:
        app = create_ui_app()
        debug = _is_debug_enabled()
        if debug:
            warnings.warn("DEBUG MODE ENABLED - DO NOT USE IN PRODUCTION", RuntimeWarning)
        app.run(host=_server_host(), port=port, debug=debug)


def reset_credentials() -> None:
    import json
    import secrets
    from cryptography.fernet import Fernet

    config = AppConfig.from_env()
    iam_path = config.iam_config_path
    encryption_key = config.secret_key

    access_key = os.environ.get("ADMIN_ACCESS_KEY", "").strip() or secrets.token_hex(12)
    secret_key = os.environ.get("ADMIN_SECRET_KEY", "").strip() or secrets.token_urlsafe(32)
    custom_keys = bool(os.environ.get("ADMIN_ACCESS_KEY", "").strip())

    fernet = Fernet(_derive_fernet_key(encryption_key)) if encryption_key else None

    raw_config = None
    if iam_path.exists():
        try:
            raw_bytes = iam_path.read_bytes()
            from app.iam import _IAM_ENCRYPTED_PREFIX
            if raw_bytes.startswith(_IAM_ENCRYPTED_PREFIX):
                if fernet:
                    try:
                        content = fernet.decrypt(raw_bytes[len(_IAM_ENCRYPTED_PREFIX):]).decode("utf-8")
                        raw_config = json.loads(content)
                    except Exception:
                        print("WARNING: Could not decrypt existing IAM config. Creating fresh config.")
                else:
                    print("WARNING: IAM config is encrypted but no SECRET_KEY available. Creating fresh config.")
            else:
                try:
                    raw_config = json.loads(raw_bytes.decode("utf-8"))
                except json.JSONDecodeError:
                    print("WARNING: Existing IAM config is corrupted. Creating fresh config.")
        except OSError:
            pass

    if raw_config and raw_config.get("users"):
        is_v2 = raw_config.get("version", 1) >= 2
        admin_user = None
        for user in raw_config["users"]:
            policies = user.get("policies", [])
            for p in policies:
                actions = p.get("actions", [])
                if "iam:*" in actions or "*" in actions:
                    admin_user = user
                    break
            if admin_user:
                break
        if not admin_user:
            admin_user = raw_config["users"][0]

        if is_v2:
            admin_keys = admin_user.get("access_keys", [])
            if admin_keys:
                admin_keys[0]["access_key"] = access_key
                admin_keys[0]["secret_key"] = secret_key
            else:
                from datetime import datetime as _dt, timezone as _tz
                admin_user["access_keys"] = [{
                    "access_key": access_key,
                    "secret_key": secret_key,
                    "status": "active",
                    "created_at": _dt.now(_tz.utc).isoformat(),
                }]
        else:
            admin_user["access_key"] = access_key
            admin_user["secret_key"] = secret_key
    else:
        from datetime import datetime as _dt, timezone as _tz
        raw_config = {
            "version": 2,
            "users": [
                {
                    "user_id": f"u-{secrets.token_hex(8)}",
                    "display_name": "Local Admin",
                    "enabled": True,
                    "access_keys": [
                        {
                            "access_key": access_key,
                            "secret_key": secret_key,
                            "status": "active",
                            "created_at": _dt.now(_tz.utc).isoformat(),
                        }
                    ],
                    "policies": [
                        {"bucket": "*", "actions": list(ALLOWED_ACTIONS)}
                    ],
                }
            ]
        }

    json_text = json.dumps(raw_config, indent=2)
    iam_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = iam_path.with_suffix(".json.tmp")
    if fernet:
        from app.iam import _IAM_ENCRYPTED_PREFIX
        encrypted = fernet.encrypt(json_text.encode("utf-8"))
        temp_path.write_bytes(_IAM_ENCRYPTED_PREFIX + encrypted)
    else:
        temp_path.write_text(json_text, encoding="utf-8")
    temp_path.replace(iam_path)

    print(f"\n{'='*60}")
    print("MYFSIO - ADMIN CREDENTIALS RESET")
    print(f"{'='*60}")
    if custom_keys:
        print(f"Access Key: {access_key} (from ADMIN_ACCESS_KEY)")
        print(f"Secret Key: {'(from ADMIN_SECRET_KEY)' if os.environ.get('ADMIN_SECRET_KEY', '').strip() else secret_key}")
    else:
        print(f"Access Key: {access_key}")
        print(f"Secret Key: {secret_key}")
    print(f"{'='*60}")
    if fernet:
        print("IAM config saved (encrypted).")
    else:
        print(f"IAM config saved to: {iam_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    if _is_frozen():
        multiprocessing.set_start_method("spawn", force=True)

    parser = argparse.ArgumentParser(description="Run the S3 clone services.")
    parser.add_argument("--mode", choices=["api", "ui", "both", "reset-cred"], default="both")
    parser.add_argument("--api-port", type=int, default=5000)
    parser.add_argument("--ui-port", type=int, default=5100)
    parser.add_argument("--prod", action="store_true", help="Run in production mode using Granian")
    parser.add_argument("--dev", action="store_true", help="Force development mode (Flask dev server)")
    parser.add_argument("--check-config", action="store_true", help="Validate configuration and exit")
    parser.add_argument("--show-config", action="store_true", help="Show configuration summary and exit")
    parser.add_argument("--reset-cred", action="store_true", help="Reset admin credentials and exit")
    args = parser.parse_args()

    if args.reset_cred or args.mode == "reset-cred":
        reset_credentials()
        sys.exit(0)

    if args.check_config or args.show_config:
        config = AppConfig.from_env()
        config.print_startup_summary()
        if args.check_config:
            issues = config.validate_and_report()
            critical = [i for i in issues if i.startswith("CRITICAL:")]
            sys.exit(1 if critical else 0)
        sys.exit(0)

    prod_mode = args.prod or (_is_frozen() and not args.dev)
    
    config = AppConfig.from_env()
    
    first_run_marker = config.storage_root / ".myfsio.sys" / ".initialized"
    is_first_run = not first_run_marker.exists()
    
    if is_first_run:
        config.print_startup_summary()
        
        issues = config.validate_and_report()
        critical_issues = [i for i in issues if i.startswith("CRITICAL:")]
        if critical_issues:
            print("ABORTING: Critical configuration issues detected. Please fix them before starting.")
            sys.exit(1)
        
        try:
            first_run_marker.parent.mkdir(parents=True, exist_ok=True)
            first_run_marker.write_text(f"Initialized on {__import__('datetime').datetime.now().isoformat()}\n")
        except OSError:
            pass
    
    if prod_mode:
        print("Running in production mode (Granian)")
        issues = config.validate_and_report()
        critical_issues = [i for i in issues if i.startswith("CRITICAL:")]
        if critical_issues:
            for issue in critical_issues:
                print(f"  {issue}")
            print("ABORTING: Critical configuration issues detected. Please fix them before starting.")
            sys.exit(1)
    else:
        print("Running in development mode (Flask dev server)")

    if args.mode in {"api", "both"}:
        print(f"Starting API server on port {args.api_port}...")
        api_proc = Process(target=serve_api, args=(args.api_port, prod_mode, config))
        api_proc.start()
    else:
        api_proc = None

    def _cleanup_api():
        if api_proc and api_proc.is_alive():
            api_proc.terminate()
            api_proc.join(timeout=5)
            if api_proc.is_alive():
                api_proc.kill()

    if api_proc:
        atexit.register(_cleanup_api)
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    if args.mode in {"ui", "both"}:
        print(f"Starting UI server on port {args.ui_port}...")
        serve_ui(args.ui_port, prod_mode, config)
    elif api_proc:
        try:
            api_proc.join()
        except KeyboardInterrupt:
            pass
