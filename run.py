"""Helper script to run the API server, UI server, or both."""
from __future__ import annotations

import argparse
import os
import sys
import warnings
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


def _server_host() -> str:
    """Return the bind host for API and UI servers."""
    return os.getenv("APP_HOST", "0.0.0.0")


def _is_debug_enabled() -> bool:
    return os.getenv("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")


def _is_frozen() -> bool:
    """Check if running as a compiled binary (PyInstaller/Nuitka)."""
    return getattr(sys, 'frozen', False) or '__compiled__' in globals()


def serve_api(port: int, prod: bool = False, config: Optional[AppConfig] = None) -> None:
    app = create_api_app()
    if prod:
        from waitress import serve
        if config:
            serve(
                app,
                host=_server_host(),
                port=port,
                ident="MyFSIO",
                threads=config.server_threads,
                connection_limit=config.server_connection_limit,
                backlog=config.server_backlog,
                channel_timeout=config.server_channel_timeout,
            )
        else:
            serve(app, host=_server_host(), port=port, ident="MyFSIO")
    else:
        debug = _is_debug_enabled()
        if debug:
            warnings.warn("DEBUG MODE ENABLED - DO NOT USE IN PRODUCTION", RuntimeWarning)
        app.run(host=_server_host(), port=port, debug=debug)


def serve_ui(port: int, prod: bool = False, config: Optional[AppConfig] = None) -> None:
    app = create_ui_app()
    if prod:
        from waitress import serve
        if config:
            serve(
                app,
                host=_server_host(),
                port=port,
                ident="MyFSIO",
                threads=config.server_threads,
                connection_limit=config.server_connection_limit,
                backlog=config.server_backlog,
                channel_timeout=config.server_channel_timeout,
            )
        else:
            serve(app, host=_server_host(), port=port, ident="MyFSIO")
    else:
        debug = _is_debug_enabled()
        if debug:
            warnings.warn("DEBUG MODE ENABLED - DO NOT USE IN PRODUCTION", RuntimeWarning)
        app.run(host=_server_host(), port=port, debug=debug)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the S3 clone services.")
    parser.add_argument("--mode", choices=["api", "ui", "both"], default="both")
    parser.add_argument("--api-port", type=int, default=5000)
    parser.add_argument("--ui-port", type=int, default=5100)
    parser.add_argument("--prod", action="store_true", help="Run in production mode using Waitress")
    parser.add_argument("--dev", action="store_true", help="Force development mode (Flask dev server)")
    parser.add_argument("--check-config", action="store_true", help="Validate configuration and exit")
    parser.add_argument("--show-config", action="store_true", help="Show configuration summary and exit")
    args = parser.parse_args()

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
        print("Running in production mode (Waitress)")
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
        api_proc = Process(target=serve_api, args=(args.api_port, prod_mode, config), daemon=True)
        api_proc.start()
    else:
        api_proc = None

    if args.mode in {"ui", "both"}:
        print(f"Starting UI server on port {args.ui_port}...")
        serve_ui(args.ui_port, prod_mode, config)
    elif api_proc:
        try:
            api_proc.join()
        except KeyboardInterrupt:
            pass
