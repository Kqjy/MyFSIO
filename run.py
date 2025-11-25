"""Helper script to run the API server, UI server, or both."""
from __future__ import annotations

import argparse
import os
import sys
import warnings
from multiprocessing import Process

from app import create_api_app, create_ui_app


def _server_host() -> str:
    """Return the bind host for API and UI servers."""
    return os.getenv("APP_HOST", "0.0.0.0")


def _is_debug_enabled() -> bool:
    return os.getenv("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")


def _is_frozen() -> bool:
    """Check if running as a compiled binary (PyInstaller/Nuitka)."""
    return getattr(sys, 'frozen', False) or '__compiled__' in globals()


def serve_api(port: int, prod: bool = False) -> None:
    app = create_api_app()
    if prod:
        from waitress import serve
        serve(app, host=_server_host(), port=port, ident="MyFSIO")
    else:
        debug = _is_debug_enabled()
        if debug:
            warnings.warn("DEBUG MODE ENABLED - DO NOT USE IN PRODUCTION", RuntimeWarning)
        app.run(host=_server_host(), port=port, debug=debug)


def serve_ui(port: int, prod: bool = False) -> None:
    app = create_ui_app()
    if prod:
        from waitress import serve
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
    args = parser.parse_args()

    # Default to production mode when running as compiled binary
    # unless --dev is explicitly passed
    prod_mode = args.prod or (_is_frozen() and not args.dev)
    
    if prod_mode:
        print("Running in production mode (Waitress)")
    else:
        print("Running in development mode (Flask dev server)")

    if args.mode in {"api", "both"}:
        print(f"Starting API server on port {args.api_port}...")
        api_proc = Process(target=serve_api, args=(args.api_port, prod_mode), daemon=True)
        api_proc.start()
    else:
        api_proc = None

    if args.mode in {"ui", "both"}:
        print(f"Starting UI server on port {args.ui_port}...")
        serve_ui(args.ui_port, prod_mode)
    elif api_proc:
        try:
            api_proc.join()
        except KeyboardInterrupt:
            pass
