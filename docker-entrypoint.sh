#!/bin/sh
set -e

# Start API server in background
gunicorn "app:create_api_app()" --bind 0.0.0.0:5000 --workers 4 --access-logfile - &

# Start UI server in foreground
gunicorn "app:create_ui_app()" --bind 0.0.0.0:5100 --workers 4 --access-logfile -
