#!/bin/sh
set -e

# Start API server in background
waitress-serve --ident=MyFSIO --listen=*:5000 --call app:create_api_app &

# Start UI server in foreground
waitress-serve --ident=MyFSIO --listen=*:5100 --call app:create_ui_app
