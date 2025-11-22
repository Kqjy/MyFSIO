#!/bin/sh
set -e

# Run both services using the python runner in production mode
exec python run.py --prod
