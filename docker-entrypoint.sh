#!/bin/sh
set -e

ENGINE="${ENGINE:-rust}"

exec python run.py --prod --engine "$ENGINE"
