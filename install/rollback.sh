#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 -I -B "${SCRIPT_DIR}/../scripts/council_lifecycle.py" rollback "$@"
