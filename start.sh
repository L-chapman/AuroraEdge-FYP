#!/bin/sh
# Run with `sh ./start.sh`; no executable-bit change is required.
set -eu
launch_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${NORTHFLUX_PYTHON:-}" ]; then
    exec "$NORTHFLUX_PYTHON" "$launch_dir/start.py" "$@"
fi
if command -v python3 >/dev/null 2>&1; then
    exec python3 "$launch_dir/start.py" "$@"
fi
printf '%s\n' '[ERROR] Install Python 3.10 or newer, including its venv package, then try again.' >&2
exit 1
