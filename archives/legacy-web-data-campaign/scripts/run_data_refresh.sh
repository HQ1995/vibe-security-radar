#!/bin/sh

set -eu

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH= cd "$script_dir/.." && pwd -P)
python="$repo_root/cve-analyzer/.venv/bin/python"

if [ ! -x "$python" ]; then
    printf '%s\n' \
        "data refresh failed: synced interpreter is missing at $python" \
        "run: uv sync --project $repo_root/cve-analyzer --frozen" >&2
    exit 127
fi

# Keep the runner's own imports on the repository-bound virtualenv.  The
# analyzer child additionally uses Python isolated mode.
unset PYTHONHOME PYTHONPATH
export PYTHONNOUSERSITE=1

cd "$repo_root"
exec "$python" "$script_dir/run_data_refresh.py" "$@"
