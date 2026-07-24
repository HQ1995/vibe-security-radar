#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
python_bin="${repo_root}/cve-analyzer/.venv/bin/python"
runtime_root="${AI_SLOP_TEST_RUNTIME:-${repo_root}/.ai-slop/test-runtime/pytest}"

if [[ ! -x "${python_bin}" ]]; then
  echo "missing test interpreter: ${python_bin}" >&2
  exit 2
fi

mkdir -p -- "$(dirname -- "${runtime_root}")"
export TMPDIR="$(dirname -- "${runtime_root}")"
export PYTHONDONTWRITEBYTECODE=1

exec "${python_bin}" -m pytest --basetemp "${runtime_root}" "$@"
