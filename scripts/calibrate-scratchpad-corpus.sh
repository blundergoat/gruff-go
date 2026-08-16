#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  printf 'calibration-corpus: missing required tool: python3\n' >&2
  exit 2
fi

printf -v calibration_command '%q ' "$0" "$@"
export GRUFF_GO_CALIBRATION_COMMAND="${calibration_command% }"

exec python3 "$REPO_ROOT/scripts/calibration-corpus.py" "$@"
