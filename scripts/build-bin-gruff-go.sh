#!/usr/bin/env bash
# build-bin-gruff-go.sh - compile the gruff-go CLI to bin/gruff-go.
#
# Usage:
#   scripts/build-bin-gruff-go.sh
#
# Builds the cmd/gruff-go entrypoint into ./bin/gruff-go (the same path the
# README and docs/releasing.md document), then prints the resolved version so
# the human can confirm the freshly built binary is the one they expect.
#
# The build runs from REPO_ROOT regardless of the caller's working directory.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -t 1 ]]; then
  C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_RED=$'\033[31m'; C_OFF=$'\033[0m'
else
  C_GRN=""; C_YEL=""; C_RED=""; C_OFF=""
fi
log()  { printf '%s\n' "$*" >&2; }
ok()   { printf '%s%s%s\n' "$C_GRN" "$*" "$C_OFF" >&2; }
fail() { printf '%s%s%s\n' "$C_RED" "$*" "$C_OFF" >&2; exit 1; }

OUT="$REPO_ROOT/bin/gruff-go"
PKG="./cmd/gruff-go"

command -v go >/dev/null 2>&1 || fail "go toolchain not found on PATH"

cd "$REPO_ROOT"
log "Building $PKG -> $OUT"
go build -o "$OUT" "$PKG" || fail "go build failed"

ok "Built $OUT"
log "Version: $("$OUT" --version 2>/dev/null || printf '%s' "${C_YEL}--version unavailable${C_OFF}")"
