#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS_ROOT="${GRUFF_GO_CALIBRATION_CORPUS:-$REPO_ROOT/.goat-flow/scratchpad/scan-test-repos}"
BIN="${GRUFF_GO_CALIBRATION_BIN:-/tmp/gruff-go-calibration}"

log() {
  printf '%s\n' "$*" >&2
}

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'calibration-corpus: missing required tool: %s\n' "$tool" >&2
    exit 2
  fi
}

build_binary() {
  log "building gruff-go calibration binary at $BIN"
  (cd "$REPO_ROOT" && go build -o "$BIN" ./cmd/gruff-go)
}

enumerate_modules() {
  if command -v rg >/dev/null 2>&1; then
    printf 'enumerator=rg\n'
    rg --files --hidden --no-ignore "$CORPUS_ROOT" -g go.mod | sort
    return
  fi
  printf 'enumerator=find\n'
  find "$CORPUS_ROOT" -name go.mod -type f | sort
}

scan_module() {
  local module_root="$1" rel project module tmp status start end
  rel="${module_root#"$CORPUS_ROOT"/}"
  project="${rel%%/*}"
  if [[ "$rel" == "$project" ]]; then
    module="."
  else
    module="${rel#"$project"/}"
  fi

  tmp="$(mktemp)"
  start="$(date +%s%N)"
  set +e
  (cd "$module_root" && "$BIN" analyse --format json --no-config . >"$tmp")
  status=$?
  set -e
  end="$(date +%s%N)"

  if (( status > 1 )); then
    rm -f "$tmp"
    printf 'calibration-corpus: scanner crashed for %s/%s with exit %d\n' "$project" "$module" "$status" >&2
    exit "$status"
  fi

  python3 - "$tmp" "$project" "$module" "$start" "$end" <<'PY'
import collections
import json
import sys

path, project, module = sys.argv[1], sys.argv[2], sys.argv[3]
started, ended = int(sys.argv[4]), int(sys.argv[5])
try:
    with open(path, "r", encoding="utf-8") as fh:
        report = json.load(fh)
except Exception as exc:
    print(f"calibration-corpus: unreadable JSON for {project}/{module}: {exc}", file=sys.stderr)
    sys.exit(2)

summary = report.get("summary", {})
score = report.get("score", {})
findings = report.get("findings", [])
counts = collections.Counter(item.get("ruleId", "<missing>") for item in findings)
top_rules = ";".join(f"{rule}={count}" for rule, count in counts.most_common(5)) or "-"
seconds = f"{(ended - started) / 1_000_000_000:.2f}"
print(
    f"project={project} module={module} "
    f"files={summary.get('filesScanned', 0)} "
    f"skipped={summary.get('filesSkipped', 0)} "
    f"findings={summary.get('findingsCount', len(findings))} "
    f"grade={score.get('grade', 'n/a')} "
    f"seconds={seconds} top_rules={top_rules}"
)
PY
  rm -f "$tmp"
}

main() {
  require_tool go
  require_tool python3

  if [[ ! -d "$CORPUS_ROOT" ]]; then
    printf 'calibration-corpus: skipped (%s not present)\n' "$CORPUS_ROOT"
    exit 0
  fi

  build_binary

  mapfile -t module_entries < <(enumerate_modules)
  local enumerator="${module_entries[0]#enumerator=}"
  local modules=("${module_entries[@]:1}")
  printf 'calibration-corpus=%s\n' "$CORPUS_ROOT"
  printf 'enumerator=%s\n' "$enumerator"
  printf 'project,module,files,skipped,findings,grade,seconds,top_rules\n'

  local go_mod module_root
  for go_mod in "${modules[@]}"; do
    module_root="$(dirname "$go_mod")"
    scan_module "$module_root"
  done
}

main "$@"
