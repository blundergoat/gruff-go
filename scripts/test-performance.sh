#!/usr/bin/env bash
# test-performance.sh - benchmark the gruff-go analyser end-to-end.
#
# Modes:
#   --smoke         (M1) one timed pass over the repo itself, prints elapsed + counts
#   --matrix        (M2) hyperfine over self + synthetic-medium + synthetic-large
#   --sweep         (M3) format x rule-set x pathological inputs; peak RSS captured
#   --compare       (M4) compare against scripts/.perf-results/baseline.json
#   --baseline-update (M4) overwrite baseline with current run
#   --ci            (M4) stricter regression tolerances and compact output
#   --all           run --smoke, --matrix, --sweep in that order
#
# Defaults to --smoke when no mode flag is given.

set -euo pipefail

# ---------- paths anchored at repo root ----------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$REPO_ROOT/bin/gruff-go"
RESULTS_DIR="$SCRIPT_DIR/.perf-results"
CORPUS_DIR="$SCRIPT_DIR/.perf-corpus"
BASELINE_FILE="$RESULTS_DIR/baseline.json"
HYPERFINE=""  # populated by preflight when needed

# Regression tolerances (per-corpus wall %, per-rule wall %). --ci tightens them.
REGRESSION_CORPUS_PCT=20
REGRESSION_RULE_PCT=50

# Run counts handed to hyperfine.
HYPERFINE_WARMUP=1
HYPERFINE_MIN_RUNS=5

# Pathological-cell timeout (seconds).
SWEEP_CELL_TIMEOUT=60

# Synthetic corpus sizes (file counts).
MEDIUM_FILES=500
LARGE_FILES=5000

# Deterministic generator seed - changing this invalidates the baseline.
CORPUS_SEED=20260517

# ---------- ui helpers ----------
if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_DIM=""; C_OFF=""
fi
log()  { printf '%s\n' "$*" >&2; }
ok()   { printf '%s%s%s\n' "$C_GRN" "$*" "$C_OFF" >&2; }
warn() { printf '%s%s%s\n' "$C_YEL" "$*" "$C_OFF" >&2; }
fail() { printf '%s%s%s\n' "$C_RED" "$*" "$C_OFF" >&2; exit 1; }

# ---------- hyperfine bootstrap ----------
HF_VERSION="v1.20.0"
HF_TOOLS_DIR="$SCRIPT_DIR/.tools"
HF_LOCAL="$HF_TOOLS_DIR/hyperfine"
# Pinned SHA-256 per platform tarball. Update these when bumping HF_VERSION.
HF_SHA_linux_x86_64="63ad53934062118f5b0be11785e0bb1603d4b91667d1921f2fd8df9a8712040a"
HF_SHA_linux_aarch64="90875cb1db7a1d797c311174d061728361e58fc70e3b62262a00635ac3b1997c"
HF_SHA_darwin_x86_64="f58d0b90993fadfa122a351428c469ce24afef3865f027f0e6e86f0830d088f1"
HF_SHA_darwin_aarch64="8ee7067016620447c9d2d6234ec9a4680f958b7ad983549b56334668f63075b5"

detect_platform_asset() {
  # echoes "<asset-stem> <sha256>"; fails if platform unsupported.
  local os arch sha asset
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "$os/$arch" in
    linux/x86_64)    asset="hyperfine-${HF_VERSION}-x86_64-unknown-linux-gnu";    sha="$HF_SHA_linux_x86_64" ;;
    linux/aarch64|linux/arm64)
                      asset="hyperfine-${HF_VERSION}-aarch64-unknown-linux-gnu";   sha="$HF_SHA_linux_aarch64" ;;
    darwin/x86_64)   asset="hyperfine-${HF_VERSION}-x86_64-apple-darwin";          sha="$HF_SHA_darwin_x86_64" ;;
    darwin/arm64|darwin/aarch64)
                      asset="hyperfine-${HF_VERSION}-aarch64-apple-darwin";        sha="$HF_SHA_darwin_aarch64" ;;
    *) fail "no pinned hyperfine binary for $os/$arch. install hyperfine manually and put it on PATH." ;;
  esac
  printf '%s %s\n' "$asset" "$sha"
}

bootstrap_hyperfine() {
  # Echoes the path to a working hyperfine binary.
  if command -v hyperfine >/dev/null 2>&1; then
    command -v hyperfine
    return 0
  fi
  if [[ -x "$HF_LOCAL" ]]; then
    printf '%s\n' "$HF_LOCAL"
    return 0
  fi

  command -v curl >/dev/null || fail "curl is required to bootstrap hyperfine"
  command -v sha256sum >/dev/null || command -v shasum >/dev/null \
    || fail "sha256sum or shasum is required to verify the hyperfine download"

  local asset sha
  read -r asset sha < <(detect_platform_asset)
  local url="https://github.com/sharkdp/hyperfine/releases/download/${HF_VERSION}/${asset}.tar.gz"
  local tmp; tmp=$(mktemp -d)
  log "${C_DIM}fetching ${asset} ...${C_OFF}"
  if ! curl -fsSL -o "$tmp/hf.tar.gz" "$url"; then
    rm -rf "$tmp"
    fail "failed to download $url"
  fi
  local got
  if command -v sha256sum >/dev/null; then
    got=$(sha256sum "$tmp/hf.tar.gz" | awk '{print $1}')
  else
    got=$(shasum -a 256 "$tmp/hf.tar.gz" | awk '{print $1}')
  fi
  if [[ "$got" != "$sha" ]]; then
    rm -rf "$tmp"
    fail "hyperfine sha256 mismatch (expected $sha, got $got) - refusing to install"
  fi
  mkdir -p "$HF_TOOLS_DIR"
  tar -xzf "$tmp/hf.tar.gz" -C "$tmp"
  cp "$tmp/${asset}/hyperfine" "$HF_LOCAL"
  chmod +x "$HF_LOCAL"
  rm -rf "$tmp"
  log "${C_DIM}installed hyperfine ${HF_VERSION} -> $HF_LOCAL${C_OFF}"
  printf '%s\n' "$HF_LOCAL"
}

# ---------- preflight ----------
preflight() {
  # $1: "needs_hyperfine" if any mode other than smoke is requested
  local need_hf="${1:-}"
  if [[ ! -x "$BIN" ]]; then
    log "${C_DIM}building $BIN ...${C_OFF}"
    (cd "$REPO_ROOT" && go build -o "$BIN" ./cmd/gruff-go) || fail "go build failed"
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required for result parsing"
  fi

  if [[ "$need_hf" == "needs_hyperfine" ]]; then
    HYPERFINE=$(bootstrap_hyperfine)
    if ! /usr/bin/time -v true 2>/dev/null; then
      warn "GNU /usr/bin/time -v not available; peak RSS will be omitted from --sweep"
    fi
  fi

  mkdir -p "$RESULTS_DIR" "$CORPUS_DIR"
}

# ---------- M1: smoke ----------
run_smoke() {
  log ""
  log "== smoke =="
  local start_ns end_ns elapsed_ms summary_file
  summary_file=$(mktemp)
  trap 'rm -f "$summary_file"' RETURN
  start_ns=$(date +%s%N)
  # gruff-go discovers .gruff-go.yaml from cwd, so cd into the repo for realism.
  (cd "$REPO_ROOT" && "$BIN" analyse --format summary-json .) > "$summary_file"
  end_ns=$(date +%s%N)
  elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

  python3 - "$elapsed_ms" "$summary_file" <<'PY'
import json, sys
elapsed_ms = int(sys.argv[1])
d = json.load(open(sys.argv[2]))
s = d["summary"]
print(f"elapsed_ms = {elapsed_ms}")
print(f"files_scanned = {s['filesScanned']}")
print(f"files_skipped = {s['filesSkipped']}")
print(f"findings = {s['findingsCount']}")
print(f"score = {d['score']['composite']} ({d['score']['grade']})")
PY
  ok "smoke OK"
}

# ---------- M2: corpus generator (deterministic) ----------
ensure_corpus() {
  local target="$1" count="$2" stamp_file
  stamp_file="$target/.stamp-${CORPUS_SEED}-${count}"
  if [[ -f "$stamp_file" ]]; then
    return 0
  fi
  log "${C_DIM}generating $count-file corpus at $target ...${C_OFF}"
  rm -rf "$target"
  mkdir -p "$target"
  python3 - "$target" "$count" "$CORPUS_SEED" <<'PY'
import os, random, sys
target, count, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rng = random.Random(seed)

# Shape distribution: 70% small (10-40 lines), 25% medium (60-150), 5% large (200-400).
def pick_shape():
    r = rng.random()
    if r < 0.70: return rng.randint(10, 40)
    if r < 0.95: return rng.randint(60, 150)
    return rng.randint(200, 400)

PKG_PER_DIR = 25
for i in range(count):
    pkg_idx = i // PKG_PER_DIR
    pkg_dir = os.path.join(target, f"pkg{pkg_idx:04d}")
    os.makedirs(pkg_dir, exist_ok=True)
    lines = pick_shape()
    path = os.path.join(pkg_dir, f"f{i:05d}.go")
    with open(path, "w") as fh:
        fh.write(f"// Package pkg{pkg_idx:04d} is part of the synthetic perf corpus.\n")
        fh.write(f"package pkg{pkg_idx:04d}\n\n")
        # one function per file, body filled with statements
        fh.write(f"func F{i:05d}(x int) int {{\n")
        for _ in range(lines - 4):
            fh.write("\tx++\n")
        fh.write("\treturn x\n")
        fh.write("}\n")

# go.mod so analyse treats it as one project.
with open(os.path.join(target, "go.mod"), "w") as fh:
    fh.write("module example.com/perfcorpus\n\ngo 1.25.0\n")
PY
  : > "$stamp_file"
}

hyperfine_run() {
  # $1: label (becomes JSON path stem); $2: workdir; $3..: command (single string).
  # Runs the command with cwd=$workdir so gruff-go finds the right .gitignore.
  local label="$1" workdir="$2"; shift 2
  local out_json="$RESULTS_DIR/raw-${label}.json"
  # hyperfine doesn't have a --cwd flag; wrap the command in a cd subshell.
  # We use bash -c so we can express the cd; --shell=none disabled here intentionally.
  # -i: gruff-go returns 1 when findings exist (working as designed); we time the
  # complete run regardless. The script's own correctness checks happen elsewhere.
  "$HYPERFINE" -i \
    --warmup "$HYPERFINE_WARMUP" \
    --min-runs "$HYPERFINE_MIN_RUNS" \
    --export-json "$out_json" \
    --command-name "$label" \
    -- "cd '$workdir' && $*" >/dev/null
  printf '%s\n' "$out_json"
}

corpus_metrics() {
  # Asks gruff itself how many files it actually scans (post-gitignore, post-built-in
  # filters). Echoes "<files> <kloc>". KLOC is approximated by line-counting just
  # the files gruff scanned would be expensive; we approximate via wc -l on tracked
  # .go files within the path. Close enough for throughput display.
  local target="$1" summary_file
  summary_file=$(mktemp)
  (cd "$target" && "$BIN" analyse --no-config --format summary-json . 2>/dev/null > "$summary_file") || true
  local files; files=$(python3 -c "import json; print(json.load(open('$summary_file'))['summary']['filesScanned'])")
  rm -f "$summary_file"
  # Approximate KLOC from the scanned files. We re-walk and count just .go (most
  # accurate would be parsing the report, but it doesn't carry per-file linecounts).
  local lines; lines=$(find "$target" -name "*.go" -not -path '*/node_modules/*' -not -path '*/.goat-flow/*' -print0 2>/dev/null | xargs -0 wc -l 2>/dev/null | tail -1 | awk '{print $1}')
  : "${lines:=0}"
  python3 -c "print(f'$files {$lines/1000:.2f}')"
}

run_matrix() {
  log ""
  log "== matrix =="
  ensure_corpus "$CORPUS_DIR/medium" "$MEDIUM_FILES"
  ensure_corpus "$CORPUS_DIR/large" "$LARGE_FILES"

  # For apples-to-apples timing we use --no-config on every corpus so the same
  # default-enabled rule set runs everywhere. Self timing reads its own .gruff-go.yaml
  # under --smoke; matrix is for cross-corpus comparison.
  local rows=()
  for entry in "self:$REPO_ROOT" "medium:$CORPUS_DIR/medium" "large:$CORPUS_DIR/large"; do
    local name="${entry%%:*}" path="${entry#*:}"
    log "${C_DIM}timing $name ($path) ...${C_OFF}"
    local raw
    raw=$(hyperfine_run "matrix-$name" "$path" "$BIN analyse --no-config --format summary-json .")
    local metrics; metrics=$(corpus_metrics "$path")
    rows+=("$name|$raw|$metrics")
  done

  python3 - <<PY
import json
rows = """${rows[*]}""".strip().split("\n") if """${rows[*]}""" else []
# bash array joined by space; split on '|' triples manually
raw = """${rows[*]}"""
# Re-parse: we passed rows separated by spaces; cells separated by '|'.
entries = []
for chunk in raw.split():
    pass
PY
  # The above python heredoc parsing is fragile; do it in bash instead:
  printf '\n%-8s  %12s  %12s  %12s  %10s  %12s\n' \
    "corpus" "median_ms" "p95_ms" "stddev_ms" "files" "files_per_s"
  printf '%s\n' "--------  ------------  ------------  ------------  ----------  ------------"
  for row in "${rows[@]}"; do
    local name raw metrics files kloc
    name="${row%%|*}"
    raw="${row#*|}"; raw="${raw%%|*}"
    metrics="${row##*|}"
    files="${metrics%% *}"; kloc="${metrics##* }"
    python3 - "$name" "$raw" "$files" "$kloc" <<'PY'
import json, sys
name, raw, files, kloc = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
d = json.load(open(raw))
times = sorted(d["results"][0]["times"])  # seconds
median = times[len(times)//2] * 1000
p95 = times[min(len(times)-1, int(round(0.95*(len(times)-1))))] * 1000
stddev = d["results"][0]["stddev"] * 1000
files_per_s = files / (median/1000) if median > 0 else 0
print(f"{name:<8}  {median:12.1f}  {p95:12.1f}  {stddev:12.1f}  {files:10d}  {files_per_s:12.1f}")
PY
  done
  ok "matrix OK"
}

# ---------- M3: dimensional sweep ----------
peak_rss_kb() {
  # Runs the given command and prints peak RSS in KB (or "-" if unavailable).
  if /usr/bin/time -v true >/dev/null 2>&1; then
    /usr/bin/time -v -- "$@" 2>&1 >/dev/null \
      | awk '/Maximum resident set size/ {print $NF; found=1} END{if(!found) print "-"}'
  else
    printf '%s\n' "-"
  fi
}

list_rules() {
  "$BIN" list-rules 2>/dev/null | awk -F'\t' '{print $1}'
}

write_single_rule_config() {
  # $1: output path; $2: rule id
  printf 'selection:\n  rules:\n    - %s\n' "$2" > "$1"
}

run_sweep() {
  log ""
  log "== sweep =="
  ensure_corpus "$CORPUS_DIR/medium" "$MEDIUM_FILES"
  local timestamp; timestamp=$(date -u +%Y%m%dT%H%M%SZ)
  local sweep_out="$RESULTS_DIR/sweep-$timestamp.json"
  local rows_json="["
  # Per-run stash file. The previous shared /tmp/gruff-sweep-stash.jsonl was
  # appended-to across runs, so an aborted sweep (or two concurrent runs)
  # poisoned the next aggregation with stale rows. Scope the file to this run
  # and remove it via trap so the next sweep always starts clean.
  local sweep_stash; sweep_stash=$(mktemp "$RESULTS_DIR/sweep-stash-XXXXXX.jsonl")
  # Expand sweep_stash now, not at trap time, so the path is captured.
  # shellcheck disable=SC2064
  trap "rm -f '$sweep_stash'" RETURN

  # ----- formats -----
  log "${C_DIM}-- formats --${C_OFF}"
  printf '\n%-14s  %12s  %12s  %12s\n' "format" "median_ms" "stddev_ms" "rss_kb"
  printf '%s\n' "--------------  ------------  ------------  ------------"
  for fmt in summary-json text json sarif html; do
    local raw; raw=$(hyperfine_run "sweep-fmt-$fmt" "$CORPUS_DIR/medium" "$BIN analyse --no-config --format $fmt .")
    local rss; rss=$(peak_rss_kb "$BIN" analyse --no-config --format "$fmt" "$CORPUS_DIR/medium")
    python3 - "$fmt" "$raw" "$rss" "$sweep_out" "$sweep_stash" <<'PY'
import json, sys, os
fmt, raw, rss, out, stash = sys.argv[1:6]
d = json.load(open(raw))
times = sorted(d["results"][0]["times"])
median = times[len(times)//2] * 1000
stddev = d["results"][0]["stddev"] * 1000
print(f"{fmt:<14}  {median:12.1f}  {stddev:12.1f}  {rss:>12}")
# stash a structured record for later aggregation
rec = {"dim": "format", "name": fmt, "median_ms": median, "stddev_ms": stddev, "peak_rss_kb": rss}
with open(stash, "a") as fh:
    fh.write(json.dumps(rec) + "\n")
PY
  done

  # ----- rule sets -----
  log "${C_DIM}-- rule sets --${C_OFF}"
  printf '\n%-30s  %12s  %12s\n' "rule_set" "median_ms" "stddev_ms"
  printf '%s\n' "------------------------------  ------------  ------------"

  # Project config applied to the medium corpus, so this is a same-input comparison
  # against --no-config below. We point --config at the repo's .gruff-go.yaml.
  local raw; raw=$(hyperfine_run "sweep-ruleset-config" "$CORPUS_DIR/medium" "$BIN analyse --config $REPO_ROOT/.gruff-go.yaml --format summary-json .")
  python3 - "config-default" "$raw" "$sweep_stash" <<'PY'
import json, sys
name, raw, stash = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(raw))
times = sorted(d["results"][0]["times"])
median = times[len(times)//2] * 1000
stddev = d["results"][0]["stddev"] * 1000
print(f"{name:<30}  {median:12.1f}  {stddev:12.1f}")
with open(stash, "a") as fh:
    fh.write(json.dumps({"dim": "ruleset", "name": name, "median_ms": median, "stddev_ms": stddev}) + "\n")
PY

  # All default-enabled rules (no config).
  raw=$(hyperfine_run "sweep-ruleset-noconfig" "$CORPUS_DIR/medium" "$BIN analyse --no-config --format summary-json .")
  python3 - "no-config" "$raw" "$sweep_stash" <<'PY'
import json, sys
name, raw, stash = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(raw))
times = sorted(d["results"][0]["times"])
median = times[len(times)//2] * 1000
stddev = d["results"][0]["stddev"] * 1000
print(f"{name:<30}  {median:12.1f}  {stddev:12.1f}")
with open(stash, "a") as fh:
    fh.write(json.dumps({"dim": "ruleset", "name": name, "median_ms": median, "stddev_ms": stddev}) + "\n")
PY

  # Each rule alone via a temporary config selection. Display filters such as
  # --include-rules intentionally do not change analysis inputs, so they would
  # not isolate rule execution cost here.
  for rid in $(list_rules); do
    local rule_config
    rule_config=$(mktemp "$RESULTS_DIR/rule-${rid}.XXXXXX.yaml")
    write_single_rule_config "$rule_config" "$rid"
    raw=$(hyperfine_run "sweep-rule-$rid" "$CORPUS_DIR/medium" "$BIN analyse --config $rule_config --format summary-json .")
    rm -f "$rule_config"
    python3 - "$rid" "$raw" "$sweep_stash" <<'PY'
import json, sys
name, raw, stash = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(raw))
times = sorted(d["results"][0]["times"])
median = times[len(times)//2] * 1000
stddev = d["results"][0]["stddev"] * 1000
print(f"{('rule:'+name):<30}  {median:12.1f}  {stddev:12.1f}")
with open(stash, "a") as fh:
    fh.write(json.dumps({"dim": "rule", "name": name, "median_ms": median, "stddev_ms": stddev}) + "\n")
PY
  done

  # ----- pathological -----
  log "${C_DIM}-- pathological --${C_OFF}"
  local patho="$CORPUS_DIR/pathological"
  ensure_pathological "$patho"
  printf '\n%-20s  %12s  %12s\n' "case" "median_ms" "stddev_ms"
  printf '%s\n' "--------------------  ------------  ------------"
  for case_name in huge-single-file many-tiny-files deep-nesting; do
    local case_dir="$patho/$case_name"
    if ! raw=$(timeout "$SWEEP_CELL_TIMEOUT" bash -c "
      '$HYPERFINE' -i --warmup 1 --min-runs 3 \
        --export-json '$RESULTS_DIR/raw-sweep-patho-$case_name.json' \
        --command-name 'patho-$case_name' \
        -- \"cd '$case_dir' && '$BIN' analyse --no-config --format summary-json .\" >/dev/null
      echo '$RESULTS_DIR/raw-sweep-patho-$case_name.json'
    "); then
      printf '%-20s  %12s  %12s\n' "$case_name" "TIMEOUT" "-"
      continue
    fi
    python3 - "$case_name" "$raw" "$sweep_stash" <<'PY'
import json, sys
name, raw, stash = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(raw))
times = sorted(d["results"][0]["times"])
median = times[len(times)//2] * 1000
stddev = d["results"][0]["stddev"] * 1000
print(f"{name:<20}  {median:12.1f}  {stddev:12.1f}")
with open(stash, "a") as fh:
    fh.write(json.dumps({"dim": "pathological", "name": name, "median_ms": median, "stddev_ms": stddev}) + "\n")
PY
  done

  # ----- aggregate into one file + highlight outliers -----
  python3 - "$sweep_out" "$sweep_stash" <<'PY'
import json, os, sys, datetime
out = sys.argv[1]
src = sys.argv[2]
recs = []
if os.path.exists(src):
    with open(src) as fh:
        for line in fh:
            recs.append(json.loads(line))
    os.remove(src)
agg = {
    "schemaVersion": "gruff-perf.v1",
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "records": recs,
}
with open(out, "w") as fh:
    json.dump(agg, fh, indent=2)
print(f"\nwrote {out}")

# Highlights
formats = [r for r in recs if r["dim"] == "format"]
rules   = [r for r in recs if r["dim"] == "rule"]
if formats:
    baseline = next((r["median_ms"] for r in formats if r["name"] == "summary-json"), None)
    if baseline:
        for r in formats:
            ratio = r["median_ms"] / baseline if baseline else 1
            if ratio > 2:
                print(f"  HIGHLIGHT: format {r['name']} is {ratio:.1f}x slower than summary-json")
if rules:
    total = sum(r["median_ms"] for r in rules)
    if total > 0:
        for r in sorted(rules, key=lambda x: -x["median_ms"])[:5]:
            share = r["median_ms"] / total
            tag = "  HIGHLIGHT: " if share > 0.25 else "  top: "
            print(f"{tag}rule {r['name']}: {r['median_ms']:.1f}ms ({share*100:.0f}% of summed rule cost)")
PY
  ok "sweep OK -> $sweep_out"
}

ensure_pathological() {
  local root="$1"
  if [[ -d "$root" && -f "$root/.stamp-${CORPUS_SEED}" ]]; then
    return
  fi
  log "${C_DIM}generating pathological corpus at $root ...${C_OFF}"
  rm -rf "$root"
  mkdir -p "$root/huge-single-file" "$root/many-tiny-files" "$root/deep-nesting"

  # huge-single-file: one 5000-line .go file.
  python3 - "$root/huge-single-file/huge.go" <<'PY'
import sys
path = sys.argv[1]
with open(path, "w") as fh:
    fh.write("package huge\n\nfunc Big(x int) int {\n")
    for _ in range(4994):
        fh.write("\tx++\n")
    fh.write("\treturn x\n}\n")
PY
  printf 'module example.com/huge\n\ngo 1.25.0\n' > "$root/huge-single-file/go.mod"

  # many-tiny-files: 5000 files, each ~3 lines.
  python3 - "$root/many-tiny-files" <<'PY'
import os, sys
root = sys.argv[1]
for i in range(5000):
    pkg = i // 50
    d = os.path.join(root, f"pkg{pkg:04d}")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, f"f{i:05d}.go"), "w") as fh:
        fh.write(f"package pkg{pkg:04d}\n\nvar V{i:05d} = {i}\n")
PY
  printf 'module example.com/tiny\n\ngo 1.25.0\n' > "$root/many-tiny-files/go.mod"

  # deep-nesting: one file with 200-level if nesting.
  python3 - "$root/deep-nesting/deep.go" <<'PY'
import sys
path = sys.argv[1]
with open(path, "w") as fh:
    fh.write("package deep\n\nfunc Deep(x int) int {\n")
    depth = 200
    for i in range(depth):
        fh.write("\t"*(i+1) + "if x > 0 {\n")
    fh.write("\t"*(depth+1) + "x++\n")
    for i in range(depth, 0, -1):
        fh.write("\t"*i + "}\n")
    fh.write("\treturn x\n}\n")
PY
  printf 'module example.com/deep\n\ngo 1.25.0\n' > "$root/deep-nesting/go.mod"

  : > "$root/.stamp-${CORPUS_SEED}"
}

# ---------- M4: regression gate ----------
write_baseline_from_results() {
  # Reads the latest matrix raw json files + sweep stash and emits baseline.
  python3 - "$RESULTS_DIR" "$BASELINE_FILE" <<'PY'
import glob, json, os, sys, datetime
results_dir, out = sys.argv[1:]
data = {"schemaVersion": "gruff-perf.v1",
        "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "corpora": {}, "rules": {}}

for path in sorted(glob.glob(os.path.join(results_dir, "raw-matrix-*.json"))):
    name = os.path.basename(path).replace("raw-matrix-", "").replace(".json", "")
    d = json.load(open(path))
    times = sorted(d["results"][0]["times"])
    median = times[len(times)//2] * 1000
    data["corpora"][name] = {"median_ms": median}

for path in sorted(glob.glob(os.path.join(results_dir, "raw-sweep-rule-*.json"))):
    name = os.path.basename(path).replace("raw-sweep-rule-", "").replace(".json", "")
    d = json.load(open(path))
    times = sorted(d["results"][0]["times"])
    median = times[len(times)//2] * 1000
    data["rules"][name] = {"median_ms": median}

with open(out, "w") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
print(f"wrote baseline -> {out}", file=sys.stderr)
PY
}

compare_to_baseline() {
  if [[ ! -f "$BASELINE_FILE" ]]; then
    fail "no baseline at $BASELINE_FILE; run --baseline-update first"
  fi
  python3 - "$RESULTS_DIR" "$BASELINE_FILE" "$REGRESSION_CORPUS_PCT" "$REGRESSION_RULE_PCT" <<'PY'
import glob, json, os, sys
results_dir, baseline_path, corpus_tol, rule_tol = sys.argv[1:]
corpus_tol = float(corpus_tol); rule_tol = float(rule_tol)
base = json.load(open(baseline_path))

def latest_median(pattern):
    paths = sorted(glob.glob(pattern))
    if not paths: return {}
    out = {}
    for p in paths:
        name = os.path.basename(p)
        try:
            d = json.load(open(p))
            times = sorted(d["results"][0]["times"])
            out[name] = times[len(times)//2] * 1000
        except Exception:
            continue
    return out

cur_corpora = {os.path.basename(p).replace("raw-matrix-","").replace(".json",""):
               sorted(json.load(open(p))["results"][0]["times"])[len(json.load(open(p))["results"][0]["times"])//2]*1000
               for p in sorted(glob.glob(os.path.join(results_dir, "raw-matrix-*.json")))}
cur_rules = {os.path.basename(p).replace("raw-sweep-rule-","").replace(".json",""):
             sorted(json.load(open(p))["results"][0]["times"])[len(json.load(open(p))["results"][0]["times"])//2]*1000
             for p in sorted(glob.glob(os.path.join(results_dir, "raw-sweep-rule-*.json")))}

print(f"\n{'corpus':<14} {'baseline_ms':>12} {'current_ms':>12} {'delta_%':>10}")
print("-"*52)
status = 0
for name, b in sorted(base.get("corpora", {}).items()):
    cur = cur_corpora.get(name)
    if cur is None:
        print(f"{name:<14} {b['median_ms']:>12.1f} {'-':>12} {'missing':>10}")
        continue
    delta = (cur - b['median_ms']) / b['median_ms'] * 100
    flag = " ***" if delta > corpus_tol else ""
    if delta > corpus_tol: status = 1
    print(f"{name:<14} {b['median_ms']:>12.1f} {cur:>12.1f} {delta:>+9.1f}%{flag}")

print(f"\n{'rule':<32} {'baseline_ms':>12} {'current_ms':>12} {'delta_%':>10}")
print("-"*68)
for name, b in sorted(base.get("rules", {}).items()):
    cur = cur_rules.get(name)
    if cur is None: continue
    delta = (cur - b['median_ms']) / b['median_ms'] * 100
    flag = " ***" if delta > rule_tol else ""
    if delta > rule_tol: status = 1
    if abs(delta) > 5 or flag:
        print(f"{name:<32} {b['median_ms']:>12.1f} {cur:>12.1f} {delta:>+9.1f}%{flag}")

sys.exit(status)
PY
}

# ---------- arg parsing ----------
mode_smoke=0; mode_matrix=0; mode_sweep=0; mode_compare=0; mode_baseline_update=0
if [[ $# -eq 0 ]]; then mode_smoke=1; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --smoke) mode_smoke=1;;
    --matrix) mode_matrix=1;;
    --sweep) mode_sweep=1;;
    --compare) mode_compare=1; mode_matrix=1; mode_sweep=1;;
    --baseline-update) mode_baseline_update=1; mode_matrix=1; mode_sweep=1;;
    --ci)
      REGRESSION_CORPUS_PCT=15
      REGRESSION_RULE_PCT=35
      mode_matrix=1; mode_sweep=1; mode_compare=1
      ;;
    --all) mode_smoke=1; mode_matrix=1; mode_sweep=1;;
    -h|--help)
      sed -n '1,15p' "$0" | sed 's/^# \{0,1\}//'
      exit 0;;
    *) fail "unknown flag: $1";;
  esac
  shift
done

need_hf=""
if [[ $mode_matrix -eq 1 || $mode_sweep -eq 1 || $mode_compare -eq 1 ]]; then
  need_hf="needs_hyperfine"
fi
preflight "$need_hf"
[[ $mode_smoke -eq 1 ]]   && run_smoke
[[ $mode_matrix -eq 1 ]]  && run_matrix
[[ $mode_sweep -eq 1 ]]   && run_sweep
[[ $mode_baseline_update -eq 1 ]] && write_baseline_from_results

# Compare runs last and its exit code drives the script's exit code so the
# regression gate can fail builds.
if [[ $mode_compare -eq 1 ]]; then
  compare_to_baseline || exit $?
fi
exit 0
