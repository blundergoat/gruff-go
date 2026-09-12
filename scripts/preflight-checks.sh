#!/usr/bin/env bash
# preflight-checks.sh - run the local verification gates for gruff-go.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    GREEN=$'\033[32m'
    RED=$'\033[31m'
    YELLOW=$'\033[33m'
    BLUE=$'\033[34m'
    RESET=$'\033[0m'
else
    BOLD=''
    DIM=''
    GREEN=''
    RED=''
    YELLOW=''
    BLUE=''
    RESET=''
fi

PASS_GLYPH="${GREEN}✔${RESET}"
FAIL_GLYPH="${RED}✘${RESET}"
SKIP_GLYPH="${YELLOW}○${RESET}"
ARROW_GLYPH="${BLUE}▸${RESET}"

# Skip sentinel exit code for run_step (autotools convention).
readonly SKIP_EXIT=77

RELEASE_MODE=0
TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0
FAILURES=()

now_ns() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import time; print(time.time_ns())'
        return
    fi
    printf '%s000000000\n' "$(date +%s)"
}

START_TIME=$(now_ns)

# Select the repository's preferred Go release so preflight evaluates the same toolchain everywhere.
configure_go_toolchain() {
    local preferred_toolchain

    # An explicit override is a deliberate compatibility check, so preserve the caller's choice.
    if [[ -n "${GOTOOLCHAIN:-}" ]]; then
        return
    fi

    preferred_toolchain=$(awk '$1 == "toolchain" { print $2; exit }' "$REPO_ROOT/go.mod")

    # A module without a preferred release keeps the Go command's normal automatic selection.
    if [[ -z "$preferred_toolchain" ]]; then
        return
    fi

    export GOTOOLCHAIN="$preferred_toolchain"
}

rule() {
    printf '  %s\n' "${DIM}────────────────────────────────────────────${RESET}"
}

elapsed_since() {
    local started_at=$1
    local finished_at elapsed_ms seconds minutes remainder frac

    finished_at=$(now_ns)
    elapsed_ms=$(((finished_at - started_at) / 1000000))

    if ((elapsed_ms < 1000)); then
        printf '%dms' "$elapsed_ms"
        return
    fi

    seconds=$((elapsed_ms / 1000))
    frac=$(((elapsed_ms % 1000) / 100))

    if ((seconds < 60)); then
        printf '%d.%ds' "$seconds" "$frac"
        return
    fi

    minutes=$((seconds / 60))
    remainder=$((seconds % 60))
    printf '%dm %02d.%ds' "$minutes" "$remainder" "$frac"
}

header() {
    printf '\n'
    printf '  %sPreflight Check%s\n' "$BOLD" "$RESET"
    printf '  %s%s - %s%s\n' "$DIM" "$(date '+%Y-%m-%d %H:%M:%S')" "$REPO_ROOT" "$RESET"
    printf '  %sGo toolchain: %s%s\n' "$DIM" "${GOTOOLCHAIN:-auto}" "$RESET"
    rule
    printf '\n'
}

step() {
    local label=$1
    TOTAL=$((TOTAL + 1))
    printf '  %s %-32s' "$ARROW_GLYPH" "$label"
}

pass() {
    local detail=${1:-}
    PASSED=$((PASSED + 1))
    if [[ -n "$detail" ]]; then
        printf '%s  %s%s%s\n' "$PASS_GLYPH" "$DIM" "$detail" "$RESET"
    else
        printf '%s\n' "$PASS_GLYPH"
    fi
}

fail_line() {
    local label=$1
    FAILED=$((FAILED + 1))
    FAILURES+=("$label")
    printf '%s\n' "$FAIL_GLYPH"
}

skip_line() {
    local reason=${1:-skipped}
    SKIPPED=$((SKIPPED + 1))
    printf '%s  %s%s%s\n' "$SKIP_GLYPH" "$DIM" "$reason" "$RESET"
}

indent_output() {
    while IFS= read -r line; do
        printf '    %s%s%s\n' "$DIM" "$line" "$RESET"
    done
}

# run_step <label> <cmd...>
#   The wrapped function/command may:
#     - exit 0 and print a single-line detail string (shown dim after the glyph)
#     - exit SKIP_EXIT (77) and print a skip reason (shown dim after the ○ glyph)
#     - exit non-zero with diagnostic output (last 20 lines indented under the line)
run_step() {
    local label=$1
    shift
    local started_at output status elapsed

    step "$label"
    started_at=$(now_ns)
    output=$("$@" 2>&1)
    status=$?
    elapsed=$(elapsed_since "$started_at")

    if ((status == SKIP_EXIT)); then
        skip_line "${output:-skipped}"
        return 0
    fi

    if ((status == 0)); then
        if [[ -n "$output" ]]; then
            pass "$output  $elapsed"
        else
            pass "$elapsed"
        fi
        return 0
    fi

    fail_line "$label"
    if [[ -n "$output" ]]; then
        printf '%s\n' "$output" | tail -20 | indent_output
    fi
    printf '    %sexit %d after %s%s\n' "$DIM" "$status" "$elapsed" "$RESET"
    return "$status"
}

repo_files() {
    local pattern="$1"
    if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        {
            git -C "$REPO_ROOT" ls-files -- "$pattern"
            git -C "$REPO_ROOT" ls-files --others --exclude-standard -- "$pattern"
        } | sort -u
    else
        (cd "$REPO_ROOT" && find . -type f -name "$pattern" -print | sed 's#^\./##')
    fi
}

tool_version() {
    local version
    version=$(grep -oE 'const toolVersion = "[^"]+"' "$REPO_ROOT/internal/cli/cli.go" \
        | sed -E 's/.*"([^"]+)"/\1/')
    if [[ -z "$version" ]]; then
        printf 'could not parse toolVersion from internal/cli/cli.go'
        return 1
    fi
    printf '%s' "$version"
}

check_file_contains() {
    local file=$1 needle=$2
    if ! grep -qF "$needle" "$REPO_ROOT/$file"; then
        printf '%s missing %q\n' "$file" "$needle"
        return 1
    fi
}

check_package_versions() {
    local version=$1
    if ! command -v node >/dev/null 2>&1; then
        # In release mode we insist on the package.json/package-lock.json check;
        # locally we skip silently so Go-only developers can still run preflight,
        # matching how check_npm_audit and check_go_vuln handle their tooling.
        if ((RELEASE_MODE == 1)); then
            printf 'node is required to verify package.json and package-lock.json versions'
            return 1
        fi
        return 0
    fi

    node - "$REPO_ROOT/package.json" "$REPO_ROOT/package-lock.json" "$version" <<'NODE'
const fs = require("fs");

const [packagePath, lockPath, expectedVersion] = process.argv.slice(2);

function readJSON(path) {
  try {
    return JSON.parse(fs.readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`${path}: ${error.message}`);
  }
}

function expectVersion(path, field, actual) {
  if (actual !== expectedVersion) {
    throw new Error(`${path}: expected ${field} to be ${expectedVersion}, got ${actual}`);
  }
}

const packageJSON = readJSON(packagePath);
expectVersion(packagePath, "version", packageJSON.version);

const packageLock = readJSON(lockPath);
expectVersion(lockPath, "version", packageLock.version);
if (!packageLock.packages || !packageLock.packages[""]) {
  throw new Error(`${lockPath}: missing packages[""] root package entry`);
}
expectVersion(lockPath, 'packages[""].version', packageLock.packages[""].version);
NODE
}

check_golden_versions() {
    local version=$1 drift
    drift=$(grep -RInE '"(version|semanticVersion)": "[0-9]+\.[0-9]+\.[0-9]+([+-][^"]*)?"' \
        "$REPO_ROOT/internal/cli/testdata/golden" 2>/dev/null \
        | grep -v '"version": "2.1.0"' \
        | grep -vF "\"$version\"" || true)
    if [[ -n "$drift" ]]; then
        printf 'CLI golden version drift:\n%s' "$drift"
        return 1
    fi
}

release_tag_at_head() {
    local tags=()

    if [[ "${GITHUB_REF_TYPE:-}" == "tag" && "${GITHUB_REF_NAME:-}" == v[0-9]* ]]; then
        printf '%s' "$GITHUB_REF_NAME"
        return 0
    fi

    if ! git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        return 1
    fi

    mapfile -t tags < <(git -C "$REPO_ROOT" tag --points-at HEAD --list 'v[0-9]*' | sort)
    if ((${#tags[@]} > 1)); then
        printf 'multiple release tags point at HEAD: %s' "${tags[*]}"
        return 2
    fi
    if ((${#tags[@]} == 1)); then
        printf '%s' "${tags[0]}"
        return 0
    fi
    return 1
}

check_release_version() {
    local version=$1 tag status existing latest

    tag=$(release_tag_at_head)
    status=$?
    if ((status == 2)); then
        printf '%s' "$tag"
        return 1
    fi
    if ((status == 0)); then
        if [[ "${tag#v}" != "$version" ]]; then
            printf 'release tag %s does not match toolVersion %s; run scripts/bump-version.sh before tagging' "$tag" "$version"
            return 1
        fi
        printf 'version %s matches %s' "$version" "$tag"
        return 0
    fi

    if ((RELEASE_MODE == 0)); then
        printf 'version %s' "$version"
        return 0
    fi

    if ! git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        printf '--release requires git metadata to compare release tags'
        return 1
    fi

    existing=$(git -C "$REPO_ROOT" tag --list "v$version")
    if [[ -n "$existing" ]]; then
        printf 'toolVersion %s already has release tag %s; run scripts/bump-version.sh <next-version>' "$version" "$existing"
        return 1
    fi

    latest=$(git -C "$REPO_ROOT" tag --list 'v[0-9]*' --sort=-v:refname | head -1)
    if [[ -n "$latest" ]]; then
        printf 'version %s (latest tag %s)' "$version" "$latest"
    else
        printf 'version %s (no prior release tags)' "$version"
    fi
}

check_version_metadata() {
    local version detail
    if ! version=$(tool_version); then
        printf '%s' "$version"
        return 1
    fi
    if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
        printf 'toolVersion %s is not SemVer' "$version"
        return 1
    fi

    check_file_contains "internal/analysis/report.go" "Version: \"$version\"" || return 1
    check_file_contains "internal/report/machine_test.go" "SemanticVersion != \"$version\"" || return 1
    check_package_versions "$version" || return 1
    check_golden_versions "$version" || return 1
    detail=$(check_release_version "$version") || {
        printf '%s' "$detail"
        return 1
    }
    printf '%s' "$detail"
}

check_npm_audit() {
    local output
    if [[ ! -f "$REPO_ROOT/package-lock.json" ]]; then
        printf 'no package-lock.json'
        return "$SKIP_EXIT"
    fi
    if ! command -v npm >/dev/null 2>&1; then
        printf 'npm not installed'
        return "$SKIP_EXIT"
    fi

    if ! output=$(npm audit --audit-level=moderate 2>&1); then
        printf '%s' "$output"
        return 1
    fi
    printf '%s' "${output:-npm audit passed}"
}

check_go_vuln() {
    local output
    if [[ ! -f "$REPO_ROOT/go.mod" ]]; then
        printf 'no go.mod'
        return "$SKIP_EXIT"
    fi
    if ! command -v govulncheck >/dev/null 2>&1; then
        printf 'govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)'
        return "$SKIP_EXIT"
    fi

    if ! output=$(govulncheck ./... 2>&1); then
        printf '%s' "$output"
        return 1
    fi
    if grep -q 'No vulnerabilities found.' <<<"$output"; then
        printf 'no vulnerabilities'
    else
        printf 'govulncheck passed'
    fi
}

check_shell_syntax() {
    local files=() output
    mapfile -t files < <(repo_files '*.sh')
    if ((${#files[@]} == 0)); then
        printf 'no shell scripts'
        return "$SKIP_EXIT"
    fi
    if ! output=$(bash -n "${files[@]}" 2>&1); then
        printf '%s' "$output"
        return 1
    fi
    printf '%d files' "${#files[@]}"
}

check_post_turn_limit_hardening() {
    local hook='.goat-flow/hooks/post-turn-safety.sh' output
    if [[ ! -f "$hook" ]]; then
        printf 'post-turn-safety hook not installed'
        return "$SKIP_EXIT"
    fi
    # The hook gates every file on MAX_FILE_BYTES. Unvalidated, a nonnumeric
    # limit evaluates to 0 and the scanner silently skips everything while still
    # reporting clean - a safety hook that does nothing and says it passed.
    # Running the self-test under hostile limits distinguishes a hardened hook
    # from one that has been reverted: the hardened hook returns 0, the
    # unhardened upstream template returns 2 ("clean case failed on scanner 0").
    #
    # This lives here rather than inside the hook because the hook is a managed
    # goat-flow file: a `goat-flow install` that restores the upstream template
    # would revert the hardening AND the in-file self-test cases together, so
    # only a project-owned check outside that file can notice.
    if ! output=$(
        GOAT_FLOW_POST_TURN_SAFETY_MAX_BYTES=invalid \
            GOAT_FLOW_POST_TURN_SAFETY_MAX_FINDINGS=08 \
            bash "$hook" --self-test 2>&1
    ); then
        printf 'post-turn-safety limit hardening reverted (%s); re-apply before shipping' "${output:-no output}"
        return 1
    fi
    printf 'nonnumeric and leading-zero limits fall back'
}

check_shellcheck() {
    local files=() output combined status file
    mapfile -t files < <(repo_files '*.sh')
    if ((${#files[@]} == 0)); then
        printf 'no shell scripts'
        return "$SKIP_EXIT"
    fi
    if ! command -v shellcheck >/dev/null 2>&1; then
        printf 'shellcheck not installed'
        return "$SKIP_EXIT"
    fi

    status=0
    combined=""
    for file in "${files[@]}"; do
        # Existing tracked warning in the performance harness; keep other files strict.
        if [[ "$file" == "scripts/test-performance.sh" ]]; then
            output=$(shellcheck -e SC2034 "$file" 2>&1) || status=1
        else
            output=$(shellcheck "$file" 2>&1) || status=1
        fi
        if [[ -n "$output" ]]; then
            combined+="${output}"$'\n'
        fi
    done

    if ((status != 0)); then
        printf '%s' "$combined"
        return 1
    fi
    printf '%d files' "${#files[@]}"
}

check_gofmt() {
    local files=() unformatted
    mapfile -t files < <(repo_files '*.go')
    if ((${#files[@]} == 0)); then
        printf 'no Go files'
        return "$SKIP_EXIT"
    fi

    unformatted=$(gofmt -l "${files[@]}" 2>&1)
    if [[ -n "$unformatted" ]]; then
        printf 'needs gofmt:\n%s' "$unformatted"
        return 1
    fi
    printf '%d files' "${#files[@]}"
}

check_go_vet() {
    local output
    if ! output=$(go vet ./... 2>&1); then
        printf '%s' "$output"
        return 1
    fi
}

check_go_test() {
    local output status ok_count notest_count cached_count pkg_count
    output=$(go test ./... 2>&1)
    status=$?
    if ((status != 0)); then
        printf '%s' "$output"
        return "$status"
    fi
    ok_count=$(grep -c '^ok ' <<<"$output" || true)
    notest_count=$(grep -c '\[no test files\]' <<<"$output" || true)
    cached_count=$(grep -c '(cached)' <<<"$output" || true)
    pkg_count=$((ok_count + notest_count))
    if ((cached_count > 0)); then
        printf '%d packages (%d cached)' "$pkg_count" "$cached_count"
    else
        printf '%d packages' "$pkg_count"
    fi
}

check_gruff_summary() {
    local output status score grade findings
    output=$(go run ./cmd/gruff-go summary . 2>&1)
    status=$?
    if ((status != 0)); then
        printf '%s' "$output"
        return "$status"
    fi
    grade=$(awk '/^Composite:/ {print $2; exit}' <<<"$output")
    score=$(awk -F'[()/]' '/^Composite:/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' <<<"$output")
    findings=$(awk '/^Findings:/ {print $2; exit}' <<<"$output")
    printf 'grade %s - %s/100 - %s findings' "${grade:-?}" "${score:-?}" "${findings:-?}"
}

# ---------------------------------------------------------------------------
# Documentation drift (M09 task 14). The owned documentation must agree with the
# live rule catalogue, name only rules that ship, cite only decisions this port
# carries, and link only to pages that exist. Every extraction fails closed: a
# document that states no catalogue size or names no rule is a defect, not a pass.
# ---------------------------------------------------------------------------

# Extract the live catalogue facts once so every drift assertion reads one snapshot.
docs_drift_facts() {
    local catalogue_file=$1
    node - "$catalogue_file" <<'NODE'
const fs = require("fs");

const listing = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const rules = listing && Array.isArray(listing.rules) ? listing.rules : null;
if (!rules || rules.length === 0) {
  throw new Error("false-empty: list-rules published no rules under rules");
}
const ids = rules.map((rule) => rule.id).sort();
const pillars = [...new Set(rules.map((rule) => rule.pillar))].sort();
const enabled = rules.filter((rule) => rule.defaultEnabled === true).length;
const pillarCounts = pillars.map((pillar) => pillar + ":" + rules.filter((rule) => rule.pillar === pillar).length);
console.log("count=" + rules.length);
console.log("pillars=" + pillars.length);
console.log("enabled=" + enabled);
console.log("optin=" + (rules.length - enabled));
console.log("pillarNames=" + pillars.join("|"));
console.log("pillarCounts=" + pillarCounts.join("|"));
console.log("ids=" + ids.join(" "));
NODE
}

# Compare every per-pillar table row in the README with the live catalogue. A row that names a count
# the catalogue does not have, or a table shorter than the catalogue's pillar list, is a stale claim.
docs_drift_pillar_table() {
    local readme=$1 facts=$2
    local backtick='`'
    local pillar_counts row_pillar row_count live_count table_rows=0 pillars
    pillars=$(docs_fact "$facts" pillars)
    pillar_counts="|$(docs_fact "$facts" pillarCounts)|"

    while IFS='|' read -r row_pillar row_count; do
        table_rows=$((table_rows + 1))
        live_count=$(sed -n "s/.*|${row_pillar}:\([0-9]*\)|.*/\1/p" <<<"$pillar_counts")
        if [[ "$live_count" != "$row_count" ]]; then
            printf 'docs drift: source-revision: README.md pillar table says %s has %s rules but list-rules has %s\n' \
                "$row_pillar" "$row_count" "${live_count:-no such pillar}"
            return 1
        fi
    done < <(grep -oE "^\| *${backtick}[a-z-]+${backtick} *\| *[0-9]+ *\|$" "$readme" \
        | sed -E "s/^\| *${backtick}([a-z-]+)${backtick} *\| *([0-9]+) *\|$/\1|\2/")

    if ((table_rows > 0 && table_rows != pillars)); then
        printf 'docs drift: source-revision: README.md pillar table has %s rows but list-rules has %s pillars\n' \
            "$table_rows" "$pillars"
        return 1
    fi

    printf '%s' "$table_rows"
}

# Read one fact from the extracted facts block.
docs_fact() {
    local facts=$1 key=$2
    sed -n "s/^${key}=//p" <<<"$facts"
}

# Capture the live catalogue facts, or the reason the catalogue could not be read.
docs_drift_live_facts() {
    local catalogue facts
    if ! command -v node >/dev/null 2>&1; then
        printf 'node is required to read list-rules JSON'
        return "$SKIP_EXIT"
    fi
    catalogue=$(mktemp "${TMPDIR:-/tmp}/gruff-go-docs-drift.XXXXXX.json") || return 1
    if ! go run ./cmd/gruff-go list-rules --no-config --format json >"$catalogue" 2>/dev/null; then
        rm -f -- "$catalogue"
        printf 'docs drift: list-rules --format json failed'
        return 1
    fi
    facts=$(docs_drift_facts "$catalogue" 2>&1)
    local status=$?
    rm -f -- "$catalogue"
    printf '%s' "$facts"
    return "$status"
}

# Compare the owned documentation under one root with the live catalogue facts. Runs against the
# real checkout, and against synthetic copies in the fixture harness, so both share one contract.
docs_drift_check_root() {
    local docs_root=$1 facts=$2
    local readme="$docs_root/README.md" rules_doc="$docs_root/docs/rules.md"
    local count pillars enabled optin ids pillar_names
    local claim claims=0 doc token decision link
    local documents=() mentioned=() phantom=() bad_decisions=() dead=()

    count=$(docs_fact "$facts" count)
    pillars=$(docs_fact "$facts" pillars)
    enabled=$(docs_fact "$facts" enabled)
    optin=$(docs_fact "$facts" optin)
    ids=" $(docs_fact "$facts" ids) "
    pillar_names=$(docs_fact "$facts" pillarNames)

    for doc in "$readme" "$rules_doc"; do
        if [[ ! -f "$doc" ]]; then
            printf 'docs drift: false-empty: %s is missing\n' "${doc#"$docs_root"/}"
            return 1
        fi
    done

    # Source-revision claims: every stated catalogue size must equal the live catalogue.
    while IFS= read -r claim; do
        claims=$((claims + 1))
        if [[ "$claim" != "$count rules across $pillars pillars" ]]; then
            printf 'docs drift: source-revision: a document says "%s" but list-rules has %s rules across %s pillars\n' \
                "$claim" "$count" "$pillars"
            return 1
        fi
    done < <(grep -ohE '[0-9]+\*{0,2} rules\*{0,2} across \*{0,2}[0-9]+\*{0,2} pillars' "$readme" "$rules_doc" | tr -d '*')
    while IFS= read -r claim; do
        claims=$((claims + 1))
        if [[ "$claim" != "$enabled"* ]]; then
            printf 'docs drift: source-revision: a document says "%s" but list-rules enables %s by default\n' \
                "$claim" "$enabled"
            return 1
        fi
    done < <(grep -ohE '[0-9]+\*{0,2} (rules are )?enabled by default' "$readme" "$rules_doc" | tr -d '*')
    while IFS= read -r claim; do
        claims=$((claims + 1))
        if [[ "$claim" != "$optin "* ]]; then
            printf 'docs drift: source-revision: a document says "%s" but list-rules has %s opt-in rules\n' \
                "$claim" "$optin"
            return 1
        fi
    done < <(grep -ohE '[0-9]+ (opt-in rules|rules are opt-in)' "$readme" "$rules_doc")
    local table_rows
    table_rows=$(docs_drift_pillar_table "$readme" "$facts") || {
        printf '%s\n' "$table_rows"
        return 1
    }
    claims=$((claims + table_rows))
    if ((claims == 0)); then
        printf 'docs drift: false-empty: README.md and docs/rules.md state no catalogue size\n'
        return 1
    fi

    # Phantom rule ids: a backticked <pillar>.<slug> in the README or docs must be a rule that
    # ships. UPGRADING.md is history by design, and a line that says retired or removed is too.
    mapfile -t documents < <(find "$docs_root/docs" -maxdepth 1 -name '*.md' 2>/dev/null | sort)
    documents+=("$readme")
    while IFS= read -r token; do
        mentioned+=("$token")
        if [[ "$ids" != *" $token "* ]]; then
            phantom+=("$token")
        fi
    done < <(grep -hvE 'retired|removed' "${documents[@]}" \
        | grep -oE "\`($pillar_names)\.[a-z0-9-]+\`" | tr -d '`' | sort -u)
    if ((${#mentioned[@]} == 0)); then
        printf 'docs drift: false-empty: the documentation names no rule id\n'
        return 1
    fi
    if ((${#phantom[@]} > 0)); then
        printf 'docs drift: phantom rule ids not in list-rules: %s\n' "${phantom[*]}"
        return 1
    fi

    # Decision namespace: every ADR the documentation cites must exist in this port's decisions.
    while IFS= read -r decision; do
        if ! compgen -G "$REPO_ROOT/.goat-flow/learning-loop/decisions/$decision-*.md" >/dev/null; then
            bad_decisions+=("$decision")
        fi
    done < <(cat "${documents[@]}" "$docs_root/UPGRADING.md" 2>/dev/null | grep -oE 'ADR-[0-9]{3}' | sort -u)
    if ((${#bad_decisions[@]} > 0)); then
        printf 'docs drift: decision-namespace: %s cited but absent from .goat-flow/learning-loop/decisions\n' \
            "${bad_decisions[*]}"
        return 1
    fi

    # Entry-page links: every relative link from the README must resolve inside the checkout. A
    # fixture copy carries only the documentation, so a link to any other checked-in file still
    # resolves against the real repository root.
    while IFS= read -r link; do
        if [[ ! -e "$docs_root/$link" && ! -e "$REPO_ROOT/$link" ]]; then
            dead+=("$link")
        fi
    done < <(grep -oE '\]\([^)#[:space:]]+' "$readme" | sed 's/^](//' | grep -vE '^(https?://|mailto:)' | sort -u)
    if ((${#dead[@]} > 0)); then
        printf 'docs drift: entry-page link does not resolve: %s\n' "${dead[*]}"
        return 1
    fi

    printf '%s rules, %s pillars, %s enabled; %s rule ids and every cited decision resolve' \
        "$count" "$pillars" "$enabled" "${#mentioned[@]}"
}

check_docs_drift() {
    local facts status
    facts=$(docs_drift_live_facts)
    status=$?
    if ((status != 0)); then
        printf '%s' "$facts"
        return "$status"
    fi
    docs_drift_check_root "$REPO_ROOT" "$facts"
}

# Run the drift check against one mutated copy and require the named rejection.
expect_docs_drift_rejection() {
    local case_name=$1 expected=$2 docs_root=$3 facts=$4 output
    if output=$(docs_drift_check_root "$docs_root" "$facts" 2>&1); then
        printf 'docs drift fixture %s: the mutation passed the gate\n' "$case_name"
        return 1
    fi
    if [[ "$output" != *"$expected"* ]]; then
        printf 'docs drift fixture %s: rejected for the wrong reason; expected "%s", got: %s\n' \
            "$case_name" "$expected" "$output"
        return 1
    fi
}

# Prove the drift gate rejects each mutation class without touching the real documentation
# (M09 task 16): false-empty, phantom rule, decision-namespace, source-revision, dead link.
check_docs_drift_fixtures() {
    local facts status harness valid root count first_pillar
    local backtick='`'
    facts=$(docs_drift_live_facts)
    status=$?
    if ((status != 0)); then
        printf '%s' "$facts"
        return "$status"
    fi
    count=$(docs_fact "$facts" count)
    first_pillar=$(docs_fact "$facts" pillarNames)
    first_pillar=${first_pillar%%|*}

    harness=$(mktemp -d "${TMPDIR:-/tmp}/gruff-go-docs-fixtures.XXXXXX") || return 1
    valid="$harness/valid"
    mkdir -p "$valid"
    cp "$REPO_ROOT/README.md" "$REPO_ROOT/UPGRADING.md" "$valid/"
    cp -R "$REPO_ROOT/docs" "$valid/docs"
    if ! docs_drift_check_root "$valid" "$facts" >/dev/null 2>&1; then
        printf 'docs drift fixture: the unmodified copy failed the gate'
        rm -rf -- "$harness"
        return 1
    fi

    root="$harness/false-empty"
    cp -R "$valid" "$root"
    printf '# gruff-go\n\nSee the docs.\n' >"$root/README.md"
    printf '# Rule Catalog\n\nSee list-rules.\n' >"$root/docs/rules.md"
    expect_docs_drift_rejection false-empty 'false-empty' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

    root="$harness/phantom-rule"
    cp -R "$valid" "$root"
    printf '\nThe %s%s.phantom-rule%s rule is documented here.\n' "$backtick" "$first_pillar" "$backtick" >>"$root/README.md"
    expect_docs_drift_rejection phantom-rule 'phantom rule ids' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

    root="$harness/decision-namespace"
    cp -R "$valid" "$root"
    printf '\nSee ADR-999 for the rationale.\n' >>"$root/README.md"
    expect_docs_drift_rejection decision-namespace 'decision-namespace' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

    root="$harness/source-revision"
    cp -R "$valid" "$root"
    sed -i "s/$count rules across/$((count + 1)) rules across/" "$root/README.md"
    expect_docs_drift_rejection source-revision 'source-revision' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

    root="$harness/dead-link"
    cp -R "$valid" "$root"
    printf '\n[Missing page](docs/missing-page.md)\n' >>"$root/README.md"
    expect_docs_drift_rejection dead-link 'entry-page link' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

    root="$harness/stale-pillar-table"
    cp -R "$valid" "$root"
    sed -i -E "0,/^(\| *${backtick}[a-z-]+${backtick} *\| *)[0-9]+( *\|)$/s//\1999\2/" "$root/README.md"
    expect_docs_drift_rejection stale-pillar-table 'pillar table' "$root" "$facts" || { rm -rf -- "$harness"; return 1; }

    rm -rf -- "$harness"
    printf '6 mutations rejected'
}

summary() {
    local elapsed failure
    elapsed=$(elapsed_since "$START_TIME")
    printf '\n'
    rule
    printf '\n'

    if ((FAILED == 0)); then
        if ((SKIPPED > 0)); then
            printf '  %sAll %d checks passed%s  %s(%d skipped, %s)%s\n' \
                "$GREEN$BOLD" "$PASSED" "$RESET" \
                "$DIM" "$SKIPPED" "$elapsed" "$RESET"
        else
            printf '  %sAll %d checks passed%s  %s(%s)%s\n' \
                "$GREEN$BOLD" "$PASSED" "$RESET" \
                "$DIM" "$elapsed" "$RESET"
        fi
        printf '\n'
        return 0
    fi

    printf '  %s%d/%d checks failed%s  %s(%s)%s\n' \
        "$RED$BOLD" "$FAILED" "$TOTAL" "$RESET" \
        "$DIM" "$elapsed" "$RESET"
    printf '\n'
    for failure in "${FAILURES[@]}"; do
        printf '    %s  %s\n' "$FAIL_GLYPH" "$failure"
    done
    printf '\n'

    return 1
}

usage() {
    cat <<'USAGE'
Usage: scripts/preflight-checks.sh

Runs the local verification gates for gruff-go:
  - Version metadata consistency
  - Node dependency audit (npm audit)
  - Go vulnerability audit (govulncheck, skipped locally if unavailable)
  - Shell syntax (bash -n)
  - Shellcheck
  - Post-turn limit hardening
  - Formatting (gofmt -l)
  - Static analysis (go vet)
  - Tests (go test ./...)
  - Gruff-go self-scan (go run ./cmd/gruff-go summary .)
  - Documentation drift (README.md and docs/ agree with list-rules, cite only carried decisions, link only to real pages)
  - Documentation drift fixtures (each mutation class is rejected: false-empty, phantom rule, decision-namespace, source-revision, dead link)

Options:
  --release     Also require the source version to be unreleased unless HEAD is the matching v* tag.
  -h, --help    Show this help.

Environment:
  GOTOOLCHAIN   Override the preferred Go release declared in go.mod.
  NO_COLOR      Disable ANSI colour output.
USAGE
}

main() {
    while (($# > 0)); do
        case "$1" in
            --release)
                RELEASE_MODE=1
                shift
                ;;
            -h|--help)
                usage
                return 0
                ;;
            *)
                printf '%sUnknown option:%s %s\n' "$RED" "$RESET" "$1" >&2
                usage >&2
                return 64
                ;;
        esac
    done

    cd "$REPO_ROOT" || return 1

    configure_go_toolchain

    header

    run_step "Version metadata"           check_version_metadata
    run_step "Node dependency audit"      check_npm_audit
    run_step "Go vulnerability audit"     check_go_vuln
    run_step "Shell syntax (bash -n)"     check_shell_syntax
    run_step "Shellcheck"                 check_shellcheck
    run_step "Post-turn limit hardening"  check_post_turn_limit_hardening
    run_step "Formatting (gofmt -l)"      check_gofmt
    run_step "Static analysis (go vet)"   check_go_vet
    run_step "Tests (go test ./...)"      check_go_test
    run_step "Gruff-go self-scan"         check_gruff_summary
    run_step "Documentation drift"        check_docs_drift
    run_step "Documentation drift fixtures" check_docs_drift_fixtures

    summary
}

main "$@"
