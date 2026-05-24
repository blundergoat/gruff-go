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
    score=$(awk '/^score:/ {print $2; exit}' <<<"$output")
    grade=$(awk '/^score:/ {print $NF; exit}' <<<"$output")
    findings=$(awk '/^findings:/ {print $2; exit}' <<<"$output")
    printf 'grade %s - %s/100 - %s findings' "${grade:-?}" "${score:-?}" "${findings:-?}"
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
  - Formatting (gofmt -l)
  - Static analysis (go vet)
  - Tests (go test ./...)
  - Gruff-go self-scan (go run ./cmd/gruff-go summary .)

Options:
  --release     Also require the source version to be unreleased unless HEAD is the matching v* tag.
  -h, --help    Show this help.

Environment:
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

    header

    run_step "Version metadata"           check_version_metadata
    run_step "Node dependency audit"      check_npm_audit
    run_step "Go vulnerability audit"     check_go_vuln
    run_step "Shell syntax (bash -n)"     check_shell_syntax
    run_step "Shellcheck"                 check_shellcheck
    run_step "Formatting (gofmt -l)"      check_gofmt
    run_step "Static analysis (go vet)"   check_go_vet
    run_step "Tests (go test ./...)"      check_go_test
    run_step "Gruff-go self-scan"         check_gruff_summary

    summary
}

main "$@"
