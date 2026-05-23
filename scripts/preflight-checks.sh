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
    printf '  %s%s — %s%s\n' "$DIM" "$(date '+%Y-%m-%d %H:%M:%S')" "$REPO_ROOT" "$RESET"
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
    printf 'grade %s — %s/100 — %s findings' "${grade:-?}" "${score:-?}" "${findings:-?}"
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
  - Shell syntax (bash -n)
  - Shellcheck
  - Formatting (gofmt -l)
  - Static analysis (go vet)
  - Tests (go test ./...)
  - Gruff-go self-scan (go run ./cmd/gruff-go summary .)

Options:
  -h, --help    Show this help.

Environment:
  NO_COLOR      Disable ANSI colour output.
USAGE
}

main() {
    while (($# > 0)); do
        case "$1" in
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

    run_step "Shell syntax (bash -n)"     check_shell_syntax
    run_step "Shellcheck"                 check_shellcheck
    run_step "Formatting (gofmt -l)"      check_gofmt
    run_step "Static analysis (go vet)"   check_go_vet
    run_step "Tests (go test ./...)"      check_go_test
    run_step "Gruff-go self-scan"         check_gruff_summary

    summary
}

main "$@"
