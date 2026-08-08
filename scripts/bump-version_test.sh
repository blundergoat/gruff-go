#!/usr/bin/env bash
# Exercises bump-version.sh's read-only reference scanner in disposable trees.
# The fixtures pin ownership categories, failure semantics, stable row ordering,
# non-Git operation, and the already-current no-op path without touching the
# checkout's source version or package metadata.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_UNDER_TEST="$SCRIPT_DIR/bump-version.sh"
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gruff-go-bump-version-test.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT

TESTS_RUN=0
REAL_SED=$(command -v sed)
export REAL_SED
[[ -n "$REAL_SED" && -x "$REAL_SED" ]] || {
    printf 'FAIL sed is required for guard fixtures\n' >&2
    exit 1
}

# fail stops the suite with one grep-friendly diagnostic.
fail() {
    printf 'FAIL %s\n' "$*" >&2
    exit 1
}

# assert_equal compares exact scalar or multiline fixture output.
assert_equal() {
    local want=$1 got=$2 context=$3
    [[ "$got" == "$want" ]] || fail "$context: got [$got], want [$want]"
}

# assert_contains verifies a stable diagnostic or output fragment.
assert_contains() {
    local haystack=$1 needle=$2 context=$3
    [[ "$haystack" == *"$needle"* ]] || fail "$context: missing [$needle]"
}

# hash_tree returns a content hash for every regular file below a fixture root.
hash_tree() {
    local root=$1
    (
        cd "$root"
        find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
    ) | sha256sum | awk '{ print $1 }'
}

# write_source_tree creates the script-owned source/version anchors for a fixture.
write_source_tree() {
    local root=$1 cli_version=$2 report_version=$3 machine_version=$4
    mkdir -p "$root/internal/cli/testdata/golden" "$root/internal/analysis" "$root/internal/report"
    printf 'const toolVersion = "%s"\n' "$cli_version" >"$root/internal/cli/cli.go"
    printf 'Version: "%s",\n' "$report_version" >"$root/internal/analysis/report.go"
    printf 'if driver.SemanticVersion != "%s" {\n' "$machine_version" >"$root/internal/report/machine_test.go"
    cat >"$root/package.json" <<EOF
{
  "name": "fixture",
  "version": "$cli_version"
}
EOF
    cat >"$root/package-lock.json" <<EOF
{
  "name": "fixture",
  "version": "$cli_version",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "fixture",
      "version": "$cli_version"
    },
    "node_modules/unrelated": {
      "version": "8.7.6"
    }
  }
}
EOF
}

# write_guard_tools makes mutation-only dependencies fail if check/no-op reaches them.
write_guard_tools() {
    local bin=$1
    mkdir -p "$bin"
    cat >"$bin/node" <<'EOF'
#!/usr/bin/env bash
# Test double for Node on paths that promise not to mutate package metadata.
# Release reviewers use it to detect an accidental handoff to JSON writes.
# It exists only inside a disposable fixture and always fails if reached.
printf 'node\n' >>"$MUTATION_MARKER"
exit 97
EOF
    cat >"$bin/go" <<'EOF'
#!/usr/bin/env bash
# Test double for Go on paths that promise not to regenerate CLI goldens.
# Release reviewers use it to detect an accidental build or write path.
# It exists only inside a disposable fixture and always fails if reached.
printf 'go\n' >>"$MUTATION_MARKER"
exit 98
EOF
    cat >"$bin/sed" <<'EOF'
#!/usr/bin/env bash
# Test double that permits read-only sed parsing but rejects in-place edits.
# Release reviewers use it to prove check/no-op cannot rewrite source prose.
# It exists only inside a disposable fixture and delegates safe reads.
for arg in "$@"; do
    # In-place sed would mean check/no-op changed a user's fixture unexpectedly.
    if [[ "$arg" == -i || "$arg" == -i* ]]; then
        printf 'sed-inplace\n' >>"$MUTATION_MARKER"
        exit 99
    fi
done
exec "$REAL_SED" "$@"
EOF
    chmod +x "$bin/node" "$bin/go" "$bin/sed"
}

# run_checker captures stdout, stderr, and exit status without tripping set -e.
run_checker() {
    local root=$1 version=$2 stdout_file=$3 stderr_file=$4 status_file=$5 guard_bin=$6
    set +e
    MUTATION_MARKER="$TMP_DIR/mutation-called" PATH="$guard_bin:$PATH" \
        "$SCRIPT_UNDER_TEST" --check-references --root "$root" --source-version "$version" \
        >"$stdout_file" 2>"$stderr_file"
    printf '%d' "$?" >"$status_file"
    set -e
}

# test_classification_and_order pins all owner categories and mismatch failures.
test_classification_and_order() {
    local root="$TMP_DIR/classification" guard_bin="$TMP_DIR/guard-bin"
    local before after status output expected
    write_source_tree "$root" "1.2.3" "0.9.0" "9.9.9"
    write_guard_tools "$guard_bin"
    printf 'gruff-go 1.2.3 analyse\n' >"$root/internal/cli/testdata/golden/a-text.golden"
    printf '    "name": "gruff-go",\n    "version": "0.9.0"\n' >"$root/internal/cli/testdata/golden/b-summary.golden"
    printf '    "semanticVersion": "9.9.9"\n' >"$root/internal/cli/testdata/golden/c-sarif.golden"
    mkdir -p "$root/docs" "$root/.goat-flow"
    cat >"$root/AGENTS.md" <<'EOF'
# gruff-go fixture (v7.7.7)
EOF
    cat >"$root/README.md" <<'EOF'
| Release line | Published `1.2.3` package line |
go get -tool github.com/blundergoat/gruff-go/cmd/gruff-go@v0.9.0
go get -tool github.com/blundergoat/gruff-go/cmd/gruff-go@v1.2.3
go get -tool github.com/blundergoat/gruff-go/cmd/gruff-go@v9.9.9
EOF
    cat >"$root/SECURITY.md" <<'EOF'
| `0.9.x` (current public line) | no |
| `1.2.x` (current public line) | yes |
| `9.9.x` (current public line) | future |
EOF
    printf '%s\n' "This source tree currently reports gruff-go version \`1.2.3\`." >"$root/CONTRIBUTING.md"
    cat >"$root/docs/output-formats.md" <<'EOF'
gruff-go 1.2.3 analyse
  "tool": { "name": "gruff-go", "version": "1.2.3" }
EOF
    cat >"$root/docs/ci-integration.md" <<'EOF'
go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.9.0
EOF
    cat >"$root/docs/unrelated.md" <<'EOF'
Go 1.25.0, SARIF 2.1.0, actions/example@v4.1.0, and 127.0.0.1 are not gruff-go release references.
Historical migration: v0.2.0 introduced an old behavior.
EOF
    printf '%s\n' 'Public install: go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.9.0' >"$root/.goat-flow/architecture.md"
    printf '%s\n' 'Public install: go install github.com/blundergoat/gruff-go/cmd/gruff-go@v9.9.9' >"$root/.goat-flow/code-map.md"

    before=$(hash_tree "$root")
    run_checker "$root" "1.2.3" "$TMP_DIR/class.out" "$TMP_DIR/class.err" "$TMP_DIR/class.status" "$guard_bin"
    after=$(hash_tree "$root")
    status=$(<"$TMP_DIR/class.status")
    output=$(<"$TMP_DIR/class.out")
    expected=$'published-install\t.goat-flow/architecture.md\t1\tv0.9.0\npublished-install\t.goat-flow/code-map.md\t1\tv9.9.9\npublished-install\tREADME.md\t1\t1.2.3\npublished-install\tREADME.md\t2\tv0.9.0\npublished-install\tREADME.md\t3\tv1.2.3\npublished-install\tREADME.md\t4\tv9.9.9\npublished-install\tdocs/ci-integration.md\t1\tv0.9.0\nsecurity-support\tSECURITY.md\t1\t0.9.x\nsecurity-support\tSECURITY.md\t2\t1.2.x\nsecurity-support\tSECURITY.md\t3\t9.9.x\nsource-current\tCONTRIBUTING.md\t1\t1.2.3\nsource-current\tdocs/output-formats.md\t1\t1.2.3\nsource-current\tdocs/output-formats.md\t2\t1.2.3\nsource-current\tinternal/analysis/report.go\t1\t0.9.0\nsource-current\tinternal/cli/cli.go\t1\t1.2.3\nsource-current\tinternal/cli/testdata/golden/a-text.golden\t1\t1.2.3\nsource-current\tinternal/cli/testdata/golden/b-summary.golden\t2\t0.9.0\nsource-current\tinternal/cli/testdata/golden/c-sarif.golden\t1\t9.9.9\nsource-current\tinternal/report/machine_test.go\t1\t9.9.9\nsource-current\tpackage-lock.json\t3\t1.2.3\nsource-current\tpackage-lock.json\t8\t1.2.3\nsource-current\tpackage.json\t3\t1.2.3\nunclassified\tAGENTS.md\t1\tv7.7.7'
    assert_equal "1" "$status" "mismatched/unclassified fixture exit"
    assert_equal "$expected" "$output" "stable reference rows"
    assert_equal "$before" "$after" "check mode fixture hash"
    [[ ! -e "$TMP_DIR/mutation-called" ]] || fail "check mode invoked a mutation-only tool"
    TESTS_RUN=$((TESTS_RUN + 1))
}

# test_clean_review_rows proves published/security drift is review-only.
test_clean_review_rows() {
    local root="$TMP_DIR/clean" guard_bin="$TMP_DIR/clean-guard" status output
    write_source_tree "$root" "2.1.0" "2.1.0" "2.1.0"
    write_guard_tools "$guard_bin"
    mkdir -p "$root/docs"
    cat >"$root/internal/cli/testdata/golden/summary.golden" <<'EOF'
  "version": "2.1.0",
  "name": "gruff-go",
  "version": "2.1.0"
EOF
    printf '%s\n' 'go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.9.0' >"$root/README.md"
    printf '%s\n' "| \`0.9.x\` (current public line) | yes |" >"$root/SECURITY.md"
    printf '%s\n' "This source tree currently reports gruff-go version \`2.1.0\`." >"$root/CONTRIBUTING.md"
    printf '%s\n' '# AGENTS.md - v1.13.1 (2026-07-13)' >"$root/AGENTS.md"
    run_checker "$root" "2.1.0" "$TMP_DIR/clean.out" "$TMP_DIR/clean.err" "$TMP_DIR/clean.status" "$guard_bin"
    status=$(<"$TMP_DIR/clean.status")
    output=$(<"$TMP_DIR/clean.out")
    assert_equal "0" "$status" "review-only fixture exit"
    assert_contains "$output" $'published-install\tREADME.md\t1\tv0.9.0' "published review row"
    assert_contains "$output" $'security-support\tSECURITY.md\t1\t0.9.x' "security review row"
    assert_contains "$output" $'source-current\tinternal/cli/testdata/golden/summary.golden\t3\t2.1.0' "tool version beside SARIF 2.1.0"
    TESTS_RUN=$((TESTS_RUN + 1))
}

# test_instruction_header_ownership proves the Claude and Copilot product headers
# are owned source references, so a stale instruction title cannot ship unnoticed.
test_instruction_header_ownership() {
    local root="$TMP_DIR/instruction" guard_bin="$TMP_DIR/instruction-guard" status output
    write_source_tree "$root" "2.1.0" "2.1.0" "2.1.0"
    write_guard_tools "$guard_bin"
    mkdir -p "$root/.github"
    printf '%s\n' '# gruff-go - Go code-quality scanner (v2.1.0)' >"$root/CLAUDE.md"
    printf '%s\n' '# gruff-go - Go code-quality scanner (v2.1.0)' >"$root/.github/copilot-instructions.md"
    # AGENTS.md keeps a GOAT Flow header, which stays outside gruff-go ownership.
    printf '%s\n' '# AGENTS.md - v1.13.1 (2026-07-13)' >"$root/AGENTS.md"
    run_checker "$root" "2.1.0" "$TMP_DIR/instruction.out" "$TMP_DIR/instruction.err" \
        "$TMP_DIR/instruction.status" "$guard_bin"
    status=$(<"$TMP_DIR/instruction.status")
    output=$(<"$TMP_DIR/instruction.out")
    assert_equal "0" "$status" "current instruction headers exit"
    assert_contains "$output" $'source-current\tCLAUDE.md\t1\tv2.1.0' "Claude header owned row"
    assert_contains "$output" $'source-current\t.github/copilot-instructions.md\t1\tv2.1.0' "Copilot header owned row"
    [[ "$output" != *"AGENTS.md"* ]] || fail "GOAT Flow AGENTS header claimed gruff-go ownership"

    # A stale header is the drift this ownership exists to catch.
    printf '%s\n' '# gruff-go - Go code-quality scanner (v0.2.0)' >"$root/CLAUDE.md"
    run_checker "$root" "2.1.0" "$TMP_DIR/instruction-stale.out" "$TMP_DIR/instruction-stale.err" \
        "$TMP_DIR/instruction-stale.status" "$guard_bin"
    status=$(<"$TMP_DIR/instruction-stale.status")
    output=$(<"$TMP_DIR/instruction-stale.out")
    assert_equal "1" "$status" "stale instruction header exit"
    assert_contains "$output" $'source-current\tCLAUDE.md\t1\tv0.2.0' "stale Claude header row"
    TESTS_RUN=$((TESTS_RUN + 1))
}

# test_invalid_arguments pins input validation without needing repository state.
test_invalid_arguments() {
    local root="$TMP_DIR/invalid" status args
    local -a expanded=()
    mkdir -p "$root"
    # Each bad invocation models a release reviewer mistyping one required input.
    for args in \
        "--check-references --root $root" \
        "--check-references --root $root --source-version v1.2.3" \
        "--check-references --root $root/missing --source-version 1.2.3" \
        "--check-references --wat $root --source-version 1.2.3"
    do
        read -r -a expanded <<<"$args"
        set +e
        "$SCRIPT_UNDER_TEST" "${expanded[@]}" >"$TMP_DIR/invalid.out" 2>"$TMP_DIR/invalid.err"
        status=$?
        set -e
        assert_equal "1" "$status" "invalid arguments [$args]"
    done
    TESTS_RUN=$((TESTS_RUN + 1))
}

# test_already_current_noop proves the normal one-argument no-op still scans only.
test_already_current_noop() {
    local root="$TMP_DIR/noop" guard_bin="$TMP_DIR/noop-guard"
    local before after status output diagnostic
    write_source_tree "$root" "1.2.3" "1.2.3" "1.2.3"
    mkdir -p "$root/scripts" "$root/docs"
    cp "$SCRIPT_UNDER_TEST" "$root/scripts/bump-version.sh"
    chmod +x "$root/scripts/bump-version.sh"
    printf 'gruff-go 1.2.3 analyse\n' >"$root/internal/cli/testdata/golden/text.golden"
    printf '%s\n' "This source tree currently reports gruff-go version \`1.2.3\`." >"$root/CONTRIBUTING.md"
    write_guard_tools "$guard_bin"
    before=$(hash_tree "$root")
    set +e
    MUTATION_MARKER="$TMP_DIR/noop-mutation-called" PATH="$guard_bin:$PATH" \
        "$root/scripts/bump-version.sh" 1.2.3 >"$TMP_DIR/noop.out" 2>"$TMP_DIR/noop.err"
    status=$?
    set -e
    after=$(hash_tree "$root")
    output=$(<"$TMP_DIR/noop.out")
    diagnostic=$(<"$TMP_DIR/noop.err")
    assert_equal "0" "$status" "already-current no-op exit"
    assert_equal "$before" "$after" "already-current tree hash"
    assert_contains "$output" $'source-current\tinternal/cli/cli.go\t1\t1.2.3' "already-current scanner output"
    assert_contains "$diagnostic" "current version is already 1.2.3" "already-current diagnostic"
    [[ ! -e "$TMP_DIR/noop-mutation-called" ]] || fail "already-current path invoked mutation-only tooling"
    TESTS_RUN=$((TESTS_RUN + 1))
}

test_classification_and_order
test_clean_review_rows
test_instruction_header_ownership
test_invalid_arguments
test_already_current_noop

printf 'PASS bump-version reference fixtures (%d tests)\n' "$TESTS_RUN"
