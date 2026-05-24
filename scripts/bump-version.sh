#!/usr/bin/env bash
# bump-version.sh - update every in-tree gruff-go version literal in one shot.
#
# Usage:
#   scripts/bump-version.sh <new-version>
#
# Updates:
#   internal/cli/cli.go          (const toolVersion)
#   internal/analysis/report.go  (Tool.Version literal)
#   internal/report/machine_test.go (SARIF driver assertion)
#   package.json                 (version field)
#   package-lock.json            (root package version fields)
#   internal/cli/testdata/golden/*.golden (regenerated via UPDATE_GOLDEN=1)
#
# Does NOT touch CHANGELOG.md, README.md, SECURITY.md, or docs/. Those carry
# release narrative or "pre-release" framing that changes per release rather
# than per bump, so they stay hand-edited.
#
# After the script finishes it prints a checklist of files that still reference
# the old version so the human can decide whether each is a stale literal or
# intentional history.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_DIM=""; C_OFF=""
fi
log()  { printf '%s\n' "$*" >&2; }
ok()   { printf '%s%s%s\n' "$C_GRN" "$*" "$C_OFF" >&2; }
warn() { printf '%s%s%s\n' "$C_YEL" "$*" "$C_OFF" >&2; }
fail() { printf '%s%s%s\n' "$C_RED" "$*" "$C_OFF" >&2; exit 1; }

if [[ $# -ne 1 ]]; then
  fail "usage: $(basename "$0") <new-version>  (e.g. 1.2.3, 1.3.0-rc.1)"
fi

NEW_VERSION="$1"

# SemVer-ish validation: MAJOR.MINOR.PATCH plus optional pre-release / build
# identifiers. Rejects an obvious typo like "v1.2.3" or "1.2".
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  fail "version '$NEW_VERSION' does not look like SemVer (expected MAJOR.MINOR.PATCH[-pre][+build])"
fi

CLI_FILE="$REPO_ROOT/internal/cli/cli.go"
REPORT_FILE="$REPO_ROOT/internal/analysis/report.go"
MACHINE_TEST_FILE="$REPO_ROOT/internal/report/machine_test.go"
PKG_JSON="$REPO_ROOT/package.json"
PKG_LOCK="$REPO_ROOT/package-lock.json"

for path in "$CLI_FILE" "$REPORT_FILE" "$MACHINE_TEST_FILE" "$PKG_JSON" "$PKG_LOCK"; do
  [[ -f "$path" ]] || fail "missing expected file: $path"
done

# Discover current version from cli.go (single source of truth-ish).
CURRENT_VERSION=$(grep -oE 'const toolVersion = "[^"]+"' "$CLI_FILE" \
  | sed -E 's/.*"([^"]+)"/\1/')
if [[ -z "$CURRENT_VERSION" ]]; then
  fail "could not parse current version from $CLI_FILE"
fi

if [[ "$CURRENT_VERSION" == "$NEW_VERSION" ]]; then
  warn "current version is already $NEW_VERSION; nothing to do"
  exit 0
fi

if ! command -v node >/dev/null 2>&1; then
  fail "node is required to update package.json and package-lock.json safely"
fi

log "${C_DIM}bumping $CURRENT_VERSION -> $NEW_VERSION${C_OFF}"

# sed -i differs between GNU and BSD. Use a portable in-place wrapper.
sed_inplace() {
  local file="$1" expr="$2"
  if sed --version >/dev/null 2>&1; then
    sed -i -E "$expr" "$file"
  else
    sed -i '' -E "$expr" "$file"
  fi
}

escape_sed_ere() {
  printf '%s' "$1" | sed -e 's/[][(){}.^$*+?|\\]/\\&/g'
}

package_metadata_versions() {
  local mode="$1" current="$2" next="${3:-$2}"
  node - "$PKG_JSON" "$PKG_LOCK" "$mode" "$current" "$next" <<'NODE'
const fs = require("fs");

const [packagePath, lockPath, mode, currentVersion, nextVersion] = process.argv.slice(2);

if (mode !== "check" && mode !== "write") {
  throw new Error(`unsupported package metadata mode: ${mode}`);
}

function readJSON(path) {
  try {
    return JSON.parse(fs.readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`${path}: ${error.message}`);
  }
}

function expectVersion(path, field, actual, expected) {
  if (actual !== expected) {
    throw new Error(`${path}: expected ${field} to be ${expected}, got ${actual}`);
  }
}

const packageJSON = readJSON(packagePath);
expectVersion(packagePath, "version", packageJSON.version, currentVersion);

const packageLock = readJSON(lockPath);
expectVersion(lockPath, "version", packageLock.version, currentVersion);
if (!packageLock.packages || !packageLock.packages[""]) {
  throw new Error(`${lockPath}: missing packages[""] root package entry`);
}
expectVersion(lockPath, 'packages[""].version', packageLock.packages[""].version, currentVersion);

if (mode === "write") {
  packageJSON.version = nextVersion;
  fs.writeFileSync(packagePath, `${JSON.stringify(packageJSON, null, 2)}\n`);

  packageLock.version = nextVersion;
  packageLock.packages[""].version = nextVersion;
  fs.writeFileSync(lockPath, `${JSON.stringify(packageLock, null, 2)}\n`);
}
NODE
}

CURRENT_VERSION_PATTERN=$(escape_sed_ere "$CURRENT_VERSION")

for entry in \
  "$CLI_FILE:const toolVersion = \"${CURRENT_VERSION}\"" \
  "$REPORT_FILE:Version: \"${CURRENT_VERSION}\"" \
  "$MACHINE_TEST_FILE:SemanticVersion != \"${CURRENT_VERSION}\""
do
  file="${entry%%:*}"
  needle="${entry#*:}"
  if ! grep -qF "$needle" "$file"; then
    fail "pre-edit check failed: '$needle' not present in $file"
  fi
done
package_metadata_versions check "$CURRENT_VERSION"

# Anchor each replacement to its surrounding context so we don't accidentally
# touch an unrelated string that happens to match the old version.
sed_inplace "$CLI_FILE"          "s|(const toolVersion = )\"${CURRENT_VERSION_PATTERN}\"|\\1\"${NEW_VERSION}\"|"
sed_inplace "$REPORT_FILE"       "s|(Version:[[:space:]]+)\"${CURRENT_VERSION_PATTERN}\"|\\1\"${NEW_VERSION}\"|"
sed_inplace "$MACHINE_TEST_FILE" "s|(SemanticVersion != )\"${CURRENT_VERSION_PATTERN}\"|\\1\"${NEW_VERSION}\"|"
package_metadata_versions write "$CURRENT_VERSION" "$NEW_VERSION"

# Verify each anchor actually hit.
for entry in \
  "$CLI_FILE:const toolVersion = \"${NEW_VERSION}\"" \
  "$REPORT_FILE:Version: \"${NEW_VERSION}\"" \
  "$MACHINE_TEST_FILE:SemanticVersion != \"${NEW_VERSION}\"" \
  "$PKG_JSON:\"version\": \"${NEW_VERSION}\"" \
  "$PKG_LOCK:\"version\": \"${NEW_VERSION}\""
do
  file="${entry%%:*}"
  needle="${entry#*:}"
  if ! grep -qF "$needle" "$file"; then
    fail "post-edit check failed: '$needle' not present in $file"
  fi
done

ok "updated cli.go, report.go, machine_test.go, package.json, package-lock.json"

# Regenerate every CLI golden snapshot so SARIF / summary-json / etc. carry
# the new version. UPDATE_GOLDEN=1 is the convention defined in golden_test.go.
log "${C_DIM}regenerating CLI golden snapshots ...${C_OFF}"
(
  cd "$REPO_ROOT"
  UPDATE_GOLDEN=1 go test ./internal/cli/... >/dev/null
)
ok "regenerated goldens"

# Sanity sweep: anything in tracked source files still naming the old version?
# We exclude history, agent instructions, and local tooling surfaces that can
# intentionally carry old examples or point-in-time records.
log ""
log "scanning for remaining references to ${CURRENT_VERSION} ..."
if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  remaining=$(git -C "$REPO_ROOT" grep -IlF -- "$CURRENT_VERSION" -- . \
    ':!CHANGELOG.md' \
    ':!AGENTS.md' \
    ':!CLAUDE.md' \
    ':!GEMINI.md' \
    ':!.goat-flow/**' \
    ':!.agents/**' \
    ':!.claude/**' \
    ':!.codex/**' \
    ':!.gemini/**' \
    ':!.idea/**' \
    ':!node_modules/**' \
    2>/dev/null || true)
else
  remaining=$(grep -RIlF --exclude-dir=.git --exclude-dir=node_modules \
                         --exclude-dir=.perf-corpus --exclude-dir=.perf-results \
                         --exclude-dir=.goat-flow --exclude-dir=.agents \
                         --exclude-dir=.claude --exclude-dir=.codex --exclude-dir=.gemini \
                         --exclude-dir=.idea \
                         --exclude=AGENTS.md --exclude=CLAUDE.md --exclude=GEMINI.md \
                         --exclude=CHANGELOG.md \
                         -- "$CURRENT_VERSION" "$REPO_ROOT" 2>/dev/null || true)
fi

if [[ -z "$remaining" ]]; then
  ok "no stale references to ${CURRENT_VERSION} outside CHANGELOG.md"
else
  warn "the following files still mention ${CURRENT_VERSION}; review and update manually if they should track the bump:"
  printf '%s\n' "$remaining" | sed 's|^|  - |' >&2
fi

cat <<EOF >&2

Next steps:
  - Update CHANGELOG.md with the release entry for ${NEW_VERSION}.
  - Run \`make check\` to confirm tests pass.
  - Run \`go run ./cmd/gruff-go analyse .\` to confirm the binary dogfoods clean.
  - Commit the changes and tag \`v${NEW_VERSION}\` once review lands.
EOF
