#!/usr/bin/env bash
# Updates source-version literals for a release and audits owned references.
# Users run normal mode when preparing a reviewed source-version bump.
# Release reviewers use check mode to separate source, published, and security
# ownership without changing files or advertising an unpublished tag.
#
# Usage:
#   scripts/bump-version.sh <new-version>
#   scripts/bump-version.sh --check-references --root <tree> --source-version <X.Y.Z>
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
# After the mutation path, the same read-only scanner rejects stale source
# references and prints published/security rows for human review.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Interactive users get colour; redirected release logs stay plain text.
if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_DIM=""; C_OFF=""
fi
# log writes neutral release progress for the operator.
log() {
  printf '%s\n' "$*" >&2
}

# ok marks a release step that completed successfully.
ok() {
  printf '%s%s%s\n' "$C_GRN" "$*" "$C_OFF" >&2
}

# warn highlights a review decision without treating it as a failure.
warn() {
  printf '%s%s%s\n' "$C_YEL" "$*" "$C_OFF" >&2
}

# fail stops before the user can rely on incomplete release state.
fail() {
  printf '%s%s%s\n' "$C_RED" "$*" "$C_OFF" >&2
  exit 1
}

SOURCE_VERSION_REGEX='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
REFERENCE_TOKEN_REGEX='(^|[^0-9A-Za-z_.-])(v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?)([^0-9A-Za-z_.-]|$)'
VERSION_SERIES_REGEX='(^|[^0-9A-Za-z_.-])([0-9]+\.[0-9]+\.x)([^0-9A-Za-z_.-]|$)'

REFERENCE_SOURCE_VERSION=''
REFERENCE_CHECK_FAILED=0
REFERENCE_ROWS=()

# record_reference adds one stable review row and tracks source drift.
record_reference() {
  local category=$1 relative_path=$2 line_number=$3 literal=$4
  local comparable_literal=${literal#v}
  REFERENCE_ROWS+=("${category}"$'\t'"${relative_path}"$'\t'"${line_number}"$'\t'"${literal}")

  # A source-owned literal must describe the binary users are building now.
  if [[ "$category" == "source-current" && "$comparable_literal" != "$REFERENCE_SOURCE_VERSION" ]]; then
    REFERENCE_CHECK_FAILED=1
  fi

  # An unowned gruff-go version can silently mislead install or support choices.
  if [[ "$category" == "unclassified" ]]; then
    REFERENCE_CHECK_FAILED=1
  fi
}

# record_semver_from_line extracts one gruff-go release token from an owned line.
record_semver_from_line() {
  local category=$1 relative_path=$2 line_number=$3 line_text=$4

  # Lines without a three-part release token do not belong in this inventory.
  if [[ "$line_text" =~ $REFERENCE_TOKEN_REGEX ]]; then
    record_reference "$category" "$relative_path" "$line_number" "${BASH_REMATCH[2]}"
  fi
}

# record_series_from_line extracts a public support line such as 0.4.x.
record_series_from_line() {
  local category=$1 relative_path=$2 line_number=$3 line_text=$4

  # A missing release series means the prose is not a version-owned row.
  if [[ "$line_text" =~ $VERSION_SERIES_REGEX ]]; then
    record_reference "$category" "$relative_path" "$line_number" "${BASH_REMATCH[2]}"
  fi
}

# scan_source_anchor_file checks one script-owned literal in source or metadata.
scan_source_anchor_file() {
  local root=$1 relative_path=$2 required_marker=$3
  local line_number=0 line_text full_path="$root/$relative_path"

  # Minimal non-Git fixtures may omit source surfaces they are not exercising.
  if [[ ! -f "$full_path" ]]; then
    return 0
  fi

  # Each matching line represents version output a source user can observe.
  while IFS= read -r line_text || [[ -n "$line_text" ]]; do
    line_number=$((line_number + 1))
    # The marker prevents unrelated dependency or schema versions from leaking in.
    if [[ "$line_text" == *"$required_marker"* ]]; then
      record_semver_from_line "source-current" "$relative_path" "$line_number" "$line_text"
    fi
  done <"$full_path"
}

# scan_package_lock_versions reads only npm's top-level and root-package versions.
scan_package_lock_versions() {
  local root=$1 relative_path="package-lock.json"
  local full_path="$root/package-lock.json"
  local line_number=0 line_text root_package_open=0

  # A fixture without npm metadata can still exercise documentation ownership.
  if [[ ! -f "$full_path" ]]; then
    return 0
  fi

  # The formatted lockfile identifies its root package before dependency entries.
  while IFS= read -r line_text || [[ -n "$line_text" ]]; do
    line_number=$((line_number + 1))
    # This is the lockfile's own version, shown at two-space indentation.
    if [[ "$line_text" =~ ^[[:space:]][[:space:]]\"version\"[[:space:]]*: ]]; then
      record_semver_from_line "source-current" "$relative_path" "$line_number" "$line_text"
    fi
    # npm renders packages[""] with this exact four-space key.
    if [[ "$line_text" =~ ^[[:space:]]{4}\"\"[[:space:]]*: ]]; then
      root_package_open=1
      continue
    fi
    # The first six-space version after packages[""] is the user-installed root.
    if ((root_package_open == 1)) && [[ "$line_text" =~ ^[[:space:]]{6}\"version\"[[:space:]]*: ]]; then
      record_semver_from_line "source-current" "$relative_path" "$line_number" "$line_text"
      root_package_open=0
    fi
  done <"$full_path"
}

# scan_golden_versions inventories CLI output users compare in snapshots.
scan_golden_versions() {
  local root=$1
  local golden_root="$root/internal/cli/testdata/golden"
  local golden_path relative_path line_number line_text gruff_tool_version_pending
  local -a golden_files=()

  # A focused fixture need not create the golden directory.
  if [[ ! -d "$golden_root" ]]; then
    return 0
  fi
  mapfile -t golden_files < <(find "$golden_root" -type f -name '*.golden' -print | LC_ALL=C sort)

  # Every snapshot is scanned in path order so review output stays reproducible.
  for golden_path in "${golden_files[@]}"; do
    relative_path=${golden_path#"$root"/}
    line_number=0
    gruff_tool_version_pending=0
    # Only mastheads and tool-version fields represent the gruff-go release.
    while IFS= read -r line_text || [[ -n "$line_text" ]]; do
      line_number=$((line_number + 1))
      # A named gruff-go tool block owns the next ordinary JSON version field.
      if [[ "$line_text" == *'"name": "gruff-go"'* ]]; then
        gruff_tool_version_pending=1
      fi
      # Text mastheads and SARIF semanticVersion fields name gruff-go directly.
      if [[ "$line_text" == gruff-go\ * || "$line_text" == *'"semanticVersion":'* ]]; then
        record_semver_from_line "source-current" "$relative_path" "$line_number" "$line_text"
        gruff_tool_version_pending=0
        continue
      fi
      # This ignores SARIF's document version while retaining a same-valued tool version.
      if ((gruff_tool_version_pending == 1)) && [[ "$line_text" == *'"version":'* ]]; then
        record_semver_from_line "source-current" "$relative_path" "$line_number" "$line_text"
        gruff_tool_version_pending=0
      fi
    done <"$golden_path"
  done
}

# scan_owned_prose_file classifies current docs while leaving history silent.
scan_owned_prose_file() {
  local root=$1 relative_path=$2
  local full_path="$root/$relative_path"
  local line_number=0 line_text unclassified_candidate=0

  # Missing optional docs are normal in small non-Git fixtures.
  if [[ ! -f "$full_path" ]]; then
    return 0
  fi

  # Readers encounter these lines as install, support, or source-state guidance.
  while IFS= read -r line_text || [[ -n "$line_text" ]]; do
    line_number=$((line_number + 1))

    # Module pins must name an already published version users can fetch.
    if [[ "$line_text" == *'github.com/blundergoat/gruff-go/cmd/gruff-go@v'* ]]; then
      record_semver_from_line "published-install" "$relative_path" "$line_number" "$line_text"
      continue
    fi
    # README labels this value as the currently published package line.
    if [[ "$relative_path" == "README.md" && "$line_text" == *'Published `'*' package line'* ]]; then
      record_semver_from_line "published-install" "$relative_path" "$line_number" "$line_text"
      continue
    fi
    # SECURITY owns the public minor line that still receives fixes.
    if [[ "$relative_path" == "SECURITY.md" && "$line_text" == *'current public line'* ]]; then
      record_series_from_line "security-support" "$relative_path" "$line_number" "$line_text"
      continue
    fi
    # CONTRIBUTING tells source builders which version the checkout reports.
    if [[ "$relative_path" == "CONTRIBUTING.md" && "$line_text" == *'source tree currently reports gruff-go version'* ]]; then
      record_semver_from_line "source-current" "$relative_path" "$line_number" "$line_text"
      continue
    fi
    # This recognizes the stale pre-M16 contributing wording for migration.
    if [[ "$relative_path" == "CONTRIBUTING.md" && "$line_text" == *'currently on the `'*' line'* ]]; then
      record_series_from_line "source-current" "$relative_path" "$line_number" "$line_text"
      continue
    fi
    # Output examples must match the binary built from the same source tree.
    if [[ "$relative_path" == "docs/output-formats.md" && ( "$line_text" == gruff-go\ * || "$line_text" == *'"name": "gruff-go"'* ) ]]; then
      record_semver_from_line "source-current" "$relative_path" "$line_number" "$line_text"
      continue
    fi

    # Product-labelled agent instruction headers state the version this checkout
    # reports, so they are owned source references rather than published pins.
    # AGENTS.md is excluded on purpose: its header carries a GOAT Flow version.
    if [[ ( "$relative_path" == "CLAUDE.md" || "$relative_path" == ".github/copilot-instructions.md" ) \
      && "$line_number" -eq 1 && "$line_text" == *'gruff-go'* ]]; then
      record_semver_from_line "source-current" "$relative_path" "$line_number" "$line_text"
      continue
    fi

    unclassified_candidate=0
    # A product-labelled instruction header needs ownership, while an AGENTS or
    # GOAT Flow instruction-file version is not a gruff-go release reference.
    if [[ "$relative_path" == "AGENTS.md" && "$line_number" -eq 1 && "$line_text" == *'gruff-go'* ]]; then
      unclassified_candidate=1
    fi
    # Generic explicit version prose needs an owner before users can trust it.
    if [[ "$line_text" == *'gruff-go version'* || "$line_text" =~ gruff-go[[:space:]]+v?[0-9] ]]; then
      unclassified_candidate=1
    fi
    # Only a line that also contains a release token becomes a failing row.
    if ((unclassified_candidate == 1)); then
      record_semver_from_line "unclassified" "$relative_path" "$line_number" "$line_text"
    fi
  done <"$full_path"
}

# scan_owned_prose visits only current-state surfaces with named ownership.
scan_owned_prose() {
  local root=$1 documentation_path
  local -a owned_paths=(
    "AGENTS.md"
    "CLAUDE.md"
    ".github/copilot-instructions.md"
    "README.md"
    "SECURITY.md"
    "CONTRIBUTING.md"
  )

  # User docs are current-state unless a line is explicitly historical.
  if [[ -d "$root/docs" ]]; then
    while IFS= read -r documentation_path; do
      owned_paths+=("${documentation_path#"$root"/}")
    done < <(find "$root/docs" -type f -name '*.md' -print | LC_ALL=C sort)
  fi
  owned_paths+=(
    ".goat-flow/architecture.md"
    ".goat-flow/code-map.md"
    ".goat-flow/glossary.md"
  )

  # Fixed path order plus final row sorting makes output stable across hosts.
  for documentation_path in "${owned_paths[@]}"; do
    scan_owned_prose_file "$root" "$documentation_path"
  done
}

# check_version_references performs the reusable non-mutating ownership scan.
check_version_references() {
  local root=$1 source_version=$2
  REFERENCE_SOURCE_VERSION=$source_version
  REFERENCE_CHECK_FAILED=0
  REFERENCE_ROWS=()

  scan_source_anchor_file "$root" "internal/cli/cli.go" 'const toolVersion = '
  scan_source_anchor_file "$root" "internal/analysis/report.go" 'Version: '
  scan_source_anchor_file "$root" "internal/report/machine_test.go" 'SemanticVersion != '
  scan_source_anchor_file "$root" "package.json" '"version":'
  scan_package_lock_versions "$root"
  scan_golden_versions "$root"
  scan_owned_prose "$root"

  # Review rows are sorted by owner, path, numeric line, then literal.
  if ((${#REFERENCE_ROWS[@]} > 0)); then
    printf '%s\n' "${REFERENCE_ROWS[@]}" | LC_ALL=C sort -t $'\t' -k1,1 -k2,2 -k3,3n -k4,4
  fi

  # Source drift and unclassified versions block a release preparation.
  if ((REFERENCE_CHECK_FAILED == 1)); then
    return 1
  fi
}

# run_reference_check_mode validates scanner inputs before reading the tree.
run_reference_check_mode() {
  local reference_root='' source_version=''
  shift

  # Reviewers may supply flags in either order, but each needs one value.
  while (($# > 0)); do
    case "$1" in
      --root)
        # An empty/missing root cannot identify the current-state documents.
        if (($# < 2)) || [[ -z "$2" ]]; then
          fail "--root requires a non-empty directory"
        fi
        reference_root=$2
        shift 2
        ;;
      --source-version)
        # An empty/missing source version cannot detect stale current prose.
        if (($# < 2)) || [[ -z "$2" ]]; then
          fail "--source-version requires MAJOR.MINOR.PATCH"
        fi
        source_version=$2
        shift 2
        ;;
      *)
        fail "unknown --check-references argument: $1"
        ;;
    esac
  done

  # Both owners are required so the check cannot silently use checkout state.
  if [[ -z "$reference_root" || -z "$source_version" ]]; then
    fail "usage: $(basename "$0") --check-references --root <tree> --source-version <X.Y.Z>"
  fi
  # A non-directory root is usually a typo in a fixture or release command.
  if [[ ! -d "$reference_root" ]]; then
    fail "reference root is not a directory: $reference_root"
  fi
  # Source input deliberately rejects a leading v used only by release tags.
  if ! [[ "$source_version" =~ $SOURCE_VERSION_REGEX ]]; then
    fail "source version '$source_version' must be MAJOR.MINOR.PATCH[-pre][+build] without a leading v"
  fi

  check_version_references "$(cd "$reference_root" && pwd)" "$source_version"
}

# Check mode exits before package tools, golden generation, or file mutation.
if [[ "${1:-}" == "--check-references" ]]; then
  run_reference_check_mode "$@"
  exit $?
fi

# Normal mode preserves the established one-version release interface.
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

# A release bump needs every owned anchor before it can safely begin.
for path in "$CLI_FILE" "$REPORT_FILE" "$MACHINE_TEST_FILE" "$PKG_JSON" "$PKG_LOCK"; do
  [[ -f "$path" ]] || fail "missing expected file: $path"
done

# Read the version users currently see from the CLI source of truth.
CURRENT_VERSION=$(grep -oE 'const toolVersion = "[^"]+"' "$CLI_FILE" \
  | sed -E 's/.*"([^"]+)"/\1/')
# Missing CLI version text means the release cannot identify its starting point.
if [[ -z "$CURRENT_VERSION" ]]; then
  fail "could not parse current version from $CLI_FILE"
fi

# An already-current request still audits docs and never reaches mutation tools.
if [[ "$CURRENT_VERSION" == "$NEW_VERSION" ]]; then
  warn "current version is already $NEW_VERSION; checking owned references only"
  # Stale source prose must still fail when no literal replacement is needed.
  if ! check_version_references "$REPO_ROOT" "$NEW_VERSION"; then
    fail "owned source references do not match $NEW_VERSION"
  fi
  exit 0
fi

# Node safely rewrites JSON metadata for users preparing a real version change.
if ! command -v node >/dev/null 2>&1; then
  fail "node is required to update package.json and package-lock.json safely"
fi

log "${C_DIM}bumping $CURRENT_VERSION -> $NEW_VERSION${C_OFF}"

# sed_inplace updates one anchored source literal across GNU and BSD systems.
sed_inplace() {
  local file="$1" expr="$2"
  # GNU sed identifies itself; macOS/BSD sed needs an empty backup suffix.
  if sed --version >/dev/null 2>&1; then
    sed -i -E "$expr" "$file"
  else
    sed -i '' -E "$expr" "$file"
  fi
}

# escape_sed_ere keeps a user-supplied version literal from changing the pattern.
escape_sed_ere() {
  printf '%s' "$1" | sed -e 's/[][(){}.^$*+?|\\]/\\&/g'
}

# package_metadata_versions checks or writes the two npm root-version owners.
package_metadata_versions() {
  local mode="$1" current="$2" next="${3:-$2}"
  node - "$PKG_JSON" "$PKG_LOCK" "$mode" "$current" "$next" <<'NODE'
const fs = require("fs");

const [packagePath, lockPath, mode, currentVersion, nextVersion] = process.argv.slice(2);

// A bad internal mode means the release helper was called incorrectly.
if (mode !== "check" && mode !== "write") {
  throw new Error(`unsupported package metadata mode: ${mode}`);
}

// readJSON loads metadata users install with the repository tooling.
function readJSON(path) {
  try {
    return JSON.parse(fs.readFileSync(path, "utf8"));
  // A contributor can reach this when package metadata is malformed or unreadable.
  } catch (error) {
    throw new Error(`${path}: ${error.message}`);
  }
}

// expectVersion stops a release when one package owner still shows another version.
function expectVersion(path, field, actual, expected) {
  // Users must never receive package metadata that disagrees with the CLI.
  if (actual !== expected) {
    throw new Error(`${path}: expected ${field} to be ${expected}, got ${actual}`);
  }
}

const packageJSON = readJSON(packagePath);
expectVersion(packagePath, "version", packageJSON.version, currentVersion);

const packageLock = readJSON(lockPath);
expectVersion(lockPath, "version", packageLock.version, currentVersion);
// A missing root entry means npm cannot describe the package being released.
if (!packageLock.packages || !packageLock.packages[""]) {
  throw new Error(`${lockPath}: missing packages[""] root package entry`);
}
expectVersion(lockPath, 'packages[""].version', packageLock.packages[""].version, currentVersion);

// Write mode runs only after every old metadata value was checked.
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

# Pre-edit anchors ensure a contributor cannot replace an unrelated version.
for entry in \
  "$CLI_FILE:const toolVersion = \"${CURRENT_VERSION}\"" \
  "$REPORT_FILE:Version: \"${CURRENT_VERSION}\"" \
  "$MACHINE_TEST_FILE:SemanticVersion != \"${CURRENT_VERSION}\""
do
  file="${entry%%:*}"
  needle="${entry#*:}"
  # A missing old anchor stops before any source or metadata file changes.
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
# Post-edit anchors confirm every user-visible source owner moved together.
for entry in \
  "$CLI_FILE:const toolVersion = \"${NEW_VERSION}\"" \
  "$REPORT_FILE:Version: \"${NEW_VERSION}\"" \
  "$MACHINE_TEST_FILE:SemanticVersion != \"${NEW_VERSION}\"" \
  "$PKG_JSON:\"version\": \"${NEW_VERSION}\"" \
  "$PKG_LOCK:\"version\": \"${NEW_VERSION}\""
do
  file="${entry%%:*}"
  needle="${entry#*:}"
  # A missing new anchor prevents an incomplete bump from being presented as done.
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

log ""
log "checking owned references for ${NEW_VERSION} ..."
# The same non-mutating scanner used by fixtures closes the normal bump path.
if ! check_version_references "$REPO_ROOT" "$NEW_VERSION"; then
  fail "owned source references do not match $NEW_VERSION; review the rows above"
fi
ok "owned source references match ${NEW_VERSION}; published/security rows require review"

cat <<EOF >&2

Next steps:
  - Update CHANGELOG.md with the release entry for ${NEW_VERSION}.
  - Run \`make check\` to confirm tests pass.
  - Run \`go run ./cmd/gruff-go analyse .\` to confirm the binary dogfoods clean.
  - Commit the changes and tag \`v${NEW_VERSION}\` once review lands.
EOF
