#!/usr/bin/env bash
# publish-go-pkg.sh - publish and verify a gruff-go Go module release.
#
# Go modules are published by pushing a semver tag. This helper keeps the
# local checks, tag push, proxy warm-up, and install verification in one place.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

REMOTE="${REMOTE:-origin}"
RUN_CHECKS=1
PUSH_TAG=1
VERIFY_PROXY=1
VERIFY_INSTALL=1
FETCH_TAGS=1
DRY_RUN=0
ALLOW_NON_MAIN=0
VERSION=""
TMP_DIR=""

usage() {
    cat <<'USAGE'
Usage: scripts/publish-go-pkg.sh [version]

Publishes a gruff-go Go module version by pushing its release tag, then verifies
that proxy.golang.org can resolve and install it. If version is omitted, the
script uses internal/cli/cli.go's toolVersion.

Examples:
  scripts/publish-go-pkg.sh 0.2.0
  scripts/publish-go-pkg.sh v0.2.0
  scripts/publish-go-pkg.sh --dry-run 0.2.0

Options:
  --remote <name>       Git remote to publish to (default: origin, or REMOTE).
  --skip-checks         Do not run make check or release preflight.
  --skip-proxy          Do not query proxy.golang.org.
  --skip-install        Do not verify go install from proxy.golang.org.
  --no-push             Validate only; fail if the remote tag is missing.
  --no-fetch            Do not fetch remote tags before validation.
  --allow-non-main      Allow publishing from a branch other than main.
  --dry-run             Print mutating commands without running them.
  -h, --help            Show this help.

Environment:
  GO_PROXY_RETRIES      Proxy lookup attempts before failing (default: 6).
  GO_PROXY_SLEEP        Seconds between proxy lookup attempts (default: 5).
  REMOTE                Default remote when --remote is not supplied.
USAGE
}

log() {
    printf '%s\n' "$*" >&2
}

ok() {
    printf '[ok] %s\n' "$*" >&2
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

print_cmd() {
    printf '+ ' >&2
    printf '%q ' "$@" >&2
    printf '\n' >&2
}

run_cmd() {
    print_cmd "$@"
    if ((DRY_RUN == 1)); then
        return 0
    fi
    "$@"
}

cleanup() {
    if [[ -n "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT

normalize_version() {
    local raw=$1 version
    version="${raw#v}"
    if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
        fail "version '$raw' does not look like SemVer (expected 0.2.0, not arbitrary text)"
    fi
    printf '%s' "$version"
}

source_version() {
    local version
    version=$(grep -oE 'const toolVersion = "[^"]+"' "$REPO_ROOT/internal/cli/cli.go" \
        | sed -E 's/.*"([^"]+)"/\1/')
    if [[ -z "$version" ]]; then
        fail "could not parse toolVersion from internal/cli/cli.go"
    fi
    printf '%s' "$version"
}

source_version_at_ref() {
    local ref=$1 content version
    if ! content=$(git -C "$REPO_ROOT" show "$ref:internal/cli/cli.go" 2>/dev/null); then
        fail "could not read internal/cli/cli.go from $ref"
    fi
    version=$(grep -oE 'const toolVersion = "[^"]+"' <<<"$content" \
        | sed -E 's/.*"([^"]+)"/\1/')
    if [[ -z "$version" ]]; then
        fail "could not parse toolVersion from $ref:internal/cli/cli.go"
    fi
    printf '%s' "$version"
}

module_path() {
    local module
    module=$(awk '$1 == "module" { print $2; exit }' "$REPO_ROOT/go.mod")
    if [[ -z "$module" ]]; then
        fail "could not parse module path from go.mod"
    fi
    printf '%s' "$module"
}

require_tool() {
    local tool=$1
    if ! command -v "$tool" >/dev/null 2>&1; then
        fail "$tool is required"
    fi
}

git_commit() {
    git -C "$REPO_ROOT" rev-parse "$1"
}

local_tag_commit() {
    local tag=$1
    if git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
        git_commit "$tag^{commit}"
    fi
    return 0
}

remote_tag_commit() {
    local tag=$1 peeled direct

    if ! peeled=$(git -C "$REPO_ROOT" ls-remote --tags "$REMOTE" "refs/tags/$tag^{}" \
        | awk '{ print $1; exit }'); then
        fail "could not query $REMOTE for tag $tag"
    fi
    if [[ -n "$peeled" ]]; then
        printf '%s' "$peeled"
        return 0
    fi

    if ! direct=$(git -C "$REPO_ROOT" ls-remote --tags "$REMOTE" "refs/tags/$tag" \
        | awk '{ print $1; exit }'); then
        fail "could not query $REMOTE for tag $tag"
    fi
    printf '%s' "$direct"
}

require_clean_worktree() {
    local status
    status=$(git -C "$REPO_ROOT" status --short)
    if [[ -n "$status" ]]; then
        printf '%s\n' "$status" >&2
        fail "working tree must be clean before publishing"
    fi
}

require_main_branch() {
    local branch
    branch=$(git -C "$REPO_ROOT" branch --show-current)
    if [[ "$branch" != "main" && "$ALLOW_NON_MAIN" -eq 0 ]]; then
        fail "refusing to publish from branch '${branch:-detached HEAD}'; use --allow-non-main to override"
    fi
}

require_upstream_current() {
    local upstream head upstream_head
    upstream=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)
    if [[ -z "$upstream" ]]; then
        log "[warn] no upstream configured for current branch; tag push will still publish the commit"
        return 0
    fi

    head=$(git_commit HEAD)
    upstream_head=$(git_commit "$upstream")
    if [[ "$head" != "$upstream_head" ]]; then
        fail "HEAD ($head) does not match upstream $upstream ($upstream_head); push or pull branch changes first"
    fi
}

run_release_checks() {
    if ((RUN_CHECKS == 0)); then
        log "[skip] release checks"
        return 0
    fi

    run_cmd make check
    run_cmd "$REPO_ROOT/scripts/preflight-checks.sh" --release
}

require_module_path_supports_major() {
    local module=$1 version=$2 major
    major="${version%%.*}"
    if (( major < 2 )); then
        return 0
    fi
    local suffix="/v$major"
    if [[ "$module" != *"$suffix" ]]; then
        fail "publishing v$version requires module path to end with $suffix, but go.mod has '$module'; major versions >= 2 cannot share a module path with v0/v1 under Go's semantic import versioning"
    fi
}

ensure_local_tag() {
    local tag=$1 head local_commit
    head=$(git_commit HEAD)
    local_commit=$(local_tag_commit "$tag")

    if [[ -n "$local_commit" ]]; then
        if [[ "$local_commit" != "$head" ]]; then
            fail "local tag $tag points to $local_commit, not HEAD $head"
        fi
        ok "local tag $tag points at HEAD"
        return 0
    fi

    run_cmd git -C "$REPO_ROOT" tag -a "$tag" -m "gruff-go $tag"
    ok "created local tag $tag"
}

ensure_remote_tag() {
    local tag=$1 local_commit remote_commit
    local_commit=$(local_tag_commit "$tag")
    remote_commit=$(remote_tag_commit "$tag")

    if [[ -n "$remote_commit" ]]; then
        if [[ "$remote_commit" != "$local_commit" ]]; then
            fail "remote tag $tag points to $remote_commit, not local $local_commit"
        fi
        ok "$REMOTE already has $tag"
        return 0
    fi

    if ((PUSH_TAG == 0)); then
        fail "$REMOTE does not have $tag; rerun without --no-push to publish it"
    fi

    run_cmd git -C "$REPO_ROOT" push "$REMOTE" "refs/tags/$tag"
    ok "pushed $tag to $REMOTE"
}

proxy_go() {
    env \
        GOPROXY=https://proxy.golang.org \
        GONOPROXY= \
        GOPRIVATE= \
        GONOSUMDB= \
        GOSUMDB=sum.golang.org \
        go "$@"
}

verify_go_proxy() {
    local module=$1 tag=$2 retries delay attempt output version_seen

    if ((VERIFY_PROXY == 0)); then
        log "[skip] proxy.golang.org lookup"
        return 0
    fi
    if ((DRY_RUN == 1)); then
        print_cmd env GOPROXY=https://proxy.golang.org go list -m -json "$module@$tag"
        return 0
    fi

    retries="${GO_PROXY_RETRIES:-6}"
    delay="${GO_PROXY_SLEEP:-5}"
    for ((attempt = 1; attempt <= retries; attempt++)); do
        log "checking proxy.golang.org for $module@$tag (attempt $attempt/$retries)"
        if output=$(proxy_go list -m -json "$module@$tag" 2>&1); then
            version_seen=$(awk -F'"' '/"Version":/ { print $4; exit }' <<<"$output")
            if [[ "$version_seen" != "$tag" ]]; then
                printf '%s\n' "$output" >&2
                fail "proxy returned version '${version_seen:-unknown}', expected $tag"
            fi
            ok "proxy.golang.org resolved $module@$tag"
            return 0
        fi
        if ((attempt < retries)); then
            sleep "$delay"
        fi
    done

    printf '%s\n' "$output" >&2
    fail "proxy.golang.org could not resolve $module@$tag"
}

verify_go_install() {
    local module=$1 tag=$2 expected output binary

    if ((VERIFY_INSTALL == 0)); then
        log "[skip] go install verification"
        return 0
    fi
    if ((DRY_RUN == 1)); then
        print_cmd env GOBIN='<tempdir>' GOPROXY=https://proxy.golang.org go install "$module/cmd/gruff-go@$tag"
        return 0
    fi

    TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gruff-go-publish.XXXXXX")
    env \
        GOBIN="$TMP_DIR" \
        GOPROXY=https://proxy.golang.org \
        GONOPROXY= \
        GOPRIVATE= \
        GONOSUMDB= \
        GOSUMDB=sum.golang.org \
        go install "$module/cmd/gruff-go@$tag"

    binary="$TMP_DIR/gruff-go"
    if [[ ! -x "$binary" ]]; then
        fail "go install did not produce $binary"
    fi

    expected="gruff-go ${tag#v}"
    output=$("$binary" --version 2>&1)
    if [[ "$output" != "$expected" ]]; then
        fail "installed binary printed '$output', expected '$expected'"
    fi
    ok "go install verified $module/cmd/gruff-go@$tag"
}

while (($# > 0)); do
    case "$1" in
        --remote)
            shift
            [[ $# -gt 0 ]] || fail "--remote requires a value"
            REMOTE="$1"
            ;;
        --skip-checks)
            RUN_CHECKS=0
            ;;
        --skip-proxy)
            VERIFY_PROXY=0
            ;;
        --skip-install)
            VERIFY_INSTALL=0
            ;;
        --no-push)
            PUSH_TAG=0
            ;;
        --no-fetch)
            FETCH_TAGS=0
            ;;
        --allow-non-main)
            ALLOW_NON_MAIN=1
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            fail "unknown option: $1"
            ;;
        *)
            if [[ -n "$VERSION" ]]; then
                fail "only one version argument is supported"
            fi
            VERSION=$(normalize_version "$1")
            ;;
    esac
    shift
done

if (($# > 0)); then
    if [[ -n "$VERSION" ]]; then
        fail "only one version argument is supported"
    fi
    VERSION=$(normalize_version "$1")
    shift
fi
if (($# > 0)); then
    fail "unexpected extra arguments: $*"
fi

cd "$REPO_ROOT"
require_tool git
require_tool go

if ! git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    fail "$REPO_ROOT is not a git worktree"
fi
if ! git -C "$REPO_ROOT" remote get-url "$REMOTE" >/dev/null 2>&1; then
    fail "git remote '$REMOTE' is not configured"
fi

SOURCE_VERSION=$(source_version)
if [[ -z "$VERSION" ]]; then
    VERSION=$(normalize_version "$SOURCE_VERSION")
fi

MODULE_PATH=$(module_path)
TAG="v$VERSION"

require_module_path_supports_major "$MODULE_PATH" "$VERSION"

log "publishing $MODULE_PATH@$TAG via $REMOTE"

if ((FETCH_TAGS == 1)); then
    run_cmd git -C "$REPO_ROOT" fetch "$REMOTE" --tags
fi

LOCAL_TAG_COMMIT=$(local_tag_commit "$TAG")
REMOTE_TAG_COMMIT=$(remote_tag_commit "$TAG")

# Release gate applies to both the create-tag and pre-existing-tag paths so
# the --allow-non-main opt-out is the only way to publish from a non-main or
# out-of-sync branch, and a dirty worktree never reaches `make check`.
require_clean_worktree
require_main_branch
require_upstream_current

if [[ -n "$LOCAL_TAG_COMMIT" ]]; then
    TAG_VERSION=$(source_version_at_ref "$TAG")
    if [[ "$TAG_VERSION" != "$VERSION" ]]; then
        fail "$TAG contains toolVersion $TAG_VERSION, not requested $VERSION"
    fi
    if [[ -n "$REMOTE_TAG_COMMIT" && "$REMOTE_TAG_COMMIT" != "$LOCAL_TAG_COMMIT" ]]; then
        fail "remote tag $TAG points to $REMOTE_TAG_COMMIT, not local $LOCAL_TAG_COMMIT"
    fi
    HEAD_COMMIT=$(git_commit HEAD)
    if [[ "$LOCAL_TAG_COMMIT" != "$HEAD_COMMIT" ]]; then
        fail "$TAG points to $LOCAL_TAG_COMMIT, not current HEAD $HEAD_COMMIT; check out the tag (git checkout $TAG) before publishing so release checks validate its contents"
    fi
    run_release_checks
else
    if [[ -n "$REMOTE_TAG_COMMIT" ]]; then
        fail "$REMOTE has $TAG but it is not available locally; rerun without --no-fetch"
    fi
    if [[ "$SOURCE_VERSION" != "$VERSION" ]]; then
        fail "requested $VERSION but internal/cli/cli.go has toolVersion $SOURCE_VERSION"
    fi
    run_release_checks
    ensure_local_tag "$TAG"
fi

ensure_remote_tag "$TAG"
verify_go_proxy "$MODULE_PATH" "$TAG"
verify_go_install "$MODULE_PATH" "$TAG"

ok "published and verified $MODULE_PATH@$TAG"
