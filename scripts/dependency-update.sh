#!/usr/bin/env bash
# dependency-update.sh - refresh project dependency pins.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat <<'USAGE'
Usage: scripts/dependency-update.sh

Updates dependency manifests and local audit tooling:
  - npm dependencies via npm update
  - Go module requirements via go get -u ./... and go mod tidy
  - govulncheck via go install golang.org/x/vuln/cmd/govulncheck@latest

Environment:
  RUN_NPM_SCRIPTS=1  Allow npm dependency lifecycle scripts. Defaults to off.
USAGE
}

log() {
    printf '%s\n' "$*" >&2
}

require_command() {
    local command_name=$1
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'missing required command: %s\n' "$command_name" >&2
        return 1
    fi
}

npm_script_args() {
    if [[ "${RUN_NPM_SCRIPTS:-0}" != "1" ]]; then
        printf '%s\n' "--ignore-scripts"
    fi
}

update_npm_dependencies() {
    local args=()
    [[ -f package.json ]] || return 0
    require_command npm
    mapfile -t args < <(npm_script_args)
    log "Updating npm dependencies..."
    npm update "${args[@]}"
}

update_go_dependencies() {
    [[ -f go.mod ]] || return 0
    require_command go
    log "Updating Go module dependencies..."
    go get -u ./...
    go mod tidy
}

update_go_tools() {
    require_command go
    log "Updating govulncheck..."
    go install golang.org/x/vuln/cmd/govulncheck@latest
    if ! command -v govulncheck >/dev/null 2>&1; then
        log "govulncheck installed under $(go env GOPATH)/bin; add that directory to PATH if needed."
    fi
}

main() {
    while (($# > 0)); do
        case "$1" in
            -h|--help)
                usage
                return 0
                ;;
            *)
                printf 'unknown option: %s\n' "$1" >&2
                usage >&2
                return 64
                ;;
        esac
    done

    cd "$REPO_ROOT"
    update_npm_dependencies
    update_go_dependencies
    update_go_tools
    log "Dependency update complete. Review package*.json, go.mod/go.sum, then run scripts/preflight-checks.sh."
}

main "$@"
