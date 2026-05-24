#!/usr/bin/env bash
# dependency-install.sh - install local dependencies and audit tools.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat <<'USAGE'
Usage: scripts/dependency-install.sh

Installs local dependencies needed for development and preflight:
  - npm dependencies from package-lock.json via npm ci
  - Go module cache via go mod download
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

install_npm_dependencies() {
    local args=()
    [[ -f package-lock.json ]] || return 0
    require_command npm
    mapfile -t args < <(npm_script_args)
    log "Installing npm dependencies with npm ci..."
    npm ci "${args[@]}"
}

install_go_dependencies() {
    [[ -f go.mod ]] || return 0
    require_command go
    log "Downloading Go module dependencies..."
    go mod download
}

install_go_tools() {
    require_command go
    log "Installing govulncheck..."
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
    install_npm_dependencies
    install_go_dependencies
    install_go_tools
    log "Dependency install complete. Run scripts/preflight-checks.sh next."
}

main "$@"
