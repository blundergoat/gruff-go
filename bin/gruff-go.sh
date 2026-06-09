#!/usr/bin/env sh
# gruff-go.sh - family launcher for the gruff-go CLI.
#
# Mirrors the bin/gruff-<lang> launchers in the sibling gruff ports: a tracked,
# committed entrypoint that runs the tool. Go has no `cargo run`-style "run and
# rebuild if stale" command targeting a fixed path, so this launcher builds the
# compiled binary to bin/gruff-go (the project-local, gitignored build location)
# and rebuilds it whenever it is missing or older than the tracked Go sources,
# then execs it with the caller's arguments. Build chatter goes to stderr so the
# launcher's stdout is exactly the binary's stdout.
set -eu

# Resolve this script's real directory, following symlinks, so the launcher works
# when invoked through a PATH symlink (matching the sibling launchers).
PRG="$0"
while [ -h "$PRG" ]; do
	SCRIPT_DIR="$(unset CDPATH; cd -- "$(dirname -- "$PRG")" && pwd)"
	PRG="$(readlink "$PRG")"
	case "$PRG" in
		/*) ;;
		*) PRG="$SCRIPT_DIR/$PRG" ;;
	esac
done
SCRIPT_DIR="$(unset CDPATH; cd -- "$(dirname -- "$PRG")" && pwd)"
PACKAGE_DIR="$SCRIPT_DIR/.."

BIN="$SCRIPT_DIR/gruff-go"
PKG="$PACKAGE_DIR/cmd/gruff-go"

# needs_build succeeds (exit 0) when the binary is missing or stale: a non-test
# .go file under cmd/ or internal/, or go.mod/go.sum, newer than the binary means
# the compiled output no longer matches the current sources. A pipeline ending in
# `head` keeps the scan cheap and never trips `set -e` on a closed pipe.
needs_build() {
	[ -x "$BIN" ] || return 0
	newer=$(find "$PACKAGE_DIR/cmd" "$PACKAGE_DIR/internal" \
		\( -name '*.go' ! -name '*_test.go' \) -newer "$BIN" -print 2>/dev/null | head -n 1)
	[ -z "$newer" ] || return 0
	newer=$(find "$PACKAGE_DIR" -maxdepth 1 \
		\( -name 'go.mod' -o -name 'go.sum' \) -newer "$BIN" -print 2>/dev/null | head -n 1)
	[ -z "$newer" ] || return 0
	return 1
}

if needs_build; then
	command -v go >/dev/null 2>&1 || {
		echo "gruff-go.sh: 'go' toolchain not found on PATH; cannot build $BIN" >&2
		exit 1
	}
	echo "gruff-go.sh: building $BIN ..." >&2
	# go build is silent on success and incremental via the build cache, so a
	# rebuild that changes nothing is cheap; 1>&2 guards stdout against any future
	# build chatter.
	go build -o "$BIN" "$PKG" 1>&2 || {
		echo "gruff-go.sh: build failed" >&2
		exit 1
	}
fi

exec "$BIN" "$@"
