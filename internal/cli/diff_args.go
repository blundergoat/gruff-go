// Package cli implements the gruff-go command-line interface.
// This file holds the analyse `--diff` / `--since` argument normalisation and the
// stdin-patch reader shared by the changed-region flags.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// resolvedDiffMode returns the effective changed-region source, preferring an
// explicit --since base ref over --diff so the alias wins when both are supplied.
func (values analyseFlagValues) resolvedDiffMode() string {
	if values.since != "" {
		return values.since
	}
	return values.diffMode
}

// stdinPatchFlags name the flags whose value may be the `-` stdin sentinel.
// resolveAndReadDiffPatch reads a stdin patch for either spelling, so both need
// their value folded into one token. Go's flag package accepts one or two
// leading dashes, so both forms of each name appear here.
var stdinPatchFlags = map[string]bool{
	"--diff": true, "-diff": true,
	"--since": true, "-since": true,
}

// normalizeGlobalStdinFlagValues rewrites `--diff -` into `--diff=-`, and the
// same for `--since`, before the global flag extractors run. Those extractors
// treat a bare dash as the conventional stdin operand and stop scanning there, so
// leaving the dash as its own token strands every later global flag in the
// command's argument list, where that command's FlagSet rejects it as undefined.
// Folding only these values lets a bare dash keep its operand meaning elsewhere.
func normalizeGlobalStdinFlagValues(args []string) []string {
	normalized := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		// A terminator or a standalone stdin operand protects every later token.
		if argument == "--" || argument == "-" {
			normalized = append(normalized, args[index:]...)
			break
		}
		if stdinPatchFlags[argument] && index+1 < len(args) && args[index+1] == "-" {
			normalized = append(normalized, argument+"=-")
			index++
			continue
		}
		normalized = append(normalized, argument)
	}
	return normalized
}

// normalizeAnalyseDiffArgs rewrites a bare `--diff` (no value, or followed by
// another flag) into `--diff=working-tree`, and `--diff -` into `--diff=-`, so it
// behaves like an optional-value flag - which Go's flag package does not support
// natively.
func normalizeAnalyseDiffArgs(args []string) []string {
	normalized := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		// A standalone stdin operand or terminator protects every later token from diff normalization.
		if arg == "--" || arg == "-" {
			normalized = append(normalized, args[i:]...)
			break
		}
		if arg != "--diff" {
			normalized = append(normalized, arg)
			continue
		}
		if i+1 < len(args) && args[i+1] == "-" {
			normalized = append(normalized, "--diff=-")
			i++
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
			normalized = append(normalized, "--diff=working-tree")
			continue
		}
		// A following filesystem path (git refs cannot begin with '.' or '/') means
		// the user wants a working-tree diff scoped to that path, not a base ref, so
		// default the mode and leave the path as a positional argument instead of
		// silently consuming it as the diff base.
		if looksLikeDiffPath(args[i+1]) {
			normalized = append(normalized, "--diff=working-tree")
			continue
		}
		normalized = append(normalized, arg)
	}
	return normalized
}

// looksLikeDiffPath reports whether arg is a filesystem path rather than a git base
// ref. A leading ".", "./", "../", "/", or "~" marks a path unambiguously (git ref
// names cannot begin with '.' or '/'). A bare relative path like "internal/cli" has
// no disambiguating prefix, so it falls back to the filesystem: an existing file or
// directory is treated as a scan path rather than consumed as the --diff base ref.
// Use the explicit `--diff=<ref>` form to force the ref reading when a ref and a
// path share a name.
func looksLikeDiffPath(arg string) bool {
	if arg == "." || strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") ||
		strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "~") {
		return true
	}
	if _, err := os.Stat(arg); err == nil {
		return true
	}
	return false
}

// readDiffPatchIfRequested reads a unified diff from stdin when diffMode is "-",
// returning ok=false only on a read error; for any other mode it is a no-op that
// succeeds, so callers can invoke it unconditionally.
func readDiffPatchIfRequested(diffMode string, stderr io.Writer) ([]byte, bool) {
	if diffMode != "-" {
		return nil, true
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(stderr, "diff stdin: %v\n", err)
		return nil, false
	}
	return data, true
}

// resolveAndReadDiffPatch reads a stdin patch only when the effective diff mode is
// the "-" sentinel. --since overrides --diff (see resolvedDiffMode), so resolving
// the effective mode first means `--since X --diff=-` does not block on stdin that
// the resolved mode would discard.
func resolveAndReadDiffPatch(diffMode, since string, stderr io.Writer) ([]byte, bool) {
	effective := diffMode
	if since != "" {
		effective = since
	}
	return readDiffPatchIfRequested(effective, stderr)
}
