// Package cli implements the gruff-go command-line interface.
//
// This file normalises the analyse --diff and --since arguments before flag parsing, so --diff works with or without a value.
// It also reads the patch a user pipes to stdin with --diff - or --since -, shared by both changed-region flags.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// resolvedDiffMode returns the effective changed-region source from the parsed analyse flags.
//
// An explicit --since base ref is preferred over --diff, so the alias wins when both are supplied.
// The result is the --diff value when since is empty, and is empty only when both are empty.
func (values analyseFlagValues) resolvedDiffMode() string {
	if values.since != "" {
		return values.since
	}
	return values.diffMode
}

// stdinPatchFlags names the flags whose value may be the "-" stdin sentinel.
//
// resolveAndReadDiffPatch reads a stdin patch for either spelling, so both need their value folded into one token.
// Go's flag package accepts one or two leading dashes, so both forms of each name appear here.
var stdinPatchFlags = map[string]bool{
	"--diff": true, "-diff": true,
	"--since": true, "-since": true,
}

// normalizeGlobalStdinFlagValues folds --diff - into --diff=-, and the same for --since, before the global flag extractors run.
//
// Those extractors stop at a bare dash, the stdin operand, so later global flags would reach the command's FlagSet and fail as undefined.
// Folding only these values lets a bare dash keep its operand meaning elsewhere.
//
// args is the raw argument list and is not modified; tokens from the first standalone -- or - onward are copied untouched.
// The single-dash spellings -diff and -since fold the same way.
// It returns a new slice holding the folded tokens, equal in content to args when nothing folds.
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

// normalizeAnalyseDiffArgs lets --diff act as an optional-value flag, which Go's flag package does not support natively.
//
// A double-dash --diff followed by nothing, another flag, or a path-like token, see looksLikeDiffPath, becomes --diff=working-tree.
// It writes --diff - as --diff=-, and leaves a path-like token in place as a positional scan path.
//
// args holds the analyse or hook arguments and is not modified; tokens from the first standalone -- or - onward are copied untouched.
// It returns a new slice holding the rewritten arguments; a --diff followed by any other token, taken as a base ref, is kept as two tokens.
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
		// A following path, such as --diff ./internal, asks for a working-tree diff scoped to that path; git refs cannot begin with '.' or '/'.
		// The mode defaults to working-tree and the path stays a positional argument instead of being silently consumed as the diff base.
		if looksLikeDiffPath(args[i+1]) {
			normalized = append(normalized, "--diff=working-tree")
			continue
		}
		normalized = append(normalized, arg)
	}
	return normalized
}

// looksLikeDiffPath reports whether arg, the token after a bare --diff, is a filesystem path rather than a git base ref.
//
// A lone "." or a prefix of "./", "../", "/", or "~" marks a path without a filesystem check; git ref names cannot begin with '.' or '/'.
// Any other token, such as internal/cli or .github, counts as a path only when os.Stat finds that file or directory.
//
// A false result means the caller keeps arg as the --diff base ref.
// Use the explicit --diff=<ref> form to force the ref reading when a ref and a path share a name.
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

// readDiffPatchIfRequested reads the unified diff a user pipes to stdin when diffMode, the effective diff mode, is the "-" sentinel.
//
// For any other mode it is a no-op that succeeds, so callers can invoke it unconditionally.
// When stdin is a terminal rather than a pipe, the read waits until end of input; stderr receives a diff stdin message when the read fails.
//
// It returns the patch and true after a successful read, nil and true for any mode other than "-", and nil and false on a read error.
func readDiffPatchIfRequested(diffMode string, stderr io.Writer) ([]byte, bool) {
	if diffMode != "-" {
		return nil, true
	}
	data, err := io.ReadAll(os.Stdin)
	// Redirecting a directory as stdin, such as --diff - < internal, fails here with a diff stdin message on stderr.
	if err != nil {
		fmt.Fprintf(stderr, "diff stdin: %v\n", err)
		return nil, false
	}
	return data, true
}

// resolveAndReadDiffPatch reads a stdin patch only when the effective diff mode is the "-" sentinel.
//
// Because --since overrides --diff, see resolvedDiffMode, resolving the effective mode first means --since X --diff=- does not block on stdin.
// The resolved mode would discard that input anyway.
//
// diffMode and since are the raw --diff and --since values; a non-empty since replaces diffMode, and stderr receives any stdin read failure.
// It returns the stdin patch and true when the effective mode is "-", nil and true for any other mode, and nil and false on a read error.
func resolveAndReadDiffPatch(diffMode, since string, stderr io.Writer) ([]byte, bool) {
	effective := diffMode
	if since != "" {
		effective = since
	}
	return readDiffPatchIfRequested(effective, stderr)
}
