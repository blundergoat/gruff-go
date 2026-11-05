// Package cli check-ignore command: reports whether gruff-go's path ignore rules exclude each given path, and which layer decided it.
//
// It reuses analyse's config loader and path-only ignore engine, and performs no analysis.
// Generated Go files, which analyse detects by reading their contents, report not ignored here unless a path ignore rule excludes them.
// A coding-agent hook runs it to answer the path-scope question before deciding whether to act on a file.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/blundergoat/gruff-go/internal/source"
)

// checkIgnoreResult is the per-path verdict gruff-go check-ignore emits, one for each path the user passed.
//
// Its JSON shape is the contract for agent consumers: path and ignored always appear.
// source names the deciding layer and pattern the exact config glob; each is omitted when empty, so an unignored path carries neither.
type checkIgnoreResult struct {
	// Path echoes the requested path in root-relative slash form, or the cleaned input in slash form when it cannot be made relative.
	Path string `json:"path"`
	// Ignored is true when analyse's path ignore rules exclude this path; generated Go files are not detected.
	Ignored bool `json:"ignored"`
	// Source names the deciding layer (config | gitignore | default) or "" when not ignored.
	Source string `json:"source,omitempty"`
	// Pattern is the matching config glob, present only for a config-source match.
	Pattern string `json:"pattern,omitempty"`
}

// runCheckIgnore runs gruff-go check-ignore, deciding for each path the user passed whether analyse's path ignore rules exclude it.
//
// Exit codes mirror git check-ignore: 0 when at least one path is ignored, 1 when none are, and 2 on a usage or config error.
// Generated Go files are not detected, so one that matches no ignore rule reports not ignored.
//
// args holds the check-ignore flags and the paths to check; relative paths resolve against the current working directory, which is the root.
// stdout receives the verdicts in the chosen format, and stderr receives flag usage and every error message.
// It returns the exit code; 2 also covers an unsupported format, no paths, a failed working-directory lookup, and a failed JSON output write.
func runCheckIgnore(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("check-ignore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	includeIgnored := flags.Bool("include-ignored", false, "ignore git/default-ignored paths only; config paths.ignore still applies")
	// A mistyped flag, such as --fromat json, lands here and the run exits 2.
	if err := parseCommandArguments(flags, args); err != nil {
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "unsupported format %q (want text or json)\n", *format)
		return 2
	}
	paths := flags.Args()
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "check-ignore requires at least one path")
		return 2
	}

	// Load config through analyse's own loader, so there is no second source of truth for the ignore patterns.
	// No target paths are passed, so config is found from the launch directory, while analyse can resolve it from the paths it scans.
	_, ignorePaths, _, err := configuredRegistry(*configPath, *noConfig, nil)
	// A typo in the --config path, or a malformed .gruff-go.yaml, lands here and the run exits 2 before any path is checked.
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "check-ignore: %v\n", err)
		return 2
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintf(stderr, "check-ignore: %v\n", err)
		return 2
	}

	options := source.Options{
		Root:           rootAbs,
		IgnorePatterns: ignorePaths,
		IncludeIgnored: *includeIgnored,
	}
	results := make([]checkIgnoreResult, 0, len(paths))
	anyIgnored := false
	for _, raw := range paths {
		decision := source.CheckIgnore(rootAbs, checkIgnoreRel(rootAbs, raw), isDirArg(rootAbs, raw), options)
		results = append(results, checkIgnoreResult{
			Path:    checkIgnoreRel(rootAbs, raw),
			Ignored: decision.Ignored,
			Source:  decision.Source,
			Pattern: decision.Pattern,
		})
		if decision.Ignored {
			anyIgnored = true
		}
	}

	if err := writeCheckIgnore(stdout, *format, results); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if anyIgnored {
		return 0
	}
	return 1
}

// writeCheckIgnore prints results as a JSON array of every verdict, or as a text list of only ignored paths, one per line, like git check-ignore.
//
// JSON entries carry path and ignored, plus source and pattern only when they are non-empty.
// That detail stays JSON-only because gruff-go's global flag layer swallows -v/--verbose as a cross-port no-op before this command runs.
//
// format "json" selects the indented JSON array and any other value selects the text list; stdout receives the output.
// It returns an error only when the JSON encoder fails to write to stdout; text mode ignores write errors and always returns nil.
func writeCheckIgnore(stdout io.Writer, format string, results []checkIgnoreResult) error {
	if format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(results)
	}
	for _, result := range results {
		// An unignored path prints nothing, so empty text output with exit code 1 means none of the paths given is ignored.
		if result.Ignored {
			fmt.Fprintln(stdout, result.Path)
		}
	}
	return nil
}

// checkIgnoreRel converts a user path into the launch-directory-relative slash form that the ignore engine matches and the output echoes.
//
// A path outside the root comes back with leading dot-dot steps, so a relative input reads back cleaned but an absolute one does not.
// The engine treats such a path as not-under-root.
//
// rootAbs is the absolute launch directory, and raw is the user's path, joined to rootAbs when it is relative.
// It returns the root-relative slash path, or raw cleaned in slash form when filepath.Rel cannot relate it to rootAbs.
func checkIgnoreRel(rootAbs, raw string) string {
	abs := raw
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(rootAbs, raw)
	}
	rel, err := filepath.Rel(rootAbs, abs)
	if err != nil {
		return filepath.ToSlash(filepath.Clean(raw))
	}
	return filepath.ToSlash(rel)
}

// isDirArg reports whether raw, a path the user passed, names a directory on disk, so directory-only ignore patterns are evaluated correctly.
//
// A trailing slash forces directory semantics without touching the disk.
// A non-existent path is treated as a file, the common hook case of a path the agent is about to create or edit.
//
// rootAbs is the absolute launch directory that a relative raw path is joined to before the os.Stat check; any stat failure reports false.
func isDirArg(rootAbs, raw string) bool {
	if strings.HasSuffix(raw, "/") {
		return true
	}
	abs := raw
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(rootAbs, raw)
	}
	info, err := os.Stat(abs)
	return err == nil && info.IsDir()
}
