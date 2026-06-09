// Package cli check-ignore command: report whether gruff would exclude given
// paths, and why, using the same config resolution and ignore engine as
// analyse. It performs no analysis - it answers the path-scope question a
// coding-agent hook asks before deciding whether to act on a file.
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

// checkIgnoreResult is the per-path verdict emitted by check-ignore. The JSON
// shape is the contract for agent consumers: ignored plus the deciding source
// and (for config matches) the exact glob.
type checkIgnoreResult struct {
	// Path echoes the requested path in repository-relative slash form.
	Path string `json:"path"`
	// Ignored is true when analyse would exclude this path.
	Ignored bool `json:"ignored"`
	// Source names the deciding layer (config | gitignore | default) or "" when not ignored.
	Source string `json:"source,omitempty"`
	// Pattern is the matching config glob, present only for a config-source match.
	Pattern string `json:"pattern,omitempty"`
}

// runCheckIgnore implements `gruff-go check-ignore`. Exit codes mirror
// `git check-ignore`: 0 when at least one path is ignored, 1 when none are, and
// 2 on a usage or config error.
func runCheckIgnore(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("check-ignore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	includeIgnored := flags.Bool("include-ignored", false, "ignore git/default-ignored paths only; config paths.ignore still applies")
	if err := flags.Parse(args); err != nil {
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

	// Share the exact config resolution analyse uses, so the ignore patterns are
	// identical to a real scan - no second source of truth.
	_, ignorePaths, _, err := configuredRegistry(*configPath, *noConfig)
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

// writeCheckIgnore renders results as JSON (the agent contract, carrying
// ignored/source/pattern for every path) or as a text list. Text mode prints
// only ignored paths, one per line, mirroring `git check-ignore`; the full
// source/pattern detail is intentionally JSON-only because gruff-go's global
// flag layer reserves -v/--verbose as a cross-port no-op, so a text -v variant
// would be swallowed before this command runs.
func writeCheckIgnore(stdout io.Writer, format string, results []checkIgnoreResult) error {
	if format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(results)
	}
	for _, result := range results {
		if result.Ignored {
			fmt.Fprintln(stdout, result.Path)
		}
	}
	return nil
}

// checkIgnoreRel converts a user-supplied path into the repository-relative
// slash form the ignore engine matches against. Paths outside the root are
// returned cleaned but unmodified so they read back recognisably; the engine
// treats them as not-under-root.
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

// isDirArg reports whether raw resolves to a directory on disk, so directory-only
// ignore patterns are evaluated correctly. A non-existent path is treated as a
// file (the common hook case: a path the agent is about to create or edit);
// trailing-slash syntax also forces directory semantics.
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
