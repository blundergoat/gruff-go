// Package cli implements the coding-agent hook command and JSON contract.
// This file resolves hook flags, runs analysis, applies optional change/base
// context, and returns findings the user's current edit should address.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
)

// hookFlagValues captures the normalized choices behind one user hook run.
// It keeps config, changed-region, baseline, ignore, and path inputs together
// before analysis builds the gruff.hook.v1 response.
type hookFlagValues struct {
	format         string
	capabilities   bool
	configPath     string
	noConfig       bool
	changedRanges  string
	diffMode       string
	diffPatch      []byte
	baselinePath   string
	includeIgnored bool
	paths          []string
}

// runHook executes the agent-hook JSON contract with advisory finding exits.
func runHook(commandArguments []string, stdout, stderr io.Writer) int {
	// A help request returns guidance without scanning the user's project.
	if hasHookHelpFlag(commandArguments) {
		writeCommandHelp("hook", commandUsages["hook"], stdout, ansiStyler{})
		return 0
	}
	hookFlags, parsedFlags := parseHookFlags(commandArguments, stderr)
	// Invalid flags stop before emitting a misleading hook report.
	if !parsedFlags {
		return 2
	}
	// Capability discovery returns the contract options instead of scan findings.
	if hookFlags.capabilities {
		// A write failure means the user's agent did not receive valid capability JSON.
		if err := writeHookCapabilities(stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return 0
	}
	// Hook consumers require the single stable JSON format.
	if hookFlags.format != "json" {
		fmt.Fprintf(stderr, "unsupported hook format %q (want json)\n", hookFlags.format)
		return 2
	}

	ruleRegistry, ignoredPathPatterns, _, err := configuredRegistry(hookFlags.configPath, hookFlags.noConfig)
	// Invalid project config is returned in-band so the agent can explain it.
	if err != nil {
		// A secondary JSON write failure leaves no usable hook contract for the user.
		if writeErr := report.WriteJSON(stdout, hookConfigErrorReport(err)); writeErr != nil {
			fmt.Fprintln(stderr, writeErr)
		}
		return 2
	}
	analysisReport, err := analysis.Analyze(analysis.Options{
		Paths:          hookFlags.paths,
		Format:         "json",
		FailOn:         finding.FailThresholdNone,
		Registry:       ruleRegistry,
		IgnorePaths:    ignoredPathPatterns,
		IncludeIgnored: hookFlags.includeIgnored,
	})
	// Pipeline failures mean the user's requested project could not be analyzed.
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	projectRoot := analysisReport.Run.WorkingDirectory
	scanContext := context.Background()
	gitBaseWarningWritten := false
	changedLines, changedScopeEnabled, err := resolveHookChanged(scanContext, projectRoot, analysisReport.Paths.Scanned, hookFlags)
	// A missing initial git base degrades to a full hook scan; other errors stay fatal.
	if err != nil {
		// Non-degradable diff errors cannot produce trustworthy changed-region results.
		if !isDegradableHookGitBaseError(hookFlags.diffMode, err) {
			fmt.Fprintln(stderr, err)
			return 2
		}
		writeHookGitBaseWarning(stderr, err, &gitBaseWarningWritten)
		changedScopeEnabled = false
	}
	findingBaseline, err := resolveHookFindingBaseline(scanContext, projectRoot, hookFlags, ruleRegistry, ignoredPathPatterns)
	// Genuine baseline failures stay fatal; missing initial git history degrades safely.
	if err != nil {
		// Non-git baseline failures cannot produce a trustworthy new-only result.
		if !isDegradableHookGitBaseError(hookFlags.diffMode, err) {
			fmt.Fprintln(stderr, err)
			return 2
		}
		writeHookGitBaseWarning(stderr, err, &gitBaseWarningWritten)
		findingBaseline = hookFindingBaseline{}
	}
	payload := buildHookReport(analysisReport, ruleRegistry.Definitions(), changedLines, changedScopeEnabled, findingBaseline)
	// The user-facing hook contract must be emitted as valid JSON.
	if err := report.WriteJSON(stdout, payload); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// Fatal analysis diagnostics retain exit 2 even though ordinary findings are advisory.
	if analysisReport.Summary.ExitCode == 2 {
		return 2
	}
	return 0
}

// parseHookFlags parses hook-specific flags while preserving Go's positional parser contract.
func parseHookFlags(commandArguments []string, stderr io.Writer) (hookFlagValues, bool) {
	flags := flag.NewFlagSet("hook", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { writeCommandHelp("hook", commandUsages["hook"], stderr, ansiStyler{}) }
	format := flags.String("format", "json", "output format: json")
	capabilities := flags.Bool("capabilities", false, "emit gruff.hook.v1 capability metadata and exit")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	changedRanges := flags.String("changed-ranges", "", "explicit changed line ranges such as 3-3,8-10")
	diffMode := flags.String("diff", "", "changed-region/new-only source: working-tree, staged, unstaged, base ref, or - for unified diff on stdin")
	baselinePath := flags.String("baseline", "", "baseline file to apply for stable-identity new-only")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	normalizedArguments := normalizeAnalyseDiffArgs(commandArguments)
	// Invalid flag syntax is already explained to the user through stderr.
	if err := flags.Parse(normalizedArguments); err != nil {
		return hookFlagValues{}, false
	}
	diffPatch, readPatch := readDiffPatchIfRequested(*diffMode, stderr)
	// A failed stdin patch read leaves no reliable changed-region input.
	if !readPatch {
		return hookFlagValues{}, false
	}
	return hookFlagValues{
		format:         *format,
		capabilities:   *capabilities,
		configPath:     *configPath,
		noConfig:       *noConfig,
		changedRanges:  *changedRanges,
		diffMode:       *diffMode,
		diffPatch:      diffPatch,
		baselinePath:   *baselinePath,
		includeIgnored: *includeIgnored,
		paths:          flags.Args(),
	}, true
}

// hasHookHelpFlag detects help before the first positional path.
func hasHookHelpFlag(commandArguments []string) bool {
	normalizedArguments := normalizeAnalyseDiffArgs(commandArguments)
	// Inspect flags only until the user's first positional project path.
	for argumentIndex := 0; argumentIndex < len(normalizedArguments); argumentIndex++ {
		argument := normalizedArguments[argumentIndex]
		// Either supported help spelling should display command guidance.
		if argument == "-h" || argument == "--help" {
			return true
		}
		// An explicit separator makes every following token a user path.
		if argument == "--" {
			return false
		}
		// The first non-flag token begins positional project input.
		if !strings.HasPrefix(argument, "-") {
			return false
		}
		// Skip a value token so a path-like value is not mistaken for position input.
		if hookFlagConsumesValue(argument) {
			argumentIndex++
		}
	}
	return false
}

// hookFlagConsumesValue reports whether the next argv token belongs to a hook flag.
func hookFlagConsumesValue(flagArgument string) bool {
	// An inline `--flag=value` already carries its user-provided value.
	if strings.Contains(flagArgument, "=") {
		return false
	}
	switch strings.TrimLeft(flagArgument, "-") {
	case "format", "config", "changed-ranges", "diff", "baseline":
		return true
	default:
		return false
	}
}

// hookConfigErrorReport builds the in-band config failure payload required by B8.
func hookConfigErrorReport(configError error) hookReport {
	message := configError.Error()
	return hookReport{
		ContractVersion: hookContractVersion,
		Analyzer:        hookAnalyzer{Name: "gruff-go", Version: toolVersion},
		Findings:        []hookFinding{},
		Suppressed:      hookSuppressed{},
		Ignored:         hookIgnored{Paths: []hookIgnoredPath{}},
		Config:          hookConfigState{SchemaOK: false, Error: &message},
	}
}

// isDegradableHookGitBaseError reports no-commit/default-HEAD failures where a
// hook can still return useful findings by dropping diff/new-only filtering.
func isDegradableHookGitBaseError(diffMode string, hookError error) bool {
	// A nil error needs no fallback or warning in the user-facing hook run.
	if hookError == nil {
		return false
	}
	switch diffMode {
	case "HEAD", "working-tree", "staged":
	default:
		return false
	}
	message := strings.ToLower(hookError.Error())
	return strings.Contains(message, "ambiguous argument") ||
		strings.Contains(message, "unknown revision") ||
		strings.Contains(message, "bad revision") ||
		strings.Contains(message, "not a valid object name") ||
		strings.Contains(message, "invalid object name") ||
		strings.Contains(message, "does not have any commits")
}

// writeHookGitBaseWarning emits the schema-compatible fallback diagnostic once
// per hook run.
func writeHookGitBaseWarning(stderr io.Writer, hookError error, warningWritten *bool) {
	// Multiple git operations may fail from the same missing base; explain it once.
	if *warningWritten {
		return
	}
	fmt.Fprintf(stderr, "git diff base unavailable: %v; scanning requested paths without diff/new-only filtering\n", hookError)
	*warningWritten = true
}
