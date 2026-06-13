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

// hookFlagValues captures the hook command flags after parser normalization.
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
func runHook(args []string, stdout, stderr io.Writer) int {
	if hasHookHelpFlag(args) {
		writeCommandHelp("hook", commandUsages["hook"], stdout, ansiStyler{})
		return 0
	}
	values, ok := parseHookFlags(args, stderr)
	if !ok {
		return 2
	}
	if values.capabilities {
		if err := writeHookCapabilities(stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return 0
	}
	if values.format != "json" {
		fmt.Fprintf(stderr, "unsupported hook format %q (want json)\n", values.format)
		return 2
	}

	registry, ignorePaths, _, err := configuredRegistry(values.configPath, values.noConfig)
	if err != nil {
		if writeErr := report.WriteJSON(stdout, hookConfigErrorReport(err)); writeErr != nil {
			fmt.Fprintln(stderr, writeErr)
		}
		return 2
	}
	analysisReport, err := analysis.Analyze(analysis.Options{
		Paths:          values.paths,
		Format:         "json",
		FailOn:         finding.FailThresholdNone,
		Registry:       registry,
		IgnorePaths:    ignorePaths,
		IncludeIgnored: values.includeIgnored,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	root := analysisReport.Run.WorkingDirectory
	ctx := context.Background()
	gitBaseWarningWritten := false
	changed, changedEnabled, err := resolveHookChanged(ctx, root, analysisReport.Paths.Scanned, values)
	if err != nil {
		if !isDegradableHookGitBaseError(values.diffMode, err) {
			fmt.Fprintln(stderr, err)
			return 2
		}
		writeHookGitBaseWarning(stderr, err, &gitBaseWarningWritten)
		changedEnabled = false
	}
	baseSet, err := resolveHookBaseIdentities(ctx, root, values, registry, ignorePaths)
	if err != nil {
		if !isDegradableHookGitBaseError(values.diffMode, err) {
			fmt.Fprintln(stderr, err)
			return 2
		}
		writeHookGitBaseWarning(stderr, err, &gitBaseWarningWritten)
		baseSet = hookIdentitySet{}
	}
	payload := buildHookReport(analysisReport, registry.Definitions(), changed, changedEnabled, baseSet)
	if err := report.WriteJSON(stdout, payload); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if analysisReport.Summary.ExitCode == 2 {
		return 2
	}
	return 0
}

// parseHookFlags parses hook-specific flags while preserving Go's positional parser contract.
func parseHookFlags(args []string, stderr io.Writer) (hookFlagValues, bool) {
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
	normalized := normalizeAnalyseDiffArgs(args)
	if err := flags.Parse(normalized); err != nil {
		return hookFlagValues{}, false
	}
	diffPatch, ok := readDiffPatchIfRequested(*diffMode, stderr)
	if !ok {
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
func hasHookHelpFlag(args []string) bool {
	normalized := normalizeAnalyseDiffArgs(args)
	for i := 0; i < len(normalized); i++ {
		arg := normalized[i]
		if arg == "-h" || arg == "--help" {
			return true
		}
		if arg == "--" {
			return false
		}
		if !strings.HasPrefix(arg, "-") {
			return false
		}
		if hookFlagConsumesValue(arg) {
			i++
		}
	}
	return false
}

// hookFlagConsumesValue reports whether the next argv token belongs to a hook flag.
func hookFlagConsumesValue(arg string) bool {
	if strings.Contains(arg, "=") {
		return false
	}
	switch strings.TrimLeft(arg, "-") {
	case "format", "config", "changed-ranges", "diff", "baseline":
		return true
	default:
		return false
	}
}

// hookConfigErrorReport builds the in-band config failure payload required by B8.
func hookConfigErrorReport(err error) hookReport {
	message := err.Error()
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
func isDegradableHookGitBaseError(diffMode string, err error) bool {
	if err == nil {
		return false
	}
	switch diffMode {
	case "HEAD", "working-tree", "staged":
	default:
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "ambiguous argument") ||
		strings.Contains(message, "unknown revision") ||
		strings.Contains(message, "bad revision") ||
		strings.Contains(message, "not a valid object name") ||
		strings.Contains(message, "invalid object name") ||
		strings.Contains(message, "does not have any commits")
}

// writeHookGitBaseWarning emits the schema-compatible fallback diagnostic once
// per hook run.
func writeHookGitBaseWarning(stderr io.Writer, err error, written *bool) {
	if *written {
		return
	}
	fmt.Fprintf(stderr, "git diff base unavailable: %v; scanning requested paths without diff/new-only filtering\n", err)
	*written = true
}
