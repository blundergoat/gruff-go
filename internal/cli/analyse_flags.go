// Package cli implements the gruff-go command-line interface.
// This file owns analyse flag registration and validation.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// analyseFlagValues is the parsed analyse command state after validation.
// minSeverityRaw + minSeverityExplicit replace the resolved FailThreshold so
// runAnalyse can apply the ADR-010 precedence (CLI flag > minimumSeverity.cmd
// > DefaultFailThresholdFor) after the config has been loaded.
type analyseFlagValues struct {
	format               string
	minSeverityRaw       string
	minSeverityExplicit  bool
	configPath           string
	noConfig             bool
	baselinePath         string
	noBaseline           bool
	generateBaselinePath string
	diffBase             string
	diffMode             string
	since                string
	diffPatch            []byte
	changedRanges        string
	changedScope         string
	baselineShow         bool
	includeRules         string
	excludeRules         string
	includePillars       string
	excludePillars       string
	editorLink           string
	reportInteractive    bool
	includeIgnored       bool
}

// analyseFlagPointers keeps the registered analyse flag values together so the
// parser can stay short while preserving Go's standard flag package.
type analyseFlagPointers struct {
	format               *string
	minSeverity          *string
	configPath           *string
	noConfig             *bool
	baselinePath         *string
	noBaseline           *bool
	baselineShow         *bool
	generateBaselinePath *string
	diffBase             *string
	diffMode             *string
	since                *string
	changedRanges        *string
	changedScope         *string
	includeRules         *string
	excludeRules         *string
	includePillars       *string
	excludePillars       *string
	editorLink           *string
	reportInteractive    *bool
	includeIgnored       *bool
}

// analyseFlagConsumesValue reports whether arg names an analyse flag whose value
// lives in the following argv token when no --flag=value form is used.
func analyseFlagConsumesValue(arg string) bool {
	if strings.Contains(arg, "=") {
		return false
	}
	switch strings.TrimLeft(arg, "-") {
	case "format", "min-severity", "fail-on", "config", "baseline",
		"generate-baseline", "diff-base", "diff", "since", "changed-ranges",
		"changed-scope", "include-rules", "exclude-rules", "include-pillars",
		"exclude-pillars", "report-editor-link":
		return true
	default:
		return false
	}
}

// parseAnalyseFlags parses and validates analyse flags, printing validation
// errors to stderr in the same style as the legacy inline parser.
func parseAnalyseFlags(args []string, stderr io.Writer) (*flag.FlagSet, analyseFlagValues, bool) {
	flags := newAnalyseFlagSet(stderr)
	flagValues := registerAnalyseFlags(flags)
	args = normalizeAnalyseDiffArgs(args)
	if err := flags.Parse(args); err != nil {
		return flags, analyseFlagValues{}, false
	}
	if !validateAnalyseEnums(*flagValues.format, *flagValues.editorLink, *flagValues.changedScope, stderr) {
		return flags, analyseFlagValues{}, false
	}
	diffPatch, ok := resolveAndReadDiffPatch(*flagValues.diffMode, *flagValues.since, stderr)
	if !ok {
		return flags, analyseFlagValues{}, false
	}
	minSeverityExplicit, ok := checkMinSeverityFlag(flags, *flagValues.minSeverity, stderr)
	if !ok {
		return flags, analyseFlagValues{}, false
	}
	values := flagValues.values(diffPatch, minSeverityExplicit)
	if values.generateBaselinePath != "" {
		if err := validateGenerateBaselineFlags(values.generateBaselineState()); err != nil {
			fmt.Fprintln(stderr, err)
			return flags, analyseFlagValues{}, false
		}
	}
	return flags, values, true
}

// newAnalyseFlagSet creates the analyse flag parser with GNU-style usage text.
func newAnalyseFlagSet(stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet("analyse", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		writeCommandHelp("analyse", commandUsages["analyse"], stderr, ansiStyler{})
	}
	return flags
}

// registerAnalyseFlags registers every analyse flag and returns their storage.
func registerAnalyseFlags(flags *flag.FlagSet) analyseFlagPointers {
	// ADR-009 + ADR-010: default is whatever DefaultFailThresholdFor("analyse")
	// returns (currently advisory, intentionally permissive after the 3-bucket
	// migration). Help text shows this default; precedence in runAnalyse lets
	// .gruff-go.yaml's minimumSeverity.analyse override it.
	format := flags.String("format", "text", "output format: text, json, summary-json, sarif, github, html, or markdown")
	minSeverity := string(finding.DefaultFailThresholdFor("analyse"))
	flags.StringVar(&minSeverity, "min-severity", minSeverity, "minimum severity that causes exit 1")
	flags.StringVar(&minSeverity, "fail-on", minSeverity, "alias for --min-severity")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	baselinePath := flags.String("baseline", "", "baseline file to apply")
	noBaseline := flags.Bool("no-baseline", false, "do not apply any baseline; overrides --baseline")
	baselineShow := flags.Bool("baseline-show", false, "render the unchanged and resolved baseline sets (counts are always reported)")
	generateBaselinePath := flags.String("generate-baseline", "", "write current findings to a baseline file and exit cleanly")
	diffBase := flags.String("diff-base", "", "git base ref for changed-line filtering")
	diffMode := flags.String("diff", "", "changed-region source: working-tree, staged, unstaged, base ref, or - for unified diff on stdin")
	since := flags.String("since", "", "git base ref for changed-region filtering")
	changedRanges := flags.String("changed-ranges", "", "explicit changed line ranges such as 3-3,8-10")
	changedScope := flags.String("changed-scope", "symbol", "changed-region scope: symbol or hunk")
	includeRules := flags.String("include-rules", "", "comma-separated rule IDs to display")
	excludeRules := flags.String("exclude-rules", "", "comma-separated rule IDs to hide from display")
	includePillars := flags.String("include-pillars", "", "comma-separated pillars to display")
	excludePillars := flags.String("exclude-pillars", "", "comma-separated pillars to hide from display")
	editorLink := flags.String("report-editor-link", "none", "html report file:line link mode: none, vscode, or phpstorm")
	reportInteractive := flags.Bool("report-interactive", false, "enable interactive findings filter UI in html output")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	return analyseFlagPointers{
		format:               format,
		minSeverity:          &minSeverity,
		configPath:           configPath,
		noConfig:             noConfig,
		baselinePath:         baselinePath,
		noBaseline:           noBaseline,
		baselineShow:         baselineShow,
		generateBaselinePath: generateBaselinePath,
		diffBase:             diffBase,
		diffMode:             diffMode,
		since:                since,
		changedRanges:        changedRanges,
		changedScope:         changedScope,
		includeRules:         includeRules,
		excludeRules:         excludeRules,
		includePillars:       includePillars,
		excludePillars:       excludePillars,
		editorLink:           editorLink,
		reportInteractive:    reportInteractive,
		includeIgnored:       includeIgnored,
	}
}

// values snapshots the parsed flag pointers into the immutable analyse state.
func (values analyseFlagPointers) values(diffPatch []byte, minSeverityExplicit bool) analyseFlagValues {
	parsed := analyseFlagValues{
		format:               *values.format,
		minSeverityRaw:       *values.minSeverity,
		minSeverityExplicit:  minSeverityExplicit,
		configPath:           *values.configPath,
		noConfig:             *values.noConfig,
		baselinePath:         *values.baselinePath,
		noBaseline:           *values.noBaseline,
		generateBaselinePath: *values.generateBaselinePath,
		diffBase:             *values.diffBase,
		diffMode:             *values.diffMode,
		since:                *values.since,
		diffPatch:            diffPatch,
		changedRanges:        *values.changedRanges,
		changedScope:         *values.changedScope,
		baselineShow:         *values.baselineShow,
		includeRules:         *values.includeRules,
		excludeRules:         *values.excludeRules,
		includePillars:       *values.includePillars,
		excludePillars:       *values.excludePillars,
		editorLink:           *values.editorLink,
		reportInteractive:    *values.reportInteractive,
		includeIgnored:       *values.includeIgnored,
	}
	if parsed.noBaseline {
		parsed.baselinePath = ""
	}
	return parsed
}

// generateBaselineState projects analyse flags relevant to baseline generation.
func (values analyseFlagValues) generateBaselineState() generateBaselineFlagState {
	return generateBaselineFlagState{
		baselinePath:   values.baselinePath,
		diffBase:       values.diffBase,
		diffMode:       values.diffMode,
		since:          values.since,
		changedRanges:  values.changedRanges,
		includeRules:   values.includeRules,
		excludeRules:   values.excludeRules,
		includePillars: values.includePillars,
		excludePillars: values.excludePillars,
	}
}

// generateBaselineFlagState groups analyse flags that change finding scope.
type generateBaselineFlagState struct {
	baselinePath   string
	diffBase       string
	diffMode       string
	since          string
	changedRanges  string
	includeRules   string
	excludeRules   string
	includePillars string
	excludePillars string
}

// validateGenerateBaselineFlags rejects combinations that would make the
// generated baseline partial rather than a fresh snapshot of current findings.
func validateGenerateBaselineFlags(state generateBaselineFlagState) error {
	switch {
	case state.baselinePath != "":
		return fmt.Errorf("--generate-baseline cannot be combined with --baseline")
	case state.diffBase != "":
		return fmt.Errorf("--generate-baseline cannot be combined with --diff-base")
	case state.diffMode != "" || state.since != "" || state.changedRanges != "":
		return fmt.Errorf("--generate-baseline cannot be combined with changed-region flags")
	case state.includeRules != "" || state.excludeRules != "" || state.includePillars != "" || state.excludePillars != "":
		return fmt.Errorf("--generate-baseline cannot be combined with display filters")
	default:
		return nil
	}
}
