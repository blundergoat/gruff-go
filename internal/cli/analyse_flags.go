// Package cli implements the gruff-go command-line interface.
// This file owns analyse flag registration and validation.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
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
	// force overwrites a 0.5 baseline at the shared default path instead of refusing.
	force         bool
	diffBase      string
	diffMode      string
	since         string
	diffPatch     []byte
	changedRanges string
	changedScope  string
	baselineShow  bool
	// showRules and its three siblings are the family display filters; the plural spellings feed the same fields.
	showRules   string
	hideRules   string
	showPillars string
	hidePillars string
	// includeRules and its siblings select what executes, which moves the score as well as the report.
	includeRules   string
	excludeRules   string
	includePillars string
	excludePillars string
	// gates carries the two exit gates the family contract adds to this port.
	gates             familyGateValues
	editorLink        string
	reportInteractive bool
	includeIgnored    bool
	deepScanBudget    string
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
	force                *bool
	diffBase             *string
	diffMode             *string
	since                *string
	changedRanges        *string
	changedScope         *string
	showRules            *string
	hideRules            *string
	showPillars          *string
	hidePillars          *string
	includeRules         *string
	excludeRules         *string
	includePillars       *string
	excludePillars       *string
	runRules             *string
	skipRules            *string
	runPillars           *string
	skipPillars          *string
	minConfidence        *string
	failOnNew            *bool
	scanTimeout          *string
	editorLink           *string
	reportInteractive    *bool
	includeIgnored       *bool
	deepScanBudget       *string
}

// analyseFlagHasSeparateValue identifies analyse flags whose value is the next token.
// The help pre-scan uses it so a flag value spelled `--help` is not mistaken for a help request.
func analyseFlagHasSeparateValue(flagArgument string) bool {
	// An inline assignment leaves the following token available as a path or another flag.
	if strings.Contains(flagArgument, "=") {
		return false
	}
	// These are analyse's non-Boolean flags; every other supported flag is self-contained.
	switch strings.TrimLeft(flagArgument, "-") {
	case "include-rule", "exclude-rule", "include-pillar", "exclude-pillar",
		"format", "min-severity", "fail-on", "config", "baseline",
		"generate-baseline", "diff-base", "diff", "since", "changed-ranges",
		"changed-scope", "include-rules", "exclude-rules", "include-pillars",
		"exclude-pillars", "report-editor-link", "deep-scan-budget",
		"show-rule", "hide-rule", "show-pillar", "hide-pillar",
		"min-confidence", "scan-timeout":
		return true
	default:
		// Boolean and unknown flags do not reserve the next token during the help pre-scan.
		return false
	}
}

// parseAnalyseFlags validates analyse options and retains positional paths in the returned FlagSet.
// It writes usage errors to stderr; false tells runAnalyse to stop before loading config or scanning.
func parseAnalyseFlags(commandArguments []string, stderr io.Writer) (*flag.FlagSet, analyseFlagValues, bool) {
	flagSet := newAnalyseFlagSet(stderr)
	registeredFlags := registerAnalyseFlags(flagSet)
	normalizedArguments := normalizeAnalyseDiffArgs(commandArguments)
	// FlagSet already wrote a syntax error, so the command only needs the unsuccessful status.
	if err := parseCommandArguments(flagSet, normalizedArguments); err != nil {
		return flagSet, analyseFlagValues{}, false
	}
	// --min-severity inverts rather than disappears, so the run stops before producing a verdict under semantics the
	// user did not ask for. The wording is ratified in gruff-spec/fixtures/cli/locked-v05-min-severity.v1.json.
	if refuseMinSeverity(flagSet, stderr) {
		return flagSet, analyseFlagValues{}, false
	}
	// The plural display selectors behave identically under their family names, so they warn and keep working.
	warnSupersededSpellings(flagSet, stderr)
	// Unsupported output, editor-link, or changed-scope values are command-usage errors.
	if !validateAnalyseEnums(*registeredFlags.format, *registeredFlags.editorLink, *registeredFlags.changedScope, stderr) {
		return flagSet, analyseFlagValues{}, false
	}
	// Reject an incompatible --generate-baseline combination before reading a
	// --diff=- stdin patch, so the documented error returns immediately instead
	// of blocking on stdin in an interactive shell or hook. generateBaselineState
	// reads only flag values, not the patch, so validating here is safe.
	if *registeredFlags.generateBaselinePath != "" {
		if err := validateGenerateBaselineFlags(registeredFlags.values(nil, false).generateBaselineState()); err != nil {
			fmt.Fprintln(stderr, err)
			return flagSet, analyseFlagValues{}, false
		}
	}
	diffPatch, patchRead := resolveAndReadDiffPatch(*registeredFlags.diffMode, *registeredFlags.since, stderr)
	// A failed stdin patch read leaves no reliable changed-region input.
	if !patchRead {
		return flagSet, analyseFlagValues{}, false
	}
	minimumSeverityExplicit, severityValid := checkMinSeverityFlag(flagSet, *registeredFlags.minSeverity, stderr)
	// An invalid threshold is a usage error, not a partial scan with a fallback gate.
	if !severityValid {
		return flagSet, analyseFlagValues{}, false
	}
	gates, gatesValid := parseFamilyGates(*registeredFlags.minConfidence, *registeredFlags.failOnNew, stderr)
	// A confidence floor the user mistyped would silently become no floor at all.
	if !gatesValid {
		return flagSet, analyseFlagValues{}, false
	}
	parsed := registeredFlags.values(diffPatch, minimumSeverityExplicit)
	parsed.gates = gates
	return flagSet, parsed, true
}

// newAnalyseFlagSet creates the analyse flag parser with GNU-style usage text.
func newAnalyseFlagSet(stderr io.Writer) *flag.FlagSet {
	flagSet := flag.NewFlagSet("analyse", flag.ContinueOnError)
	flagSet.SetOutput(stderr)
	flagSet.Usage = func() {
		writeCommandHelp("analyse", commandUsages["analyse"], stderr, ansiStyler{})
	}
	return flagSet
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
	force := flags.Bool("force", false, "overwrite a 0.5 baseline at the default path; without it a generate that would destroy the retreat path is refused")
	diffBase := flags.String("diff-base", "", "git base ref for changed-line filtering")
	diffMode := flags.String("diff", "", "changed-region source: working-tree, staged, unstaged, base ref, or - for unified diff on stdin")
	since := flags.String("since", "", "git base ref for changed-region filtering")
	changedRanges := flags.String("changed-ranges", "", "explicit changed line ranges such as 3-3,8-10")
	changedScope := flags.String("changed-scope", "symbol", "changed-region scope: symbol or hunk")
	showRules := flags.String("show-rule", "", "comma-separated rule IDs to display; never changes execution or the score")
	hideRules := flags.String("hide-rule", "", "comma-separated rule IDs to hide from display")
	showPillars := flags.String("show-pillar", "", "comma-separated pillars to display")
	hidePillars := flags.String("hide-pillar", "", "comma-separated pillars to hide from display")
	minConfidence := flags.String("min-confidence", "", "lowest confidence that reaches the exit gate: low, medium, or high")
	failOnNew := flags.Bool("fail-on-new", false, "exit 1 when any finding is new against the applied baseline")
	scanTimeout := flags.String("scan-timeout", "", "accepted for cross-port compatibility; not implemented in gruff-go")
	runRules := flags.String("include-rule", "", "comma-separated rule IDs to run; changes execution, so the score and any generated baseline move with it")
	skipRules := flags.String("exclude-rule", "", "comma-separated rule IDs not to run")
	runPillars := flags.String("include-pillar", "", "comma-separated pillars to run; changes execution, not just display")
	skipPillars := flags.String("exclude-pillar", "", "comma-separated pillars not to run")
	includeRules := flags.String("include-rules", "", "superseded by --show-rule; comma-separated rule IDs to display")
	excludeRules := flags.String("exclude-rules", "", "superseded by --hide-rule; comma-separated rule IDs to hide from display")
	includePillars := flags.String("include-pillars", "", "superseded by --show-pillar; comma-separated pillars to display")
	excludePillars := flags.String("exclude-pillars", "", "superseded by --hide-pillar; comma-separated pillars to hide from display")
	editorLink := flags.String("report-editor-link", "none", "html report file:line link mode: none, vscode, or phpstorm")
	reportInteractive := flags.Bool("report-interactive", false, "enable interactive findings filter UI in html output")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	deepScanBudget := flags.String("deep-scan-budget", "", "override both deep-scan bounds as LINES:BYTES, or disable with off")
	return analyseFlagPointers{
		format:               format,
		minSeverity:          &minSeverity,
		configPath:           configPath,
		noConfig:             noConfig,
		baselinePath:         baselinePath,
		noBaseline:           noBaseline,
		baselineShow:         baselineShow,
		generateBaselinePath: generateBaselinePath,
		force:                force,
		diffBase:             diffBase,
		diffMode:             diffMode,
		since:                since,
		changedRanges:        changedRanges,
		changedScope:         changedScope,
		showRules:            showRules,
		hideRules:            hideRules,
		showPillars:          showPillars,
		hidePillars:          hidePillars,
		includeRules:         includeRules,
		excludeRules:         excludeRules,
		includePillars:       includePillars,
		excludePillars:       excludePillars,
		minConfidence:        minConfidence,
		failOnNew:            failOnNew,
		scanTimeout:          scanTimeout,
		runRules:             runRules,
		skipRules:            skipRules,
		runPillars:           runPillars,
		skipPillars:          skipPillars,
		editorLink:           editorLink,
		reportInteractive:    reportInteractive,
		includeIgnored:       includeIgnored,
		deepScanBudget:       deepScanBudget,
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
		force:                *values.force,
		diffBase:             *values.diffBase,
		diffMode:             *values.diffMode,
		since:                *values.since,
		diffPatch:            diffPatch,
		changedRanges:        *values.changedRanges,
		changedScope:         *values.changedScope,
		baselineShow:         *values.baselineShow,
		showRules:            firstNonEmpty(*values.showRules, *values.includeRules),
		hideRules:            firstNonEmpty(*values.hideRules, *values.excludeRules),
		showPillars:          firstNonEmpty(*values.showPillars, *values.includePillars),
		hidePillars:          firstNonEmpty(*values.hidePillars, *values.excludePillars),
		includeRules:         *values.runRules,
		excludeRules:         *values.skipRules,
		includePillars:       *values.runPillars,
		excludePillars:       *values.skipPillars,
		editorLink:           *values.editorLink,
		reportInteractive:    *values.reportInteractive,
		includeIgnored:       *values.includeIgnored,
		deepScanBudget:       *values.deepScanBudget,
	}
	if parsed.noBaseline {
		parsed.baselinePath = ""
	}
	return parsed
}

// resolveDeepScanBudget applies CLI-over-config precedence to the atomic paired bound.
func resolveDeepScanBudget(raw string, cfg cfgpkg.Config) (analysis.DeepScanBudget, error) {
	budget := analysis.DeepScanBudget{
		Enabled:  true,
		MaxLines: cfgpkg.DefaultDeepScanMaxLines,
		MaxBytes: cfgpkg.DefaultDeepScanMaxBytes,
		Override: "default",
	}
	configured := cfg.DeepScanBudget.Enabled != nil || cfg.DeepScanBudget.MaxLines != nil || cfg.DeepScanBudget.MaxBytes != nil
	if configured {
		budget.Override = "config"
		if cfg.DeepScanBudget.Enabled != nil {
			budget.Enabled = *cfg.DeepScanBudget.Enabled
		}
		if cfg.DeepScanBudget.MaxLines != nil {
			budget.MaxLines = *cfg.DeepScanBudget.MaxLines
		}
		if cfg.DeepScanBudget.MaxBytes != nil {
			budget.MaxBytes = *cfg.DeepScanBudget.MaxBytes
		}
	}
	if raw == "" {
		return budget, nil
	}
	if raw == "off" {
		budget.Enabled = false
		budget.Override = "cli"
		return budget, nil
	}
	linesRaw, bytesRaw, ok := strings.Cut(raw, ":")
	if !ok || strings.Contains(bytesRaw, ":") {
		return analysis.DeepScanBudget{}, fmt.Errorf("--deep-scan-budget must be two positive integers as LINES:BYTES, or off")
	}
	maxLines, linesErr := strconv.Atoi(linesRaw)
	maxBytes, bytesErr := strconv.Atoi(bytesRaw)
	if linesErr != nil || bytesErr != nil || maxLines <= 0 || maxBytes <= 0 {
		return analysis.DeepScanBudget{}, fmt.Errorf("--deep-scan-budget must be two positive integers as LINES:BYTES, or off")
	}
	return analysis.DeepScanBudget{Enabled: true, MaxLines: maxLines, MaxBytes: maxBytes, Override: "cli"}, nil
}

// generateBaselineState projects analyse flags relevant to baseline generation.
func (values analyseFlagValues) generateBaselineState() generateBaselineFlagState {
	return generateBaselineFlagState{
		baselinePath:  values.baselinePath,
		diffBase:      values.diffBase,
		diffMode:      values.diffMode,
		since:         values.since,
		changedRanges: values.changedRanges,
		// The family fields, because values() merges the superseded plural spellings into them. Reading the plural
		// fields here would let --include-rules generate a baseline from a filtered view of the findings.
		includeRules:   values.showRules,
		excludeRules:   values.hideRules,
		includePillars: values.showPillars,
		excludePillars: values.hidePillars,
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

// firstNonEmpty returns the family spelling when the user gave one, and the superseded spelling otherwise.
//
// Both write the same display filter, so a command line mixing them keeps the family value rather than concatenating
// two lists the user never meant to combine.
func firstNonEmpty(familyValue, supersededValue string) string {
	if familyValue != "" {
		return familyValue
	}

	return supersededValue
}
