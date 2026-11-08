// Package cli implements the gruff-go command-line interface.
//
// This file owns analyse flag registration and validation, turning what the user typed after gruff-go analyse into checked values.
// Mistakes such as --format xml, or --generate-baseline with --baseline, stop the run with a message on stderr before the config loads.
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

// analyseFlagValues is the parsed analyse command state after validation, holding what the user typed after gruff-go analyse.
//
// minSeverityRaw and minSeverityExplicit replace a resolved FailThreshold so runAnalyse can apply ADR-010 precedence after config loads.
// A threshold typed on the command line beats failOn.analyse in the config, which beats DefaultFailThresholdFor.
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
	// changedRangesSet distinguishes an absent --changed-ranges from one the user passed empty.
	changedRangesSet bool
	changedScope     string
	baselineShow     bool
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
	historyFile          *string
	editorLink           *string
	reportInteractive    *bool
	includeIgnored       *bool
	deepScanBudget       *string
}

// analyseFlagHasSeparateValue identifies analyse flags whose value is the next token.
//
// The help pre-scan uses it so a flag value spelled --help is not mistaken for a help request.
//
// flagArgument is one raw command-line token; its leading dashes are trimmed before the name is matched.
// It returns true when the token has no equals sign and names a value-taking flag other than history-file, which the switch omits.
// An inline assignment, a Boolean flag or an unknown name gives false.
func analyseFlagHasSeparateValue(flagArgument string) bool {
	// An inline assignment leaves the following token available as a path or another flag.
	if strings.Contains(flagArgument, "=") {
		return false
	}
	// The help pre-scan reserves the next token for these flags; history-file also takes a value but is omitted here.
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
//
// It writes usage errors to stderr; false tells runAnalyse to stop before loading config or scanning.
// commandArguments holds the analyse flags and positional paths; it passes through normalizeAnalyseDiffArgs before the FlagSet parses it.
//
// It returns the FlagSet, the parsed analyse values and true on success, or the FlagSet, zero analyseFlagValues and false on any failure.
func parseAnalyseFlags(commandArguments []string, stderr io.Writer) (*flag.FlagSet, analyseFlagValues, bool) {
	flagSet := newAnalyseFlagSet(stderr)
	registeredFlags := registerAnalyseFlags(flagSet)
	normalizedArguments := normalizeAnalyseDiffArgs(commandArguments)
	// A misspelled flag such as --formt lands here; FlagSet already wrote the error to stderr, so only the failed status remains.
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
	// Reject a conflicting --generate-baseline, such as one paired with --baseline, before reading a --diff=- stdin patch.
	//
	// The error then prints at once instead of blocking on stdin in an interactive shell or hook.
	// generateBaselineState reads only flag values, not the patch, so validating before the read is safe.
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
	parsed.changedRangesSet = flagProvided(flagSet, "changed-ranges")
	parsed.gates = gates
	return flagSet, parsed, true
}

// newAnalyseFlagSet creates the analyse flag parser with GNU-style usage text.
//
// stderr receives the FlagSet's parse errors and the analyse help text that its Usage function writes.
// It returns a new FlagSet named analyse that uses ContinueOnError and has no flags registered yet; it is never nil.
func newAnalyseFlagSet(stderr io.Writer) *flag.FlagSet {
	flagSet := flag.NewFlagSet("analyse", flag.ContinueOnError)
	flagSet.SetOutput(stderr)
	flagSet.Usage = func() {
		writeCommandHelp("analyse", commandUsages["analyse"], stderr, ansiStyler{})
	}
	return flagSet
}

// registerAnalyseFlags registers every analyse flag and returns their storage.
// flags is the FlagSet that receives every definition; min-severity and fail-on share one string, so both spellings set the same threshold.
func registerAnalyseFlags(flags *flag.FlagSet) analyseFlagPointers {
	// ADR-009 and ADR-010: the default exit threshold comes from DefaultFailThresholdFor for analyse, which gives advisory.
	// runAnalyse lets failOn.analyse in .gruff-go.yaml override the default, and a command-line threshold wins over both.
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
	historyFile := flags.String("history-file", "", "accepted for cross-port compatibility; not implemented in gruff-go")
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
		historyFile:          historyFile,
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

// values snapshots the parsed flag pointers into analyse command state.
//
// diffPatch is the patch read for the diff flags and minSeverityExplicit marks a threshold set on the command line; both are copied in unchanged.
// It returns that snapshot with superseded display spellings merged by firstNonEmpty and baselinePath left empty when noBaseline is set.
// changedRangesSet and gates stay zero here; parseAnalyseFlags fills them in after this call.
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
	// --no-baseline overrides --baseline, so a run given both applies no baseline file.
	if parsed.noBaseline {
		parsed.baselinePath = ""
	}
	return parsed
}

// resolveDeepScanBudget applies CLI-over-config precedence to the atomic paired bound.
//
// raw is the --deep-scan-budget value: empty keeps the defaults overlaid by any set cfg DeepScanBudget field, and off disables the bound.
// It returns the budget with Override naming the winning source as default, config or cli.
//
// Any other raw must be LINES:BYTES, two positive integers that replace both bounds; anything else fails with an error and a zero budget.
func resolveDeepScanBudget(raw string, cfg cfgpkg.Config) (analysis.DeepScanBudget, error) {
	budget := analysis.DeepScanBudget{
		Enabled:  true,
		MaxLines: cfgpkg.DefaultDeepScanMaxLines,
		MaxBytes: cfgpkg.DefaultDeepScanMaxBytes,
		Override: "default",
	}
	configured := cfg.DeepScanBudget.Enabled != nil || cfg.DeepScanBudget.MaxLines != nil || cfg.DeepScanBudget.MaxBytes != nil
	// Any DeepScanBudget field set in the config file marks Override as config, even one that repeats a default value.
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
	// A typo such as --deep-scan-budget 500 or 500:1000:2 lands here with the LINES:BYTES message.
	if !ok || strings.Contains(bytesRaw, ":") {
		return analysis.DeepScanBudget{}, fmt.Errorf("--deep-scan-budget must be two positive integers as LINES:BYTES, or off")
	}
	maxLines, linesErr := strconv.Atoi(linesRaw)
	maxBytes, bytesErr := strconv.Atoi(bytesRaw)
	// A non-number or a value below one, such as 500:1k or 0:1000, gets the same message.
	if linesErr != nil || bytesErr != nil || maxLines <= 0 || maxBytes <= 0 {
		return analysis.DeepScanBudget{}, fmt.Errorf("--deep-scan-budget must be two positive integers as LINES:BYTES, or off")
	}
	return analysis.DeepScanBudget{Enabled: true, MaxLines: maxLines, MaxBytes: maxBytes, Override: "cli"}, nil
}

// generateBaselineState projects analyse flags relevant to baseline generation.
//
// It returns the baseline, diff-base, diff, since and changed-ranges values, each empty when unset; --no-baseline also empties the baseline.
// Its include and exclude fields carry the merged display filters, so a superseded plural spelling is checked too; run selection is not copied.
func (values analyseFlagValues) generateBaselineState() generateBaselineFlagState {
	return generateBaselineFlagState{
		baselinePath:  values.baselinePath,
		diffBase:      values.diffBase,
		diffMode:      values.diffMode,
		since:         values.since,
		changedRanges: values.changedRanges,
		// The display fields, because values() merges the superseded plural spellings into them, so --include-rules is refused like --show-rule.
		// values.includeRules and its siblings hold the run selection from --include-rule, which a generated baseline may follow, so they are not read.
		includeRules:   values.showRules,
		excludeRules:   values.hideRules,
		includePillars: values.showPillars,
		excludePillars: values.hidePillars,
	}
}

// generateBaselineFlagState groups analyse flags that change finding scope.
//
// Any non-empty field makes validateGenerateBaselineFlags refuse a --generate-baseline run.
// The include and exclude fields hold the display filters, not the run-selection flags of the same name.
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

// validateGenerateBaselineFlags refuses combinations that would make the generated baseline partial, not a fresh snapshot of current findings.
//
// state holds the flags that would narrow the snapshot; it returns nil only when every one of them is empty.
// Otherwise it returns an error naming the first conflict in order: --baseline, --diff-base, the changed-region flags, then the display filters.
func validateGenerateBaselineFlags(state generateBaselineFlagState) error {
	// A conflict such as --generate-baseline with --diff-base main stops the run before any scan; with none set, generation goes ahead.
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
// Both spellings set one option, such as an analyse display filter or the baseline migration source, and a non-empty family value
// wins rather than being combined with the superseded value, which is used only when the family value is empty.
//
// familyValue holds the family flag's value and supersededValue the value of the older spelling it replaced.
// When both are empty the result is an empty string.
func firstNonEmpty(familyValue, supersededValue string) string {
	if familyValue != "" {
		return familyValue
	}

	return supersededValue
}
