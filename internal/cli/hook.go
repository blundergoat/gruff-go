// Package cli implements the coding-agent hook command and JSON contract.
//
// This file backs gruff-go hook: it resolves hook flags, runs analysis, and applies optional changed-region and baseline context.
// The JSON on stdout carries the findings the user's current edit should address, and the exit code tells the agent whether to stop.
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
//
// It keeps config, changed-region, baseline, ignore, and path inputs together before analysis builds the gruff.hook.v2 response.
type hookFlagValues struct {
	format        string
	capabilities  bool
	configPath    string
	noConfig      bool
	changedRanges string
	// changedRangesSet records that the caller passed --changed-ranges, so an empty value is refused as an
	// unreadable scope rather than read as no filter at all.
	changedRangesSet bool
	diffMode         string
	diffPatch        []byte
	baselinePath     string
	includeIgnored   bool
	deepScanBudget   string
	// failOn is the lowest severity that blocks the user's edit; the hook's default of none keeps findings advisory.
	failOn finding.FailThreshold
	// gates carry the confidence floor and the baseline dimension, which apply beside the severity threshold.
	gates familyGateValues
	// failOnDiagnostics makes non-fatal report diagnostics block with exit 1; fatal analysis diagnostics retain exit 2.
	failOnDiagnostics bool
	paths             []string
}

// runHook executes the agent-hook JSON contract with advisory finding exits.
//
// commandArguments holds the hook's flags and paths; stdout gets help, capability or report JSON, and stderr gets errors and warnings.
//
// It returns 0 for help, capabilities or an unblocked report, 1 when hookExitCode blocks, and 2 when analysis reports exit code 2.
// It also returns 2 for flag, format, config, budget or analysis failures and for failed capability or report JSON writes.
// Non-degradable changed-region or baseline errors also return 2, after writeHookFatal emits the fatal payload.
func runHook(commandArguments []string, stdout, stderr io.Writer) int {
	// A help request returns guidance without scanning the user's project.
	if hookHelpRequested(commandArguments) {
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

	ruleRegistry, ignoredPathPatterns, hookConfig, err := configuredRegistry(hookFlags.configPath, hookFlags.noConfig, nil)
	// Invalid project config is returned in-band so the agent can explain it.
	if err != nil {
		// A secondary JSON write failure leaves no usable hook contract for the user.
		if writeErr := report.WriteJSON(stdout, hookConfigErrorReport(err)); writeErr != nil {
			fmt.Fprintln(stderr, writeErr)
		}
		return 2
	}
	deepScanBudget, err := resolveDeepScanBudget(hookFlags.deepScanBudget, hookConfig)
	// An invalid non-empty --deep-scan-budget lands here: the reason goes to stderr, stdout gets no JSON, and the run exits 2.
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	hookScan := hookBaseScan{
		registry:            ruleRegistry,
		ignoredPathPatterns: ignoredPathPatterns,
		sensitiveExclusions: sensitiveExclusionsFor(hookConfig),
		deepScanBudget:      deepScanBudget,
	}
	analysisReport, err := analyzeHook(hookFlags, hookScan)
	// Pipeline failures mean the user's requested project could not be analyzed.
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	projectRoot := analysisReport.Run.WorkingDirectory
	scanContext := context.Background()
	gitBaseWarningWritten := false
	changedLines, changedScopeEnabled, err := resolveHookChanged(scanContext, projectRoot, analysisReport.Paths.Scanned, hookFlags)
	// In HEAD, working-tree or staged mode, matching git-base error text disables changed-region filtering here; other errors stay fatal.
	if err != nil {
		// Non-degradable diff errors cannot produce trustworthy changed-region results.
		// Errors outside the git-base fallback, such as --diff main when git cannot resolve main, end as fatal changed-region JSON with exit 2.
		if !isDegradableHookGitBaseError(hookFlags.diffMode, err) {
			return writeHookFatal("changed-region", err, stdout, stderr)
		}
		writeHookGitBaseWarning(stderr, err, &gitBaseWarningWritten)
		changedScopeEnabled = false
	}
	findingBaseline, err := resolveHookFindingBaseline(scanContext, projectRoot, hookFlags, hookScan)
	// In HEAD, working-tree or staged mode, matching git-base error text disables baseline filtering here; other baseline errors stay fatal.
	if err != nil {
		// Non-git baseline failures cannot produce a trustworthy new-only result.
		// An unreadable --baseline file ends as fatal baseline JSON with exit 2 unless its error text matches the git-base fallback.
		if !isDegradableHookGitBaseError(hookFlags.diffMode, err) {
			return writeHookFatal("baseline", err, stdout, stderr)
		}
		writeHookGitBaseWarning(stderr, err, &gitBaseWarningWritten)
		findingBaseline = hookFindingBaseline{}
	}
	payload := buildHookReport(hookReportInput{
		analysisReport:      analysisReport,
		ruleDefinitions:     ruleRegistry.Definitions(),
		changedLines:        changedLines,
		changedScopeEnabled: changedScopeEnabled,
		hookBaseline:        findingBaseline,
		hookFlags:           hookFlags,
	})
	// The user-facing hook contract must be emitted as valid JSON.
	if err := report.WriteJSON(stdout, payload); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// Fatal analysis diagnostics retain exit 2 even though ordinary findings are advisory.
	if analysisReport.Summary.ExitCode == 2 {
		return 2
	}
	return hookExitCode(payload, hookFlags)
}

// hookExitCode decides what the hook tells the calling agent, from the findings it actually published.
//
// The gate is read over the payload rather than the raw scan, so what blocks an edit is exactly what the agent was shown.
// A finding the changed-region filter or the baseline removed is not in the payload and does not block.
//
// payload is the report already written for the agent, and hookFlags carries failOnDiagnostics, failOn and the confidence and new-finding gates.
// It returns 1 if failOnDiagnostics meets a diagnostic, failOnNew a new finding, or any finding reaches failOn and the confidence floor, else 0.
func hookExitCode(payload hookReport, hookFlags hookFlagValues) int {
	// With --fail-on-diagnostics, any published diagnostic blocks the edit with exit 1; a run that could not finish has already exited 2.
	if hookFlags.failOnDiagnostics && len(payload.Diagnostics) > 0 {
		return 1
	}

	for _, published := range payload.Findings {
		// The baseline dimension is independent of both floors: an unreviewed finding blocks whatever its severity.
		if hookFlags.gates.failOnNew && published.BaselineStatus != nil && *published.BaselineStatus == "new" {
			return 1
		}

		// A finding blocks here only when it reaches both --fail-on and --min-confidence; with the default --fail-on none, this check never blocks.
		if hookFlags.failOn.IsTriggeredBy(published.Severity) && reachesFamilyGate(string(published.Confidence), hookFlags.gates) {
			return 1
		}
	}

	return 0
}

// writeHookFatal reports a run that could not be completed through the contract the consumer is already parsing.
//
// A hook that printed only to stderr left an agent with an exit code and no machine-readable reason, so a malformed
// range and an unreadable baseline were indistinguishable from a crash.
//
// diagnosticType labels the fatal diagnostic and hookError supplies its message.
// stdout gets the fatal JSON payload, stderr always gets hookError plus any write error, and the result is always 2.
func writeHookFatal(diagnosticType string, hookError error, stdout, stderr io.Writer) int {
	// A secondary JSON write failure leaves no usable hook contract, so the reason still reaches stderr.
	if writeErr := report.WriteJSON(stdout, hookFatalReport(diagnosticType, hookError.Error())); writeErr != nil {
		fmt.Fprintln(stderr, writeErr)
	}

	fmt.Fprintln(stderr, hookError)
	return 2
}

// analyzeHook runs the primary tree with the same scan policy used for a git-base comparison.
//
// hookFlags supplies paths and includeIgnored; scan supplies the registry, ignore patterns, sensitive exclusions and deep-scan budget.
// It returns the analysis.Report built with JSON format and a fail threshold of none, leaving exit gates to the hook.
// Any error comes back unchanged from analysis.Analyze when the scan fails.
func analyzeHook(hookFlags hookFlagValues, scan hookBaseScan) (analysis.Report, error) {
	return analysis.Analyze(analysis.Options{
		Paths:               hookFlags.paths,
		Format:              "json",
		FailOn:              finding.FailThresholdNone,
		Registry:            scan.registry,
		IgnorePaths:         scan.ignoredPathPatterns,
		SensitiveExclusions: scan.sensitiveExclusions,
		DeepScanBudget:      scan.deepScanBudget,
		IncludeIgnored:      hookFlags.includeIgnored,
	})
}

// parseHookFlags validates hook options and keeps positional scan paths for the run.
//
// commandArguments is the raw hook argument list, run through normalizeAnalyseDiffArgs first; usage errors are written to stderr.
// With --diff -, it also reads the unified diff from stdin before analysis starts.
// It returns the parsed values and true, or the zero hookFlagValues and false, which makes runHook exit 2 before analysis.
func parseHookFlags(commandArguments []string, stderr io.Writer) (hookFlagValues, bool) {
	flagSet := flag.NewFlagSet("hook", flag.ContinueOnError)
	flagSet.SetOutput(stderr)
	flagSet.Usage = func() { writeCommandHelp("hook", commandUsages["hook"], stderr, ansiStyler{}) }
	outputFormat := flagSet.String("format", "json", "output format: json")
	capabilitiesRequested := flagSet.Bool("capabilities", false, "emit gruff.hook.v1 capability metadata and exit")
	configPath := flagSet.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flagSet.Bool("no-config", false, "skip auto-loading default gruff config")
	changedRanges := flagSet.String("changed-ranges", "", "explicit changed line ranges such as 3-3,8-10")
	diffMode := flagSet.String("diff", "", "changed-region/new-only source: working-tree, staged, unstaged, base ref, or - for unified diff on stdin")
	baselinePath := flagSet.String("baseline", "", "baseline file to apply for stable-identity new-only")
	includeIgnored := flagSet.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	deepScanBudget := flagSet.String("deep-scan-budget", "", "override both deep-scan bounds as LINES:BYTES, or disable with off")
	failOn := flagSet.String("fail-on", string(finding.FailThresholdNone), "lowest severity that exits 1; the hook's default of none keeps findings advisory")
	minConfidence := flagSet.String("min-confidence", "", "lowest confidence that reaches the exit gate: low, medium or high")
	failOnNew := flagSet.Bool("fail-on-new", false, "exit 1 when any published finding is new against the applied baseline")
	failOnDiagnostics := flagSet.Bool("fail-on-diagnostics", false, "exit 1 when the run reports any diagnostic, however minor")
	normalizedArguments := normalizeAnalyseDiffArgs(commandArguments)
	// Invalid flag syntax is already explained to the user through stderr.
	if err := parseCommandArguments(flagSet, normalizedArguments); err != nil {
		return hookFlagValues{}, false
	}
	// The hook rejects --min-severity; --fail-on selects the severity exit gate.
	if refuseMinSeverity(flagSet, stderr) {
		return hookFlagValues{}, false
	}
	failThreshold, err := finding.ParseFailThreshold(*failOn)
	// A gate the user did not get is worse than a command that refused, so a mistyped severity stops the run.
	if err != nil {
		fmt.Fprintln(stderr, err)
		return hookFlagValues{}, false
	}
	gates, gatesValid := parseFamilyGates(*minConfidence, *failOnNew, stderr)
	// An unparseable confidence floor is a usage error for the same reason a mistyped severity is.
	if !gatesValid {
		return hookFlagValues{}, false
	}
	diffPatch, patchRead := readDiffPatchIfRequested(*diffMode, stderr)
	// A failed stdin patch read leaves no reliable changed-region input.
	if !patchRead {
		return hookFlagValues{}, false
	}
	return hookFlagValues{
		format:            *outputFormat,
		capabilities:      *capabilitiesRequested,
		configPath:        *configPath,
		noConfig:          *noConfig,
		changedRanges:     *changedRanges,
		changedRangesSet:  flagProvided(flagSet, "changed-ranges"),
		diffMode:          *diffMode,
		diffPatch:         diffPatch,
		baselinePath:      *baselinePath,
		includeIgnored:    *includeIgnored,
		deepScanBudget:    *deepScanBudget,
		failOn:            failThreshold,
		gates:             gates,
		failOnDiagnostics: *failOnDiagnostics,
		paths:             flagSet.Args(),
	}, true
}

// hookHelpRequested recognises help anywhere before an explicit parsing terminator.
//
// Run it before FlagSet parsing so help returns the hook's command guidance instead of a scan.
// commandArguments is normalized as in parseHookFlags, and hookFlagHasSeparateValue keeps flag values from counting as help.
// It returns true when the user asked for help, as in gruff-go hook --help, and false otherwise.
func hookHelpRequested(commandArguments []string) bool {
	normalizedArguments := normalizeAnalyseDiffArgs(commandArguments)
	return helpRequested(normalizedArguments, hookFlagHasSeparateValue)
}

// hookFlagHasSeparateValue identifies hook flags whose value is the next token.
//
// The help pre-scan uses it so flag values that resemble --help stay values.
// It returns true when flagArgument, without leading dashes, names a non-Boolean hook flag and has no equals sign; otherwise false.
func hookFlagHasSeparateValue(flagArgument string) bool {
	// An inline assignment leaves the following token available as a path or another flag.
	if strings.Contains(flagArgument, "=") {
		return false
	}
	// These are the hook's non-Boolean flags; every other supported flag is self-contained.
	switch strings.TrimLeft(flagArgument, "-") {
	case "format", "config", "changed-ranges", "diff", "baseline", "deep-scan-budget", "fail-on", "min-confidence":
		return true
	default:
		// Boolean and unknown flags do not reserve the next token during the help pre-scan.
		return false
	}
}

// hookConfigErrorReport builds the in-band config failure payload required by B8.
//
// Reached when gruff-go hook finds the project config invalid, such as a malformed .gruff-go.yaml; the run then exits 2.
// configError supplies the message for the fatal config diagnostic and the config error, whose remediation names .gruff-go.yaml and --no-config.
// It returns the hookFatalReport payload with Config.SchemaOK false and that error attached.
func hookConfigErrorReport(configError error) hookReport {
	failure := hookConfigError{
		Message:     configError.Error(),
		Remediation: "Fix the reported problem in .gruff-go.yaml, or pass --no-config to run without project configuration.",
	}
	payload := hookFatalReport("config", configError.Error())
	payload.Config = hookConfigState{SchemaOK: false, Error: &failure}
	return payload
}

// hookFatalReport builds the payload that accompanies a run which could not be completed.
//
// Required fields stay present with empty result collections, so a consumer parses one shape whether the run succeeded or not.
// The consumer reads the reason from the fatal diagnostic instead of scraping stderr.
//
// diagnosticType and message fill the single fatal diagnostic.
// It returns a full-mode, file-scope payload with empty paths, findings, suppressions and ignored paths, and Config.SchemaOK true.
func hookFatalReport(diagnosticType, message string) hookReport {
	return hookReport{
		ContractVersion: hookContractVersion,
		Analyzer:        hookAnalyzer{Name: "gruff-go", Version: toolVersion},
		Run:             hookRun{Mode: "full", Scope: "file", Paths: []string{}, Baseline: hookRunBaseline{}},
		Findings:        []hookFinding{},
		// The requested run could not be completed, so this diagnostic is fatal rather than a caveat on a usable report.
		Diagnostics: []hookDiagnostic{{
			Type:     diagnosticType,
			Severity: "fatal",
			Message:  message,
		}},
		Suppressed:   hookSuppressed{},
		Suppressions: []hookSuppression{},
		Ignored:      hookIgnored{Paths: []hookIgnoredPath{}},
		Config:       hookConfigState{SchemaOK: true},
	}
}

// isDegradableHookGitBaseError spots git-base failures that let the hook continue with the affected filter disabled.
//
// For example, gruff-go hook --diff staged in a repository with no commits yet degrades instead of failing.
// diffMode must be HEAD, working-tree or staged and hookError must match a missing-revision or no-commits git message; a nil hookError is false.
// It reports true when the caller may warn and disable only the failing stage's filter, and false when the failure stays fatal.
func isDegradableHookGitBaseError(diffMode string, hookError error) bool {
	// A nil error needs no fallback or warning in the user-facing hook run.
	if hookError == nil {
		return false
	}
	// Only HEAD, working-tree and staged degrade; an explicit ref such as --diff main stays fatal when git cannot resolve it.
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

// writeHookGitBaseWarning prints the git-base fallback warning to stderr at most once per hook run, leaving the stdout JSON untouched.
// stderr receives one warning containing hookError, and warningWritten is set so later calls in the same run write nothing.
func writeHookGitBaseWarning(stderr io.Writer, hookError error, warningWritten *bool) {
	// Multiple git operations may fail from the same missing base; explain it once.
	if *warningWritten {
		return
	}
	fmt.Fprintf(stderr, "git diff base unavailable: %v; scanning requested paths without diff/new-only filtering\n", hookError)
	*warningWritten = true
}
