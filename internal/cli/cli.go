// Package cli implements the gruff-go command-line interface.
// It wires flags and dispatches user commands to the analysis pipeline.
// Output adapters turn internal results into terminal and automation responses.
package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/blundergoat/gruff-go/internal/analysis"
	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// toolVersion is the released gruff-go semantic version printed by --version.
const toolVersion = "0.5.0"

// Main is the CLI entrypoint that parses args and dispatches subcommands.
func Main(args []string, stdout, stderr io.Writer) int {
	// `--diff -` and `--since -` must read as one flag-and-value pair before any
	// extractor below treats the bare dash as an operand terminator and strands
	// every later global flag in the command's own argument list.
	args = normalizeGlobalStdinFlagValues(args)
	args, ansiPref := extractAnsiFlags(args)
	args, quiet := extractQuiet(args)
	args, noInteraction := extractNoInteraction(args)
	args = extractVerbose(args)
	if quiet {
		stdout = io.Discard
	}
	interactive := !noInteraction && !quiet
	stdoutStyle := ansiStyler{enabled: ansiEnabled(stdout, ansiPref)}
	stderrStyle := ansiStyler{enabled: ansiEnabled(stderr, ansiPref)}

	if len(args) == 0 {
		usage(stderr, stderrStyle)
		return 2
	}

	if isVersionFlag(args[0]) {
		fmt.Fprintf(stdout, "gruff-go %s\n", toolVersion)
		return 0
	}
	if args[0] == "--capabilities" {
		if err := writeHookCapabilities(stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return 0
	}

	if exitCode, handled := runScanCommand(args, stdout, stderr, interactive); handled {
		return exitCode
	}
	return runSupportCommand(args, stdout, stderr, stdoutStyle, stderrStyle)
}

// runScanCommand dispatches the commands that analyse a project, reporting whether it recognised the name so the
// caller can try the support commands rather than guessing which half owns an unknown one.
func runScanCommand(args []string, stdout, stderr io.Writer, interactive bool) (int, bool) {
	switch args[0] {
	case "analyse", "analyze":
		return runAnalyse(args[1:], stdout, stderr, interactive), true
	case "hook":
		return runHook(args[1:], stdout, stderr), true
	case "baseline":
		return runBaseline(args[1:], stdout, stderr), true
	case "summary":
		return runSummary(args[1:], stdout, stderr, interactive), true
	case "report":
		return runReport(args[1:], stdout, stderr, interactive), true
	case "dashboard":
		return runDashboard(args[1:], stdout, stderr, interactive), true
	case "check-ignore":
		return runCheckIgnore(args[1:], stdout, stderr), true
	default:
		return 0, false
	}
}

// runSupportCommand dispatches the commands that manage configuration, list what gruff-go knows, and print help.
// It owns the unknown-command path, because by the time control reaches here no command recognises the name.
func runSupportCommand(args []string, stdout, stderr io.Writer, stdoutStyle, stderrStyle ansiStyler) int {
	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "migrate-config":
		return runMigrateConfig(args[1:], stdout, stderr)
	case "completion":
		return runCompletion(args[1:], stdout, stderr)
	case "list-rules":
		return runListRules(args[1:], stdout, stderr)
	case "list":
		usage(stdout, stdoutStyle)
		return 0
	case "help", "-h", "--help":
		if len(args) > 1 {
			return helpForCommand(args[1], stdout, stderr, stdoutStyle, stderrStyle)
		}
		usage(stdout, stdoutStyle)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr, stderrStyle)
		return 2
	}
}

// extractQuiet removes global quiet flags before command dispatch.
// Flags may follow paths, but a bare dash or `--` protects every later token as positional input.
func extractQuiet(commandArguments []string) ([]string, bool) {
	remainingArguments := make([]string, 0, len(commandArguments))
	quietRequested := false
	// Quiet flags remain global until the caller explicitly ends flag parsing.
	for argumentIndex, argument := range commandArguments {
		// The command parser must receive the terminator and every protected operand unchanged.
		if argument == "--" || argument == "-" {
			remainingArguments = append(remainingArguments, commandArguments[argumentIndex:]...)
			break
		}
		switch argument {
		case "-q", "--quiet", "--silent":
			// Quiet mode discards command stdout regardless of where the flag appears.
			quietRequested = true
		default:
			// All other tokens continue to command-specific parsing.
			remainingArguments = append(remainingArguments, argument)
		}
	}
	return remainingArguments, quietRequested
}

// extractVerbose accepts common Symfony-style verbosity flags. gruff-go does
// not currently vary output by verbosity, but accepting these flags keeps the
// global surface consistent across gruff implementations.
func extractVerbose(commandArguments []string) []string {
	remainingArguments := make([]string, 0, len(commandArguments))
	// Compatibility verbosity flags are accepted anywhere before a parsing terminator.
	for argumentIndex, argument := range commandArguments {
		// Later flag-shaped tokens are paths or stdin operands, not global verbosity requests.
		if argument == "--" || argument == "-" {
			remainingArguments = append(remainingArguments, commandArguments[argumentIndex:]...)
			break
		}
		switch argument {
		case "-v", "-vv", "-vvv", "--verbose":
			// Gruff accepts family-wide verbosity spellings but does not vary its output yet.
			continue
		default:
			// Command-specific tokens pass through unchanged.
			remainingArguments = append(remainingArguments, argument)
		}
	}
	return remainingArguments
}

// isVersionFlag reports whether the argument requests version output.
func isVersionFlag(arg string) bool {
	return arg == "-V" || arg == "--version"
}

// analyseHelpRequested recognises help anywhere before an explicit parsing terminator.
// Run it before FlagSet parsing so help writes usage to stdout and exits successfully.
func analyseHelpRequested(commandArguments []string) bool {
	normalizedArguments := normalizeAnalyseDiffArgs(commandArguments)
	return helpRequested(normalizedArguments, analyseFlagHasSeparateValue)
}

// runAnalyse executes the analyse subcommand and renders the scan report.
func runAnalyse(args []string, stdout, stderr io.Writer, interactive bool) int {
	if analyseHelpRequested(args) {
		writeCommandHelp("analyse", commandUsages["analyse"], stdout, ansiStyler{})
		return 0
	}
	flags, values, ok := parseAnalyseFlags(args, stderr)
	if !ok {
		return 2
	}
	registry, ignorePaths, cfg, err := configuredRegistryInteractive(values.configPath, values.noConfig, interactive, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	registry, cfg, ok = selectedRegistryFor(values, registry, cfg, stderr)
	// A selector naming a rule or pillar nobody defines is a usage error; scanning everything would answer a question
	// the user did not ask.
	if !ok {
		return 2
	}
	failOn, ok := resolveFailOn(values.minSeverityRaw, values.minSeverityExplicit, cfg, "analyse", stderr)
	if !ok {
		return 2
	}
	deepScanBudget, err := resolveDeepScanBudget(values.deepScanBudget, cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if values.generateBaselinePath != "" {
		return writeBaselineFromScan(baselineScanOptions{
			paths:               flags.Args(),
			outPath:             values.generateBaselinePath,
			registry:            registry,
			ignorePaths:         ignorePaths,
			includeIgnored:      values.includeIgnored,
			sensitiveExclusions: sensitiveExclusionsFor(cfg),
			deepScanBudget:      deepScanBudget,
			force:               values.force,
		}, stdout, stderr)
	}
	displayFilter, ok := analyseDisplayFilter(values, registry, cfg, stderr)
	if !ok {
		return 2
	}
	projectRoot, err := projectRootFromTargets(flags.Args())
	// The caller named targets in unrelated projects, so there is no single root to report paths against.
	if err != nil {
		fmt.Fprintf(stderr, "project root: %v\n", err)
		return 2
	}
	analysisReport, err := analysis.Analyze(analysis.Options{
		Root:                   projectRoot,
		Paths:                  flags.Args(),
		Format:                 values.format,
		FailOn:                 failOn,
		MinConfidence:          finding.Confidence(values.gates.minConfidence),
		FailOnNew:              values.gates.failOnNew,
		Registry:               registry,
		IgnorePaths:            ignorePaths,
		SensitiveExclusions:    sensitiveExclusionsFor(cfg),
		DeepScanBudget:         deepScanBudget,
		IncludeIgnored:         values.includeIgnored,
		ReportAllSkippedInputs: true,
		BaselinePath:           values.baselinePath,
		DiffBase:               values.diffBase,
		DiffMode:               values.resolvedDiffMode(),
		DiffPatch:              values.diffPatch,
		ChangedRanges:          values.changedRanges,
		ChangedScope:           values.changedScope,
		BaselineShow:           values.baselineShow,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	analysis.ApplyDisplayFilter(&analysisReport, displayFilter)
	if err := writeAnalysisReport(stdout, values.format, analysisReport, report.HTMLOptions{EditorLink: values.editorLink, Interactive: values.reportInteractive}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return analysisReport.Summary.ExitCode
}

// resolveFailOn decides which severity makes the command exit non-zero, following ADR-010 precedence:
//
//   - an explicit CLI flag wins;
//   - otherwise the matching minimumSeverity.<cmd> entry in the project config;
//   - otherwise the binary default from DefaultFailThresholdFor.
//
// Returns (threshold, ok). A value the user mistyped prints the error to stderr and returns ok=false, so the caller exits 2.
func resolveFailOn(rawValue string, flagExplicit bool, cfg cfgpkg.Config, cmd string, stderr io.Writer) (finding.FailThreshold, bool) {
	resolved := rawValue
	if !flagExplicit {
		if cfgValue := cfg.FailOn[cmd]; cfgValue != "" {
			resolved = cfgValue
		}
	}
	parsed, err := finding.ParseFailThreshold(resolved)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return "", false
	}
	return parsed, true
}

// analyseDisplayFilter builds what the report shows, from the four selectors and the configured severity floor.
//
// Everything here is presentation: the exit code and the score were decided by the rules that ran, so hiding a finding
// from the report never changes them. It reports false after explaining an unknown rule or pillar on stderr.
func analyseDisplayFilter(values analyseFlagValues, registry rule.Registry, cfg cfgpkg.Config, stderr io.Writer) (analysis.DisplayFilter, bool) {
	displayFilter, err := parseDisplayFilter(values.showRules, values.hideRules, values.showPillars, values.hidePillars, registry.Definitions())
	if err != nil {
		fmt.Fprintf(stderr, "display filter: %v\n", err)
		return analysis.DisplayFilter{}, false
	}

	// The configured floor is the only form of it in 0.6.0; --min-severity returns with the family meaning in 0.7.0.
	if floor, configured := cfg.MinimumSeverity.Severity(); configured {
		displayFilter.MinimumSeverity = floor
	}

	return displayFilter, true
}

// selectedRegistryFor narrows the registry to the rules the user asked to run, leaving both unchanged when they asked
// for no restriction. It reports false after explaining an unknown rule or pillar on stderr.
func selectedRegistryFor(values analyseFlagValues, registry rule.Registry, cfg cfgpkg.Config, stderr io.Writer) (rule.Registry, cfgpkg.Config, bool) {
	selectors := executionSelectors{
		includeRules:   values.includeRules,
		excludeRules:   values.excludeRules,
		includePillars: values.includePillars,
		excludePillars: values.excludePillars,
	}

	selectedRegistry, selectedConfig, err := applyExecutionSelectors(cfg, selectors, registry.Definitions())
	if err != nil {
		fmt.Fprintf(stderr, "execution selector: %v\n", err)
		return registry, cfg, false
	}

	// An unrestricted run keeps the configured registry rather than rebuilding an identical one.
	if !selectors.requested() {
		return registry, cfg, true
	}

	return selectedRegistry, selectedConfig, true
}

// checkMinSeverityFlag reports whether --min-severity or --fail-on was typed on the command line, and validates the value
// straight away when it was, so a mistyped severity is rejected before any config file is read.
//
// Returns (explicit, ok); a bad value prints to stderr and returns ok=false.
// Shared by runAnalyse, runSummary, and runReport so this detection lives in one place.
func checkMinSeverityFlag(flags *flag.FlagSet, rawValue string, stderr io.Writer) (bool, bool) {
	explicit := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "min-severity" || f.Name == "fail-on" {
			explicit = true
		}
	})
	if explicit {
		if _, err := finding.ParseFailThreshold(rawValue); err != nil {
			fmt.Fprintln(stderr, err)
			return explicit, false
		}
	}
	return explicit, true
}

// writeAnalysisReport serialises the analysis report to writer in the chosen format.
func writeAnalysisReport(writer io.Writer, format string, analysisReport analysis.Report, htmlOpts report.HTMLOptions) error {
	switch format {
	case "json":
		return report.WriteJSON(writer, analysisReport)
	case "summary-json":
		return report.WriteSummaryJSON(writer, analysisReport)
	case "sarif":
		return report.WriteSARIF(writer, analysisReport)
	case "github":
		return report.WriteGitHub(writer, analysisReport)
	case "html":
		return report.WriteHTML(writer, analysisReport, htmlOpts)
	case "markdown", "md":
		return report.WriteMarkdown(writer, analysisReport)
	default:
		return report.WriteText(writer, analysisReport)
	}
}

// runListRules prints metadata for every registered rule.
func runListRules(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("list-rules", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	if err := parseCommandArguments(flags, args); err != nil {
		return 2
	}
	// The registry is the whole subject, so an operand here is input the command would drop.
	if flags.NArg() > 0 {
		fmt.Fprintln(stderr, "list-rules takes no positional arguments")
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "unsupported format %q\n", *format)
		return 2
	}
	registry, _, _, err := configuredRegistry(*configPath, *noConfig)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	definitions := registry.Definitions()
	if *format == "json" {
		payload := struct {
			SchemaVersion string               `json:"schemaVersion"`
			Rules         []ruleListDefinition `json:"rules"`
		}{
			SchemaVersion: analysis.SchemaVersion,
			Rules:         ruleListDefinitions(definitions),
		}
		if err := report.WriteJSON(stdout, payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return 0
	}
	if err := report.WriteRuleText(stdout, definitions); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}

// ruleListDefinition adds precision guidance to catalogue JSON.
// Embedding keeps the existing metadata while analysis reports omit this field.
// Users receive it only when they explicitly inspect the rule catalogue.
type ruleListDefinition struct {
	rule.Definition
	FalsePositiveShapes []rule.FalsePositiveShape `json:"falsePositiveShapes,omitempty"`
}

// ruleListDefinitions prepares registered rules for users inspecting catalogue JSON.
// The adapter prevents catalogue guidance from changing analysis-report schemas.
func ruleListDefinitions(definitions []rule.Definition) []ruleListDefinition {
	listedDefinitions := make([]ruleListDefinition, 0, len(definitions))
	// Preserve registry order so text and JSON catalogue users see the same sequence.
	for _, definition := range definitions {
		listedDefinitions = append(listedDefinitions, ruleListDefinition{
			Definition:          definition,
			FalsePositiveShapes: definition.FalsePositiveShapes,
		})
	}
	return listedDefinitions
}
