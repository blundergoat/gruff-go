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

	switch args[0] {
	case "analyse", "analyze":
		return runAnalyse(args[1:], stdout, stderr, interactive)
	case "hook":
		return runHook(args[1:], stdout, stderr)
	case "baseline":
		return runBaseline(args[1:], stdout, stderr)
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "completion":
		return runCompletion(args[1:], stdout, stderr)
	case "list-rules":
		return runListRules(args[1:], stdout, stderr)
	case "check-ignore":
		return runCheckIgnore(args[1:], stdout, stderr)
	case "summary":
		return runSummary(args[1:], stdout, stderr, interactive)
	case "report":
		return runReport(args[1:], stdout, stderr, interactive)
	case "dashboard":
		return runDashboard(args[1:], stdout, stderr, interactive)
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
	failOn, ok := resolveFailOn(values.minSeverityRaw, values.minSeverityExplicit, cfg, "analyse", stderr)
	if !ok {
		return 2
	}
	if values.generateBaselinePath != "" {
		return writeBaselineFromScan(baselineScanOptions{
			paths:          flags.Args(),
			outPath:        values.generateBaselinePath,
			registry:       registry,
			ignorePaths:    ignorePaths,
			includeIgnored: values.includeIgnored,
		}, stdout, stderr)
	}
	displayFilter, err := parseDisplayFilter(values.includeRules, values.excludeRules, values.includePillars, values.excludePillars, registry.Definitions())
	if err != nil {
		fmt.Fprintf(stderr, "display filter: %v\n", err)
		return 2
	}
	analysisReport, err := analysis.Analyze(analysis.Options{
		Paths:                  flags.Args(),
		Format:                 values.format,
		FailOn:                 failOn,
		Registry:               registry,
		IgnorePaths:            ignorePaths,
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

// resolveFailOn applies the ADR-010 precedence rule for any CLI consumer:
// explicit CLI flag wins, otherwise the matching minimumSeverity.<cmd> config
// entry, otherwise the binary default from DefaultFailThresholdFor. Returns
// (threshold, ok); on parse failure prints the error to stderr and returns
// (zero-value, false) so the caller can `return 2`.
func resolveFailOn(rawValue string, flagExplicit bool, cfg cfgpkg.Config, cmd string, stderr io.Writer) (finding.FailThreshold, bool) {
	resolved := rawValue
	if !flagExplicit {
		if cfgValue := cfg.MinimumSeverity[cmd]; cfgValue != "" {
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

// checkMinSeverityFlag detects whether --min-severity / --fail-on was passed
// explicitly on the FlagSet, and early-validates the raw value when explicit so
// the user sees flag-syntax errors before any config load. Returns (explicit,
// ok); on parse failure prints to stderr and returns (_, false). Shared by
// runAnalyse / runSummary / runReport so the detection + early-validate block
// lives in one place.
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
