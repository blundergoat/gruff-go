// Package cli implements the gruff-go command-line interface.
//
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
//
// gruff-go -V or gruff-go --version, given in place of a command, prints gruff-go followed by this value and exits 0.
const toolVersion = "0.6.0"

// Main is the CLI entrypoint that parses args and dispatches subcommands.
//
// args holds the command line without the program name; global quiet, verbosity, no-interaction, and ANSI flags are removed before dispatch.
// stdout receives command output and is discarded when a quiet flag is given; stderr receives usage text and errors.
// It returns the exit code, 2 when no command is given or the name is unknown, and otherwise the code of the flag or command that ran.
func Main(args []string, stdout, stderr io.Writer) int {
	// The --diff - and --since - pairs must be joined before any extractor below treats the bare dash as an operand terminator.
	// Otherwise every later global flag, such as --quiet, is stranded in the command's own argument list.
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

	// With no command left once quiet, verbosity, no-interaction, and ANSI flags are removed, gruff-go prints usage to stderr and exits 2.
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

// runScanCommand dispatches the scan-side commands: analyse, hook, baseline, summary, report, dashboard, and check-ignore.
//
// args holds the command name followed by its arguments and must not be empty; stdout and stderr pass through to the command.
// interactive reaches only analyse, summary, report, and dashboard; Main sets it false under the quiet or no-interaction flags.
//
// It returns the command's exit code and true, or 0 and false when args names no scan command, so Main tries the support commands next.
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
//
// It also owns the unknown-command path: Main sends a name here only after runScanCommand declines it.
// A typo such as gruff-go analize prints unknown command "analize" and the usage text to stderr, then exits 2.
//
// args holds the command name followed by its arguments and must not be empty; stdout and stderr pass through to the command.
// stdoutStyle and stderrStyle apply ANSI styling to the usage and help text written to each stream.
// It returns the command's exit code, 0 after list or help without a topic, and 2 for an unknown name.
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
		// gruff-go help analyse shows that command's help; plain gruff-go help, -h, or --help prints the full usage to stdout and exits 0.
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
//
// Flags may follow paths, but a bare dash or -- protects every later token as positional input.
// commandArguments is the global argument list, read but never modified.
// It returns the arguments without the quiet flags, and true when -q, --quiet, or --silent appeared before any terminator.
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
			// Quiet mode discards command stdout wherever the flag appears before a terminator, even after the command name or a path.
			quietRequested = true
		default:
			// All other tokens continue to command-specific parsing.
			remainingArguments = append(remainingArguments, argument)
		}
	}
	return remainingArguments, quietRequested
}

// extractVerbose accepts and drops Symfony-style verbosity flags; gruff-go does not currently vary output by verbosity.
//
// Accepting these flags keeps the global surface consistent across gruff implementations.
// commandArguments is the global argument list, read but never modified.
// It returns a new slice without -v, -vv, -vvv, or --verbose; a bare dash or double dash and every later token are kept unchanged.
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
// arg requests it only when it is exactly -V or --version.
func isVersionFlag(arg string) bool {
	return arg == "-V" || arg == "--version"
}

// analyseHelpRequested recognises help anywhere before an explicit parsing terminator.
//
// It runs before FlagSet parsing, so gruff-go analyse src --help still writes usage to stdout and exits 0.
// commandArguments holds the analyse arguments after the command name, passed through normalizeAnalyseDiffArgs before the check.
// It reports true when help is requested before any terminator, and false otherwise.
func analyseHelpRequested(commandArguments []string) bool {
	normalizedArguments := normalizeAnalyseDiffArgs(commandArguments)
	return helpRequested(normalizedArguments, analyseFlagHasSeparateValue)
}

// baselineScan assembles the scan --generate-baseline runs, which reads the same resolved config as the report it replaces.
//
// paths are the scan targets, registry holds the rules to run, and ignorePaths the configured ignore paths.
// cfg supplies the sensitive exclusions and deepScanBudget the resolved budget; values adds the output path, include-ignored, and force flags.
// It returns the options writeBaselineFromScan consumes, filled field for field without validation.
func (values analyseFlagValues) baselineScan(paths []string, registry rule.Registry, ignorePaths []string, cfg cfgpkg.Config, deepScanBudget analysis.DeepScanBudget) baselineScanOptions {
	return baselineScanOptions{
		paths:               paths,
		outPath:             values.generateBaselinePath,
		registry:            registry,
		ignorePaths:         ignorePaths,
		includeIgnored:      values.includeIgnored,
		sensitiveExclusions: sensitiveExclusionsFor(cfg),
		deepScanBudget:      deepScanBudget,
		force:               values.force,
	}
}

// runAnalyse executes the analyse subcommand and renders the scan report.
//
// args follow the command name; stdout receives help and the report, stderr receives errors, and interactive reaches config loading.
// It returns 0 after help and 2 when flags, selectors, config, targets, analysis, or the report write fail.
// A baseline run returns the writer's exit code, and a completed scan the report summary's exit code.
func runAnalyse(args []string, stdout, stderr io.Writer, interactive bool) int {
	if analyseHelpRequested(args) {
		writeCommandHelp("analyse", commandUsages["analyse"], stdout, ansiStyler{})
		return 0
	}
	flags, values, ok := parseAnalyseFlags(args, stderr)
	// An unknown or malformed flag, such as --formt json, has already been explained on stderr, so the run exits 2.
	if !ok {
		return 2
	}
	registry, ignorePaths, cfg, err := configuredRegistryInteractive(values.configPath, values.noConfig, interactive, stderr, flags.Args())
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		// A typo in --config, or a .gruff-go.yaml that does not parse, lands here: the run could not start, so it exits 2.
		// For json, summary-json, or sarif, the failure also appears in the report envelope, not only on stderr.
		return writeFailedRunReport(values, analysis.ConfigErrorDiagnosticType, err, stdout)
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
	// Reached by gruff-go analyse --generate-baseline FILE: the scan writes a baseline instead of a report, and its exit code is the writer's.
	if values.generateBaselinePath != "" {
		return writeBaselineFromScan(values.baselineScan(flags.Args(), registry, ignorePaths, cfg, deepScanBudget), stdout, stderr)
	}
	displayFilter, ok := analyseDisplayFilter(values, registry, cfg, stderr)
	if !ok {
		return 2
	}
	// With several targets, any one outside the launch directory is refused with exit 2; a single outside target is not refused here.
	// For json, summary-json, or sarif, the refusal also appears in the report envelope rather than as a serialiser failure on stderr.
	if outside, found := targetOutsideLaunchDirectory(flags.Args()); found {
		err := fmt.Errorf("target %q is outside the launch directory; gruff-go analyses several targets only from a directory that contains them all", outside)
		fmt.Fprintf(stderr, "targets: %v\n", err)
		return writeFailedRunReport(values, analysis.TargetErrorDiagnosticType, err, stdout)
	}
	projectRoot, err := projectRootFromTargets(flags.Args())
	// If the launch directory cannot be read, the run exits 2 with a project root error on stderr and no report.
	if err != nil {
		fmt.Fprintf(stderr, "project root: %v\n", err)
		return 2
	}
	analysisReport, err := analysis.Analyze(analysis.Options{
		Root:                   projectRoot,
		Paths:                  targetsForRoot(projectRoot, flags.Args()),
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
		BaselinePath:           baselinePathForRun(projectRoot, values),
		DiffBase:               values.diffBase,
		DiffMode:               values.resolvedDiffMode(),
		DiffPatch:              values.diffPatch,
		ChangedRanges:          values.changedRanges,
		ChangedRangesProvided:  values.changedRangesSet,
		ChangedScope:           values.changedScope,
		BaselineShow:           values.baselineShow,
	})
	// Analysis that fails outright prints its error to stderr and exits 2 without a report, even when a machine format was asked for.
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// Hiding findings changes only what the report shows; the exit code returned below was decided before the filter ran.
	analysis.ApplyDisplayFilter(&analysisReport, displayFilter)
	if err := writeAnalysisReport(stdout, values.format, analysisReport, report.HTMLOptions{EditorLink: values.editorLink, Interactive: values.reportInteractive}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return analysisReport.Summary.ExitCode
}

// resolveFailOn decides which severity makes the command exit non-zero, following ADR-010 precedence.
//
//   - an explicit CLI flag wins;
//   - otherwise the matching failOn.<cmd> entry in the project config;
//   - otherwise the binary default from DefaultFailThresholdFor.
//
// Returns (threshold, ok). A value the user mistyped prints the error to stderr and returns ok=false, so the caller exits 2.
// rawValue is the flag value, used when flagExplicit is true or cfg has no failOn entry for cmd, and so supplies the default too.
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
// from the report never changes them.
//
// It returns the display filter and true, or a zero filter and false after explaining an unknown rule or pillar on stderr.
// values carries the show and hide selectors, registry the rule definitions they are checked against, and cfg the configured severity floor.
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

// selectedRegistryFor applies the include and exclude selectors the user typed, leaving registry and cfg unchanged when no selector is set.
//
// It returns the resulting registry and config with true, or the originals with false after explaining an unknown rule or pillar on stderr.
// values carries the include and exclude selectors; cfg is the loaded config, returned unchanged on error or when no selector is set.
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

// flagProvided reports whether the user passed the named flag, which a string flag's value cannot answer: absent and empty both read as "".
// flags must already be parsed, since Visit sees only flags that were set, and name is the flag name without leading dashes.
func flagProvided(flags *flag.FlagSet, name string) bool {
	provided := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == name {
			provided = true
		}
	})

	return provided
}

// checkMinSeverityFlag reports whether --min-severity or --fail-on was typed on the command line, validating the value when it was.
//
// A mistyped severity such as --fail-on hgih is rejected here, before any config file is read.
// Returns (explicit, ok); a bad value prints to stderr and returns ok=false.
//
// Shared by runAnalyse, runSummary, and runReport so this detection lives in one place.
// flags must already be parsed, and rawValue is the value given for those flags, validated only when one of them was set.
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

// writeFailedRunReport publishes the envelope a run that could not start owes a json, summary-json, or sarif caller, and returns its exit code.
//
// Every other format, github included, already has the reason on stderr and gets no envelope; every other port draws the line in the same place.
// Reached when gruff-go analyse --format json cannot load its config, or gets several targets with one outside the launch directory.
//
// values supplies the output format, diagnosticType and cause describe the failure inside the envelope, and stdout receives it.
// Only json, summary-json, and sarif get the envelope, and the exit code is 2 even when writing it fails.
func writeFailedRunReport(values analyseFlagValues, diagnosticType string, cause error, stdout io.Writer) int {
	switch values.format {
	case "json", "summary-json", "sarif":
		failed := analysis.FailedRunReport(".", values.format, diagnosticType, cause.Error())
		if err := writeAnalysisReport(stdout, values.format, failed, report.HTMLOptions{}); err != nil {
			return 2
		}
	}

	return 2
}

// writeAnalysisReport serialises the analysis report to writer in the chosen format.
//
// analysisReport is the report to write; format picks json, summary-json, sarif, github, html, markdown, or md, and any other value writes text.
// htmlOpts applies only to html, and it returns an error when the chosen report writer fails.
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

// runListRules prints metadata for every built-in rule, whatever the project config enables or overrides.
//
// args follow the command name and accept --format text or json, --config, and --no-config; stdout receives the listing and stderr the errors.
// It returns 0 after listing the built-in catalogue and 2 for a bad flag, an operand, an unsupported format, a broken config, or a failed write.
func runListRules(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("list-rules", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	// An unknown flag, such as gruff-go list-rules --json, is explained on stderr by the flag parser, and the command exits 2.
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
	// The config is still loaded, so a broken one makes list-rules exit 2 even though the listing is the built-in catalogue.
	//
	// defaultSeverity and defaultEnabled name release defaults in every family port.
	// A project's overrides published under them would read as the rule's defaults.
	if _, _, _, err := configuredRegistry(*configPath, *noConfig, nil); err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	builtIn := rule.Defaults()
	definitions := builtIn.Definitions()
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

// ruleListDefinition adds precision guidance that only the rule catalogue JSON shows; embedding keeps the existing metadata unchanged.
//
// Severity is renamed here rather than on rule.Definition because that struct is also embedded in the analysis report's rule list.
// Retagging rule.Definition.Severity would also rename severity in the analysis report's rule metadata, a surface the family never ratified.
//
// The suppression is a same-named empty field, not json:"-", because a dash field is removed before encoding/json resolves name conflicts.
// Such a field never competes with the promoted one, so the inherited severity key would remain in catalogue JSON.
// A field at depth 0 carrying the same JSON name does win that contest, and left at its zero value omitempty then drops it.
type ruleListDefinition struct {
	rule.Definition
	Severity            finding.Severity          `json:"severity,omitempty"`
	DefaultSeverity     finding.Severity          `json:"defaultSeverity"`
	FalsePositiveShapes []rule.FalsePositiveShape `json:"falsePositiveShapes,omitempty"`
}

// ruleListDefinitions prepares registered rules for users inspecting catalogue JSON.
//
// The adapter prevents catalogue guidance from changing analysis-report schemas.
// definitions keep their given order; each entry copies the definition's Severity into DefaultSeverity and carries its FalsePositiveShapes.
// It returns a new slice of the same length, empty but non-nil when definitions is empty.
func ruleListDefinitions(definitions []rule.Definition) []ruleListDefinition {
	listedDefinitions := make([]ruleListDefinition, 0, len(definitions))
	// Preserve registry order so text and JSON catalogue users see the same sequence.
	for _, definition := range definitions {
		listedDefinitions = append(listedDefinitions, ruleListDefinition{
			Definition:          definition,
			DefaultSeverity:     definition.Severity,
			FalsePositiveShapes: definition.FalsePositiveShapes,
		})
	}
	return listedDefinitions
}
