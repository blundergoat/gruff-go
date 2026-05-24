// Package cli implements the gruff-go command-line interface.
// It wires command-line flags and dispatches subcommands to the analysis pipeline.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// toolVersion is the released gruff-go semantic version printed by --version.
const toolVersion = "0.1.1"

// Main is the CLI entrypoint that parses args and dispatches subcommands.
func Main(args []string, stdout, stderr io.Writer) int {
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

	switch args[0] {
	case "analyse", "analyze":
		return runAnalyse(args[1:], stdout, stderr, interactive)
	case "baseline":
		return runBaseline(args[1:], stdout, stderr)
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "completion":
		return runCompletion(args[1:], stdout, stderr)
	case "list-rules":
		return runListRules(args[1:], stdout, stderr)
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

// extractQuiet removes -q / --quiet from args and returns the result plus a
// boolean indicating whether quiet mode was requested. The flag can appear at
// any position.
func extractQuiet(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	quiet := false
	for _, arg := range args {
		switch arg {
		case "-q", "--quiet", "--silent":
			quiet = true
		default:
			out = append(out, arg)
		}
	}
	return out, quiet
}

// extractVerbose accepts common Symfony-style verbosity flags. gruff-go does
// not currently vary output by verbosity, but accepting these flags keeps the
// global surface consistent across gruff implementations.
func extractVerbose(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		switch arg {
		case "-v", "-vv", "-vvv", "--verbose":
			continue
		default:
			out = append(out, arg)
		}
	}
	return out
}

// isVersionFlag reports whether the argument requests version output.
func isVersionFlag(arg string) bool {
	return arg == "-V" || arg == "--version"
}

// runAnalyse executes the analyse subcommand and renders the scan report.
func runAnalyse(args []string, stdout, stderr io.Writer, interactive bool) int {
	flags, values, ok := parseAnalyseFlags(args, stderr)
	if !ok {
		return 2
	}
	registry, ignorePaths, err := configuredRegistryInteractive(values.configPath, values.noConfig, interactive, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
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
		Paths:          flags.Args(),
		Format:         values.format,
		FailOn:         values.failOn,
		Registry:       registry,
		IgnorePaths:    ignorePaths,
		IncludeIgnored: values.includeIgnored,
		BaselinePath:   values.baselinePath,
		DiffBase:       values.diffBase,
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

// analyseFlagValues is the parsed analyse command state after validation.
type analyseFlagValues struct {
	format               string
	failOn               finding.Severity
	configPath           string
	noConfig             bool
	baselinePath         string
	generateBaselinePath string
	diffBase             string
	includeRules         string
	excludeRules         string
	includePillars       string
	excludePillars       string
	editorLink           string
	reportInteractive    bool
	includeIgnored       bool
}

// parseAnalyseFlags parses and validates analyse flags, printing validation
// errors to stderr in the same style as the legacy inline parser.
func parseAnalyseFlags(args []string, stderr io.Writer) (*flag.FlagSet, analyseFlagValues, bool) {
	flags := flag.NewFlagSet("analyse", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text, json, summary-json, sarif, github, or html")
	minSeverity := string(finding.SeverityMedium)
	flags.StringVar(&minSeverity, "min-severity", minSeverity, "minimum severity that causes exit 1")
	flags.StringVar(&minSeverity, "fail-on", minSeverity, "alias for --min-severity")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	baselinePath := flags.String("baseline", "", "baseline file to apply")
	generateBaselinePath := flags.String("generate-baseline", "", "write current findings to a baseline file and exit cleanly")
	diffBase := flags.String("diff-base", "", "git base ref for changed-line filtering")
	includeRules := flags.String("include-rules", "", "comma-separated rule IDs to display")
	excludeRules := flags.String("exclude-rules", "", "comma-separated rule IDs to hide from display")
	includePillars := flags.String("include-pillars", "", "comma-separated pillars to display")
	excludePillars := flags.String("exclude-pillars", "", "comma-separated pillars to hide from display")
	editorLink := flags.String("report-editor-link", "none", "html report file:line link mode: none, vscode, or phpstorm")
	reportInteractive := flags.Bool("report-interactive", false, "enable interactive findings filter UI in html output")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	if err := flags.Parse(args); err != nil {
		return flags, analyseFlagValues{}, false
	}
	if !supportedAnalysisFormat(*format) {
		fmt.Fprintf(stderr, "unsupported format %q\n", *format)
		return flags, analyseFlagValues{}, false
	}
	if !supportedEditorLink(*editorLink) {
		fmt.Fprintf(stderr, "unsupported --report-editor-link %q (want none, vscode, or phpstorm)\n", *editorLink)
		return flags, analyseFlagValues{}, false
	}
	failOn, err := finding.ParseSeverity(minSeverity)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return flags, analyseFlagValues{}, false
	}
	values := analyseFlagValues{
		format:               *format,
		failOn:               failOn,
		configPath:           *configPath,
		noConfig:             *noConfig,
		baselinePath:         *baselinePath,
		generateBaselinePath: *generateBaselinePath,
		diffBase:             *diffBase,
		includeRules:         *includeRules,
		excludeRules:         *excludeRules,
		includePillars:       *includePillars,
		excludePillars:       *excludePillars,
		editorLink:           *editorLink,
		reportInteractive:    *reportInteractive,
		includeIgnored:       *includeIgnored,
	}
	if values.generateBaselinePath != "" {
		if err := validateGenerateBaselineFlags(generateBaselineFlagState{
			baselinePath:   values.baselinePath,
			diffBase:       values.diffBase,
			includeRules:   values.includeRules,
			excludeRules:   values.excludeRules,
			includePillars: values.includePillars,
			excludePillars: values.excludePillars,
		}); err != nil {
			fmt.Fprintln(stderr, err)
			return flags, analyseFlagValues{}, false
		}
	}
	return flags, values, true
}

// generateBaselineFlagState groups analyse flags that change finding scope.
type generateBaselineFlagState struct {
	baselinePath   string
	diffBase       string
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
	case state.includeRules != "" || state.excludeRules != "" || state.includePillars != "" || state.excludePillars != "":
		return fmt.Errorf("--generate-baseline cannot be combined with display filters")
	default:
		return nil
	}
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
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "unsupported format %q\n", *format)
		return 2
	}
	registry, _, err := configuredRegistry(*configPath, *noConfig)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	definitions := registry.Definitions()
	if *format == "json" {
		payload := struct {
			SchemaVersion string            `json:"schemaVersion"`
			Rules         []rule.Definition `json:"rules"`
		}{
			SchemaVersion: analysis.SchemaVersion,
			Rules:         definitions,
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

// configuredRegistry builds the rule registry honouring the loaded config file.
func configuredRegistry(configPath string, noConfig bool) (rule.Registry, []string, error) {
	defaults := rule.Defaults()
	root, err := os.Getwd()
	if err != nil {
		return rule.Registry{}, nil, err
	}
	loaded, err := cfgpkg.LoadAuto(root, configPath, noConfig, defaults.Definitions())
	if err != nil {
		return rule.Registry{}, nil, err
	}
	if loaded.Path == "" {
		return defaults, nil, nil
	}
	cfg := loaded.Config
	registry, err := rule.DefaultsConfigured(cfg.RuleOptions())
	if err != nil {
		return rule.Registry{}, nil, err
	}
	return registry, cfg.IgnorePaths, nil
}

// supportedAnalysisFormat reports whether format names a known analyse output.
func supportedAnalysisFormat(format string) bool {
	switch format {
	case "text", "json", "summary-json", "sarif", "github", "html":
		return true
	default:
		return false
	}
}

// supportedEditorLink reports whether value names a supported editor-link mode.
func supportedEditorLink(value string) bool {
	switch value {
	case "none", "vscode", "phpstorm":
		return true
	default:
		return false
	}
}

// parseDisplayFilter validates the rule and pillar filter flags into a DisplayFilter.
func parseDisplayFilter(includeRules, excludeRules, includePillars, excludePillars string, definitions []rule.Definition) (analysis.DisplayFilter, error) {
	ruleIDs := map[string]struct{}{}
	for _, definition := range definitions {
		ruleIDs[definition.ID] = struct{}{}
	}
	filter := analysis.DisplayFilter{
		IncludeRules: splitCSV(includeRules),
		ExcludeRules: splitCSV(excludeRules),
	}
	for _, id := range append(append([]string{}, filter.IncludeRules...), filter.ExcludeRules...) {
		if _, ok := ruleIDs[id]; !ok {
			return analysis.DisplayFilter{}, fmt.Errorf("unknown rule %q", id)
		}
	}
	var err error
	filter.IncludePillars, err = parsePillars(includePillars)
	if err != nil {
		return analysis.DisplayFilter{}, err
	}
	filter.ExcludePillars, err = parsePillars(excludePillars)
	if err != nil {
		return analysis.DisplayFilter{}, err
	}
	return filter, nil
}

// parsePillars converts a comma-separated pillar list into validated Pillar values.
func parsePillars(input string) ([]finding.Pillar, error) {
	values := splitCSV(input)
	out := make([]finding.Pillar, 0, len(values))
	for _, value := range values {
		pillar := finding.Pillar(value)
		if !pillar.Valid() {
			return nil, fmt.Errorf("unknown pillar %q", value)
		}
		out = append(out, pillar)
	}
	return out, nil
}

// splitCSV splits a comma-separated input string and trims surrounding whitespace.
func splitCSV(input string) []string {
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
