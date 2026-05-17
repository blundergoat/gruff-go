// Package cli implements the gruff-go command-line interface.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/baseline"
	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
	"github.com/blundergoat/gruff-go/internal/rule"
)

const toolVersion = "0.1.0-dev"

func Main(args []string, stdout, stderr io.Writer) int {
	args, ansiPref := extractAnsiFlags(args)
	args, quiet := extractQuiet(args)
	if quiet {
		stdout = io.Discard
	}
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
		return runAnalyse(args[1:], stdout, stderr)
	case "baseline":
		return runBaseline(args[1:], stdout, stderr)
	case "list-rules":
		return runListRules(args[1:], stdout, stderr)
	case "summary":
		return runSummary(args[1:], stdout, stderr)
	case "report":
		return runReport(args[1:], stdout, stderr)
	case "dashboard":
		return runDashboard(args[1:], stdout, stderr)
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
		case "-q", "--quiet":
			quiet = true
		default:
			out = append(out, arg)
		}
	}
	return out, quiet
}

func isVersionFlag(arg string) bool {
	return arg == "-V" || arg == "--version"
}

func runAnalyse(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("analyse", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text, json, summary-json, sarif, github, or html")
	minSeverity := flags.String("min-severity", string(finding.SeverityMedium), "minimum severity that causes exit 1")
	configPath := flags.String("config", "", "gruff config file (.gruff.yaml, .gruff.yml, or .gruff.json)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	baselinePath := flags.String("baseline", "", "baseline file to apply")
	diffBase := flags.String("diff-base", "", "git base ref for changed-line filtering")
	includeRules := flags.String("include-rules", "", "comma-separated rule IDs to display")
	excludeRules := flags.String("exclude-rules", "", "comma-separated rule IDs to hide from display")
	includePillars := flags.String("include-pillars", "", "comma-separated pillars to display")
	excludePillars := flags.String("exclude-pillars", "", "comma-separated pillars to hide from display")
	editorLink := flags.String("report-editor-link", "none", "html report file:line link mode: none, vscode, or phpstorm")
	reportInteractive := flags.Bool("report-interactive", false, "enable interactive findings filter UI in html output")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if !supportedAnalysisFormat(*format) {
		fmt.Fprintf(stderr, "unsupported format %q\n", *format)
		return 2
	}
	if !supportedEditorLink(*editorLink) {
		fmt.Fprintf(stderr, "unsupported --report-editor-link %q (want none, vscode, or phpstorm)\n", *editorLink)
		return 2
	}
	failOn, err := finding.ParseSeverity(*minSeverity)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	registry, ignorePaths, err := configuredRegistry(*configPath, *noConfig)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	displayFilter, err := parseDisplayFilter(*includeRules, *excludeRules, *includePillars, *excludePillars, registry.Definitions())
	if err != nil {
		fmt.Fprintf(stderr, "display filter: %v\n", err)
		return 2
	}
	analysisReport, err := analysis.Run(analysis.Options{
		Paths:          flags.Args(),
		Format:         *format,
		FailOn:         failOn,
		Registry:       registry,
		IgnorePaths:    ignorePaths,
		IncludeIgnored: *includeIgnored,
		BaselinePath:   *baselinePath,
		DiffBase:       *diffBase,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	analysis.ApplyDisplayFilter(&analysisReport, displayFilter)
	if err := writeAnalysisReport(stdout, *format, analysisReport, report.HTMLOptions{EditorLink: *editorLink, Interactive: *reportInteractive}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return analysisReport.Summary.ExitCode
}

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

func runBaseline(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("baseline", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outPath := flags.String("out", "", "baseline output path")
	configPath := flags.String("config", "", "gruff config file (.gruff.yaml, .gruff.yml, or .gruff.json)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *outPath == "" {
		fmt.Fprintln(stderr, "baseline requires --out")
		return 2
	}
	registry, ignorePaths, err := configuredRegistry(*configPath, *noConfig)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	analysisReport, err := analysis.Run(analysis.Options{
		Paths:          flags.Args(),
		Format:         "json",
		FailOn:         finding.SeverityCritical,
		Registry:       registry,
		IgnorePaths:    ignorePaths,
		IncludeIgnored: *includeIgnored,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if len(analysisReport.Diagnostics) > 0 {
		if err := report.WriteText(stderr, analysisReport); err != nil {
			fmt.Fprintln(stderr, err)
		}
		return 2
	}
	if err := baseline.Write(*outPath, baseline.FromFindings(analysisReport.Findings)); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	fmt.Fprintf(stdout, "baseline: wrote %d findings to %s\n", len(analysisReport.Findings), *outPath)
	return 0
}

func runListRules(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("list-rules", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	configPath := flags.String("config", "", "gruff config file (.gruff.yaml, .gruff.yml, or .gruff.json)")
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

func supportedAnalysisFormat(format string) bool {
	switch format {
	case "text", "json", "summary-json", "sarif", "github", "html":
		return true
	default:
		return false
	}
}

func supportedEditorLink(value string) bool {
	switch value {
	case "none", "vscode", "phpstorm":
		return true
	default:
		return false
	}
}

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
