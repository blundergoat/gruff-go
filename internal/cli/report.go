// Package cli implements the gruff-go command-line interface.
// The report command runs analysis once and routes the result through the selected report writer.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
)

// runReport parses report flags, runs analysis, and writes the selected report format.
func runReport(args []string, stdout, stderr io.Writer, interactive bool) int {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "html", "report format: html or json")
	output := flags.String("output", "", "write the report to this file (default: stdout)")
	editorLink := flags.String("report-editor-link", "none", "html report file:line link mode: none, vscode, or phpstorm")
	reportInteractive := flags.Bool("report-interactive", false, "enable interactive findings filter UI in html output")
	// Default comes from DefaultFailThresholdFor("report") which is `none` -
	// report is an artifact generator, not a CI gate. minimumSeverity.report in
	// .gruff-go.yaml overrides; CLI flag wins over both (ADR-010).
	minSeverity := string(finding.DefaultFailThresholdFor("report"))
	flags.StringVar(&minSeverity, "min-severity", minSeverity, "minimum severity that causes exit 1")
	flags.StringVar(&minSeverity, "fail-on", minSeverity, "alias for --min-severity")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	baselinePath := flags.String("baseline", "", "baseline file to apply")
	diffBase := flags.String("diff-base", "", "git base ref for changed-line filtering")
	includeRules := flags.String("include-rules", "", "comma-separated rule IDs to display")
	excludeRules := flags.String("exclude-rules", "", "comma-separated rule IDs to hide from display")
	includePillars := flags.String("include-pillars", "", "comma-separated pillars to display")
	excludePillars := flags.String("exclude-pillars", "", "comma-separated pillars to hide from display")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *format != "html" && *format != "json" {
		fmt.Fprintf(stderr, "unsupported format %q (want html or json)\n", *format)
		return 2
	}
	if !supportedEditorLink(*editorLink) {
		fmt.Fprintf(stderr, "unsupported --report-editor-link %q (want none, vscode, or phpstorm)\n", *editorLink)
		return 2
	}
	minSeverityExplicit := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "min-severity" || f.Name == "fail-on" {
			minSeverityExplicit = true
		}
	})
	if minSeverityExplicit {
		if _, err := finding.ParseFailThreshold(minSeverity); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	registry, ignorePaths, cfg, err := configuredRegistryInteractive(*configPath, *noConfig, interactive, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	failOn, ok := resolveFailOn(minSeverity, minSeverityExplicit, cfg, "report", stderr)
	if !ok {
		return 2
	}
	displayFilter, err := parseDisplayFilter(*includeRules, *excludeRules, *includePillars, *excludePillars, registry.Definitions())
	if err != nil {
		fmt.Fprintf(stderr, "display filter: %v\n", err)
		return 2
	}
	analysisReport, err := analysis.Analyze(analysis.Options{
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

	writer, closer, err := openReportWriter(stdout, *output)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer closer()

	htmlOpts := report.HTMLOptions{EditorLink: *editorLink, Interactive: *reportInteractive}
	if err := writeReport(writer, analysisReport, *format, htmlOpts); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return analysisReport.Summary.ExitCode
}

// openReportWriter selects stdout or a created file as the report writer.
func openReportWriter(stdout io.Writer, path string) (io.Writer, func(), error) {
	if path == "" {
		return stdout, func() {}, nil
	}
	// #nosec G304 -- CLI intentionally writes to a user-supplied path.
	file, err := os.Create(path)
	if err != nil {
		return nil, func() {}, err
	}
	return file, func() { _ = file.Close() }, nil
}

// writeReport serialises the analysis report in the requested format.
func writeReport(writer io.Writer, analysisReport analysis.Report, format string, htmlOpts report.HTMLOptions) error {
	switch format {
	case "json":
		return report.WriteJSON(writer, analysisReport)
	case "html":
		return report.WriteHTML(writer, analysisReport, htmlOpts)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}
