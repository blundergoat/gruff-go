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
	// report is an artifact generator, not a CI gate. failOn.report in
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
	deepScanBudgetRaw := flags.String("deep-scan-budget", "", "override both deep-scan bounds as LINES:BYTES, or disable with off")
	if err := parseCommandArguments(flags, args); err != nil {
		return 2
	}
	// --min-severity inverts rather than disappears here too: this command gates on it exactly as analyse did.
	if refuseMinSeverity(flags, stderr) {
		return 2
	}
	if !validateReportEnums(*format, *editorLink, stderr) {
		return 2
	}
	minSeverityExplicit, ok := checkMinSeverityFlag(flags, minSeverity, stderr)
	if !ok {
		return 2
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
	deepScanBudget, err := resolveDeepScanBudget(*deepScanBudgetRaw, cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	displayFilter, err := parseDisplayFilter(*includeRules, *excludeRules, *includePillars, *excludePillars, registry.Definitions())
	if err != nil {
		fmt.Fprintf(stderr, "display filter: %v\n", err)
		return 2
	}
	analysisReport, err := analysis.Analyze(analysis.Options{
		Paths:               flags.Args(),
		Format:              *format,
		FailOn:              failOn,
		Registry:            registry,
		IgnorePaths:         ignorePaths,
		SensitiveExclusions: sensitiveExclusionsFor(cfg),
		DeepScanBudget:      deepScanBudget,
		IncludeIgnored:      *includeIgnored,
		BaselinePath:        *baselinePath,
		DiffBase:            *diffBase,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	analysis.ApplyDisplayFilter(&analysisReport, displayFilter)

	htmlOpts := report.HTMLOptions{EditorLink: *editorLink, Interactive: *reportInteractive}
	if err := emitReport(stdout, *output, analysisReport, *format, htmlOpts); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return analysisReport.Summary.ExitCode
}

// validateReportEnums checks the two closed vocabularies this command accepts, explaining any rejection on stderr.
//
// A mistyped format would otherwise fall through to a default and hand the user a file in the wrong shape.
func validateReportEnums(format, editorLink string, stderr io.Writer) bool {
	if format != "html" && format != "json" {
		fmt.Fprintf(stderr, "unsupported format %q (want html or json)\n", format)
		return false
	}

	if !supportedEditorLink(editorLink) {
		fmt.Fprintf(stderr, "unsupported --report-editor-link %q (want none, vscode, or phpstorm)\n", editorLink)
		return false
	}

	return true
}

// emitReport opens the requested destination and writes one complete report.
func emitReport(stdout io.Writer, path string, analysisReport analysis.Report, format string, htmlOpts report.HTMLOptions) error {
	writer, closer, err := openReportWriter(stdout, path)
	if err != nil {
		return err
	}
	defer closer()
	return writeReport(writer, analysisReport, format, htmlOpts)
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
