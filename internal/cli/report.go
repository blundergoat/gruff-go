// Package cli implements the gruff-go command-line interface.
//
// The report command runs analysis once and routes the result through the selected report writer.
// gruff-go report writes an html page by default, or json with --format json, to stdout or to the file --output names.
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

// runReport handles gruff-go report: it parses report flags, runs analysis once, and writes the selected report format.
//
// args holds the report flags and target paths, and interactive allows the first-run config prompt through configuredRegistryInteractive.
// stdout receives the report unless --output names a file, and stderr receives diagnostics and any config prompt.
//
// Returns the analysis summary exit code once the report is written, or 2 for any flag, config, analysis or report-writing failure.
func runReport(args []string, stdout, stderr io.Writer, interactive bool) int {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "html", "report format: html or json")
	output := flags.String("output", "", "write the report to this file (default: stdout)")
	editorLink := flags.String("report-editor-link", "none", "html report file:line link mode: none, vscode, or phpstorm")
	reportInteractive := flags.Bool("report-interactive", false, "enable interactive findings filter UI in html output")
	// The default comes from DefaultFailThresholdFor("report"), which is none: report generates an artifact and is not a CI gate.
	// failOn.report in .gruff-go.yaml overrides that default, and --fail-on wins over both (ADR-010).
	failOnFlag := string(finding.DefaultFailThresholdFor("report"))
	flags.StringVar(&failOnFlag, "min-severity", failOnFlag, "minimum severity that causes exit 1")
	flags.StringVar(&failOnFlag, "fail-on", failOnFlag, "alias for --min-severity")
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
	// --min-severity, the old exit-gate spelling, is refused with exit 2 so old scripts never silently get its new display-filter meaning.
	if refuseMinSeverity(flags, stderr) {
		return 2
	}
	if !validateReportEnums(*format, *editorLink, stderr) {
		return 2
	}
	failOnExplicit, ok := checkMinSeverityFlag(flags, failOnFlag, stderr)
	if !ok {
		return 2
	}
	registry, ignorePaths, cfg, err := configuredRegistryInteractive(*configPath, *noConfig, interactive, stderr, flags.Args())
	if err != nil {
		// A typo in --config, or a .gruff-go.yaml with invalid YAML, lands here and report exits 2 before scanning.
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	failOn, ok := resolveFailOn(failOnFlag, failOnExplicit, cfg, "report", stderr)
	if !ok {
		return 2
	}
	deepScanBudget, err := resolveDeepScanBudget(*deepScanBudgetRaw, cfg)
	// An empty --deep-scan-budget keeps the config or default bounds; a value that is neither LINES:BYTES nor off stops report with exit 2.
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	displayFilter, err := parseDisplayFilter(*includeRules, *excludeRules, *includePillars, *excludePillars, registry.Definitions())
	// A bad --include-rules, --exclude-rules, --include-pillars or --exclude-pillars value stops report here with exit 2, before any scan.
	if err != nil {
		fmt.Fprintf(stderr, "display filter: %v\n", err)
		return 2
	}
	analysisReport, ok := analyseFromTargets(analysis.Options{
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
	}, stderr)
	if !ok {
		return 2
	}
	analysis.ApplyDisplayFilter(&analysisReport, displayFilter)

	htmlOpts := report.HTMLOptions{EditorLink: *editorLink, Interactive: *reportInteractive}
	if err := emitReport(stdout, *output, analysisReport, *format, htmlOpts); err != nil {
		// An --output path in a missing directory, or one the user cannot write, fails here and report exits 2 after the scan.
		fmt.Fprintln(stderr, err)
		return 2
	}
	return analysisReport.Summary.ExitCode
}

// validateReportEnums checks the two closed vocabularies this command accepts, explaining any rejection on stderr.
//
// Rejecting an unsupported format here skips config loading, analysis and output-file creation for a report writeReport would refuse to write.
//
// format must be html or json, and editorLink must pass supportedEditorLink; stderr gets one message naming the first rejected value.
// Reports true when both values are accepted and false after the first rejection, with format checked before editorLink.
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
//
// path names the output file, or is empty to write to stdout; analysisReport is serialised as format, with htmlOpts applied to html output.
// Returns an error when the file cannot be created or writeReport fails; a created file is always closed before returning.
func emitReport(stdout io.Writer, path string, analysisReport analysis.Report, format string, htmlOpts report.HTMLOptions) error {
	writer, closer, err := openReportWriter(stdout, path)
	if err != nil {
		return err
	}
	defer closer()
	// If the write fails partway, the --output file keeps whatever was written before the failure and is not removed.
	return writeReport(writer, analysisReport, format, htmlOpts)
}

// openReportWriter selects stdout or a created file as the report writer.
//
// An empty path selects stdout with a no-op closer; any other path is created or truncated with os.Create.
// Returns the writer and a never-nil closer func, which closes a created file and drops its close error.
// The error is non-nil only when os.Create fails, and the writer is then nil with a no-op closer.
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
//
// format json writes analysisReport to writer with report.WriteJSON, and format html uses report.WriteHTML with htmlOpts.
// Returns an error when the selected report function fails or format is neither json nor html.
func writeReport(writer io.Writer, analysisReport analysis.Report, format string, htmlOpts report.HTMLOptions) error {
	switch format {
	case "json":
		return report.WriteJSON(writer, analysisReport)
	case "html":
		return report.WriteHTML(writer, analysisReport, htmlOpts)
	// Unreachable from runReport, which validates format first; kept so any other caller gets an error instead of an empty report.
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}
