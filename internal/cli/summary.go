// Package cli implements the gruff-go command-line interface.
//
// This file runs gruff-go summary, which reduces one scan to a compact digest, written as text or as summary JSON per --format.
// The command times the run from config loading through analysis, so the text digest's scan time line shows real wall time.
package cli

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
)

// runSummary handles gruff-go summary: it parses the summary flags, runs analysis, and prints the compact digest.
//
// args holds the summary flags and target paths; the paths left after flag parsing go to config loading and analysis.
// With no paths, as in a bare gruff-go summary, the current working directory is scanned.
//
// stdout receives the digest, as text or as summary JSON per --format, and stderr receives flag, validation, config and write errors.
// interactive tells configuredRegistryInteractive whether the session is interactive while it loads the config and rule registry.
//
// It returns the process exit code: 2 when a flag is invalid or config loading, deep-scan budget parsing, analysis or writing the digest fails.
// Otherwise it returns the analysis summary's ExitCode, which the analysis derives from the resolved fail-on threshold; 0 means the gate passed.
func runSummary(args []string, stdout, stderr io.Writer, interactive bool) int {
	flags := flag.NewFlagSet("summary", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	top := flags.Int("top", 10, "limit on top rules and top offenders shown")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	deepScanBudgetRaw := flags.String("deep-scan-budget", "", "override both deep-scan bounds as LINES:BYTES, or disable with off")
	// Default comes from DefaultFailThresholdFor("summary"); precedence below
	// lets failOn.summary in .gruff-go.yaml override it.
	failOnSeverity := string(finding.DefaultFailThresholdFor("summary"))
	flags.StringVar(&failOnSeverity, "min-severity", failOnSeverity, "minimum severity that causes exit 1")
	flags.StringVar(&failOnSeverity, "fail-on", failOnSeverity, "alias for --min-severity")
	// An unknown flag such as --formt, or a non-integer --top such as --top nope, stops the run here with exit 2.
	if err := parseCommandArguments(flags, args); err != nil {
		return 2
	}
	// Passing --min-severity is refused with exit 2 rather than silently ignored, because the flag's meaning inverted; --fail-on selects the gate.
	if refuseMinSeverity(flags, stderr) {
		return 2
	}
	// Summary has no HTML form: --format html or yaml exits 2 here, and an HTML report comes from gruff-go report --format html.
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "unsupported format %q (want text or json)\n", *format)
		return 2
	}
	if *top < 0 {
		fmt.Fprintln(stderr, "--top must be zero or a positive integer")
		return 2
	}
	failOnExplicit, ok := checkMinSeverityFlag(flags, failOnSeverity, stderr)
	if !ok {
		return 2
	}
	started := time.Now()
	registry, ignorePaths, cfg, err := configuredRegistryInteractive(*configPath, *noConfig, interactive, stderr, flags.Args())
	// A typo in --config, or a .gruff-go.yaml the loader rejects, lands here; stderr shows the reason after config: and the run exits 2.
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	failOn, ok := resolveFailOn(failOnSeverity, failOnExplicit, cfg, "summary", stderr)
	if !ok {
		return 2
	}
	deepScanBudget, err := resolveDeepScanBudget(*deepScanBudgetRaw, cfg)
	// An empty --deep-scan-budget keeps the config or default bounds; any other value must be LINES:BYTES or off, or the run exits 2 here.
	if err != nil {
		fmt.Fprintln(stderr, err)
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
	}, stderr)
	// A fatal analysis error exits 2 here before any digest reaches stdout.
	if !ok {
		return 2
	}
	scanDuration := time.Since(started)
	switch *format {
	case "json":
		if err := report.WriteSummaryV01JSON(stdout, analysisReport); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	default:
		if err := report.WriteSummaryText(stdout, analysisReport, report.SummaryOptions{
			Top:          *top,
			ScanDuration: scanDuration,
		}); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	return analysisReport.Summary.ExitCode
}
