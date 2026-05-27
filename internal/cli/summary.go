// Package cli implements the gruff-go command-line interface.
// The summary command keeps scan timing near the analysis call so digests can show real wall time.
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

// runSummary parses summary flags, runs analysis, and prints the compact digest.
func runSummary(args []string, stdout, stderr io.Writer, interactive bool) int {
	flags := flag.NewFlagSet("summary", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	top := flags.Int("top", 10, "limit on top rules and top offenders shown")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	// Default comes from DefaultFailThresholdFor("summary"); precedence below
	// lets minimumSeverity.summary in .gruff-go.yaml override it (ADR-010).
	minSeverity := string(finding.DefaultFailThresholdFor("summary"))
	flags.StringVar(&minSeverity, "min-severity", minSeverity, "minimum severity that causes exit 1")
	flags.StringVar(&minSeverity, "fail-on", minSeverity, "alias for --min-severity")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "unsupported format %q (want text or json)\n", *format)
		return 2
	}
	if *top < 0 {
		fmt.Fprintln(stderr, "--top must be zero or a positive integer")
		return 2
	}
	minSeverityExplicit, ok := checkMinSeverityFlag(flags, minSeverity, stderr)
	if !ok {
		return 2
	}
	started := time.Now()
	registry, ignorePaths, cfg, err := configuredRegistryInteractive(*configPath, *noConfig, interactive, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	failOn, ok := resolveFailOn(minSeverity, minSeverityExplicit, cfg, "summary", stderr)
	if !ok {
		return 2
	}
	analysisReport, err := analysis.Analyze(analysis.Options{
		Paths:          flags.Args(),
		Format:         *format,
		FailOn:         failOn,
		Registry:       registry,
		IgnorePaths:    ignorePaths,
		IncludeIgnored: *includeIgnored,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
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
