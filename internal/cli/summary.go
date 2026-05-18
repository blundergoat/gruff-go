package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
)

func runSummary(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("summary", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	top := flags.Int("top", 10, "limit on top rules and top offenders shown")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	minSeverity := flags.String("min-severity", string(finding.SeverityMedium), "minimum severity that causes exit 1")
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
	analysisReport, err := analysis.Run(analysis.Options{
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
	switch *format {
	case "json":
		if err := report.WriteSummaryJSON(stdout, analysisReport); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	default:
		if err := report.WriteSummaryText(stdout, analysisReport, report.SummaryOptions{Top: *top}); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	return analysisReport.Summary.ExitCode
}
