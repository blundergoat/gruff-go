// Package cli implements the gruff-go command-line interface.
// The baseline command writes a baseline JSON file from a clean scan; the same
// helper is reused by `analyse --generate-baseline` so both entry points
// produce identical snapshots.
package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/baseline"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// runBaseline writes a baseline JSON file from a clean scan.
func runBaseline(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("baseline", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outPath := flags.String("out", "", "baseline output path")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *outPath == "" {
		fmt.Fprintln(stderr, "baseline requires --out")
		return 2
	}
	registry, ignorePaths, _, err := configuredRegistry(*configPath, *noConfig)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	return writeBaselineFromScan(baselineScanOptions{
		paths:          flags.Args(),
		outPath:        *outPath,
		registry:       registry,
		ignorePaths:    ignorePaths,
		includeIgnored: *includeIgnored,
	}, stdout, stderr)
}

// baselineScanOptions groups the inputs shared by the baseline command and the
// analyse-side baseline generator.
type baselineScanOptions struct {
	paths          []string
	outPath        string
	registry       rule.Registry
	ignorePaths    []string
	includeIgnored bool
}

// writeBaselineFromScan runs a full scan with no suppression or diff filtering,
// then writes a baseline file from the current findings. The generated baseline
// is a setup artifact, so current findings do not make this command fail.
func writeBaselineFromScan(opts baselineScanOptions, stdout, stderr io.Writer) int {
	analysisReport, err := analysis.Analyze(analysis.Options{
		Paths:          opts.paths,
		Format:         "json",
		FailOn:         finding.FailThresholdError,
		Registry:       opts.registry,
		IgnorePaths:    opts.ignorePaths,
		IncludeIgnored: opts.includeIgnored,
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
	if err := baseline.Write(opts.outPath, baseline.FromFindings(analysisReport.Findings)); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	fmt.Fprintf(stdout, "baseline: wrote %d findings to %s\n", len(analysisReport.Findings), opts.outPath)
	return 0
}
