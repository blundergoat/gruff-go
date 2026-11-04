// Package cli implements the gruff-go command-line interface.
//
// The baseline command writes a baseline JSON file from a full scan with no baseline or diff filtering.
// The same helper backs analyse --generate-baseline, so both entry points run the same scan and write path.
// With --migrate-baseline it instead carries a 0.5 baseline's reviewed findings into a new file and leaves the original untouched.
package cli

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/baseline"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// runBaseline handles gruff-go baseline: it parses flags, loads config, and writes --out from a scan without baseline or diff filtering.
//
// With --migrate-baseline, or its superseded spelling --migrate, it carries a 0.5 baseline's reviewed findings into --out instead.
//
// args holds the baseline flags and the paths to scan; stdout gets the success summary, and stderr gets usage text, warnings and errors.
// It returns the command's exit code: 2 when parsing fails, --out is missing, or the config or deep-scan budget cannot be resolved.
// Otherwise it passes on writeBaselineFromScan's code, 0 when the baseline is written and 2 when the scan or write fails.
func runBaseline(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("baseline", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outPath := flags.String("out", "", "baseline output path")
	migrateBaselinePath := flags.String("migrate-baseline", "", "0.5 baseline to migrate; its reviewed findings are re-identified from the current scan and written to --out, and the original is left untouched")
	migratePath := flags.String("migrate", "", "superseded spelling of --migrate-baseline; identical behaviour")
	configPath := flags.String("config", "", "gruff config file (.gruff-go.yaml)")
	force := flags.Bool("force", false, "overwrite a 0.5 baseline at the default path; without it a generate that would destroy the retreat path is refused")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	deepScanBudgetRaw := flags.String("deep-scan-budget", "", "override both deep-scan bounds as LINES:BYTES, or disable with off")
	// A mistyped flag, such as --output for --out, lands here and gruff-go baseline exits 2.
	if err := parseCommandArguments(flags, args); err != nil {
		return 2
	}
	warnSupersededSpellings(flags, stderr)
	// Running gruff-go baseline without --out lands here; there is no default path, so nothing is scanned or written.
	if *outPath == "" {
		fmt.Fprintln(stderr, "baseline requires --out")
		return 2
	}
	registry, ignorePaths, cfg, err := configuredRegistry(*configPath, *noConfig, flags.Args())
	// With config loading on, a mistyped --config path or a config file gruff-go rejects lands here, and the command exits 2 before scanning.
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		return 2
	}
	deepScanBudget, err := resolveDeepScanBudget(*deepScanBudgetRaw, cfg)
	// A non-empty --deep-scan-budget value that is neither LINES:BYTES nor off lands here, and the command exits 2 before scanning.
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// When both spellings carry a non-empty value, --migrate-baseline wins over --migrate.
	return writeBaselineFromScan(baselineScanOptions{
		paths:               flags.Args(),
		outPath:             *outPath,
		migratePath:         firstNonEmpty(*migrateBaselinePath, *migratePath),
		force:               *force,
		registry:            registry,
		ignorePaths:         ignorePaths,
		includeIgnored:      *includeIgnored,
		sensitiveExclusions: sensitiveExclusionsFor(cfg),
		deepScanBudget:      deepScanBudget,
	}, stdout, stderr)
}

// baselineScanOptions groups the inputs shared by the baseline command and the analyse-side baseline generator.
//
// Both entry points hand writeBaselineFromScan this one struct, so a baseline from either one is built by the same scan and write path.
// For gruff-go baseline, paths and outPath come from the command line and the rest from flags and the loaded config.
type baselineScanOptions struct {
	paths   []string
	outPath string
	// migratePath names a 0.5 baseline whose reviewed findings are carried into
	// the v3 file at outPath; empty means generate from the scan alone.
	migratePath string
	// force overwrites a 0.5 baseline at the default path instead of refusing.
	force               bool
	registry            rule.Registry
	ignorePaths         []string
	includeIgnored      bool
	sensitiveExclusions []analysis.SensitiveExclusion
	deepScanBudget      analysis.DeepScanBudget
}

// writeBaselineFromScan runs a full scan with no baseline or diff filtering, then writes a baseline file from the current findings.
//
// The generated baseline is a setup artifact, so current findings do not make this command fail.
//
// opts supplies the scan inputs, outPath, force and an optional migratePath; its sensitive exclusions still keep matching findings out.
// stdout gets the one-line written or migrated summary; stderr gets the text report of a scan that exits 2, plus migration and write errors.
// It returns 0 once the baseline is written or migrated, and 2 when the scan fails, the default-path guard refuses, or migration or writing fails.
func writeBaselineFromScan(opts baselineScanOptions, stdout, stderr io.Writer) int {
	analysisReport, ok := analyseFromTargets(analysis.Options{
		Paths:               opts.paths,
		Format:              "json",
		FailOn:              finding.FailThresholdError,
		Registry:            opts.registry,
		IgnorePaths:         opts.ignorePaths,
		SensitiveExclusions: opts.sensitiveExclusions,
		DeepScanBudget:      opts.deepScanBudget,
		IncludeIgnored:      opts.includeIgnored,
	}, stderr)
	if !ok {
		return 2
	}
	// A scan that itself exits 2 writes no baseline; the user sees its text report on stderr and the command exits 2.
	if analysisReport.Summary.ExitCode == 2 {
		if err := report.WriteText(stderr, analysisReport); err != nil {
			fmt.Fprintln(stderr, err)
		}
		return 2
	}
	// A migration re-identifies the findings the 0.5 rows covered from this scan and writes them to --out; the original stays byte-identical.
	if opts.migratePath != "" {
		result, err := baseline.Migrate(opts.migratePath, opts.outPath, analysisReport.Findings, time.Now().UTC())
		// A --migrate-baseline path that does not exist lands here, and the command exits 2 with the error on stderr.
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		fmt.Fprintf(stdout, "baseline: migrated %d reviewed findings from %s into %d entries at %s; %d sensitive findings counted, not baselined; original preserved\n",
			result.Accepted, opts.migratePath, result.Occurrences, opts.outPath, result.Sensitive)
		return 0
	}
	// A generate at the shared default path never destroys a 0.5 baseline by accident; --force is the way to mean it.
	if err := baseline.RequireOverwritableDefaultPath(opts.outPath, opts.force); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	baselineFile, err := baseline.FromFindings(analysisReport.Findings)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// An --out path the user cannot write, such as one in a read-only directory, lands here and the command exits 2.
	if err := baseline.Write(opts.outPath, baselineFile); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	fmt.Fprintf(stdout, "baseline: wrote %d findings to %s\n", len(analysisReport.Findings), opts.outPath)
	return 0
}
