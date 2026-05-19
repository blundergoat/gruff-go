// Package analysis runner ties source discovery, parsing, and rule execution together.
// It produces a deterministic Report consumed by the CLI and report renderers.
package analysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/blundergoat/gruff-go/internal/baseline"
	"github.com/blundergoat/gruff-go/internal/diff"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/rule"
	"github.com/blundergoat/gruff-go/internal/source"
)

// Options configures a single Analyze invocation.
type Options struct {
	// Context cancels the analysis pipeline; nil defaults to context.Background.
	Context context.Context
	// Root is the absolute or relative directory walked for source discovery; empty means current working directory.
	Root string
	// Paths limits discovery to these explicit roots under Root; empty means scan the whole project.
	Paths []string
	// Format selects the report renderer ("text", "json", "html", "sarif", "github"); empty defaults to "text".
	Format string
	// FailOn is the severity threshold that drives the process exit code.
	FailOn finding.Severity
	// Registry supplies the rules invoked against parsed units.
	Registry rule.Registry
	// IgnorePaths lists path patterns suppressed from discovery, merged on top of gitignore handling.
	IgnorePaths []string
	// IncludeIgnored disables gitignore and metadata directory pruning when true.
	IncludeIgnored bool
	// BaselinePath points at an optional baseline file used to suppress previously accepted findings.
	BaselinePath string
	// DiffBase enables changed-lines-only mode against this git revision when non-empty.
	DiffBase string
}

// Analyze runs discovery, parsing, and rules against the configured root.
func Analyze(opts Options) (Report, error) {
	root, err := analysisRoot(opts.Root)
	if err != nil {
		return Report{}, err
	}
	opts = normalizeOptions(opts)
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}

	discovery, err := source.Discover(source.Options{
		Context:        ctx,
		Root:           root,
		Paths:          opts.Paths,
		IgnorePatterns: opts.IgnorePaths,
		IncludeIgnored: opts.IncludeIgnored,
	})
	if err != nil {
		return Report{}, err
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}

	units, parseDiagnostics := parser.Parse(discovery.Files)
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	diagnostics := diagnosticsFromDiscovery(discovery.Missing)
	diagnostics = append(diagnostics, diagnosticsFromParser(parseDiagnostics)...)
	registry := opts.Registry
	findings := registry.Analyze(units, rule.Context{Root: root})
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	findings, baselineSummary, diagnostics := applyBaseline(root, findings, diagnostics, opts.BaselinePath)
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	findings, diffSummary, diagnostics := applyDiff(root, opts.Paths, findings, diagnostics, opts.DiffBase)

	displayRoot := filepath.ToSlash(root)
	return NewReport(ReportInput{
		Root:           displayRoot,
		Inputs:         inputsOrDefault(opts.Paths),
		Format:         opts.Format,
		FailOn:         opts.FailOn,
		IncludeIgnored: opts.IncludeIgnored,
		Scanned:        scannedPaths(discovery.Files),
		Skipped:        skippedPaths(discovery.Skipped),
		Missing:        discovery.Missing,
		Diagnostics:    diagnostics,
		Findings:       findings,
		Definitions:    registry.Definitions(),
		Baseline:       baselineSummary,
		Diff:           diffSummary,
	}), nil
}

// analysisRoot resolves the supplied root to an absolute directory path.
func analysisRoot(root string) (string, error) {
	if root == "" {
		return os.Getwd()
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(rootAbs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("analysis root is not a directory: %s", root)
	}
	return rootAbs, nil
}

// normalizeOptions fills defaults for empty Options fields.
func normalizeOptions(opts Options) Options {
	if opts.FailOn == "" {
		opts.FailOn = finding.SeverityMedium
	}
	if opts.Format == "" {
		opts.Format = "text"
	}
	return opts
}

// diagnosticsFromDiscovery converts missing paths into discovery diagnostics.
func diagnosticsFromDiscovery(paths []string) []Diagnostic {
	diagnostics := []Diagnostic{}
	for _, missing := range paths {
		diagnostics = append(diagnostics, Diagnostic{
			Stage:    "discovery",
			Message:  "path does not exist",
			File:     missing,
			Severity: finding.SeverityHigh,
		})
	}
	return diagnostics
}

// diagnosticsFromParser lifts each parser-stage diagnostic into the unified analysis Diagnostic shape, stamping every entry with stage "parse" and severity high so callers can surface broken syntax without a separate code path.
func diagnosticsFromParser(parseDiagnostics []parser.Diagnostic) []Diagnostic {
	diagnostics := []Diagnostic{}
	for _, item := range parseDiagnostics {
		diagnostics = append(diagnostics, Diagnostic{
			Stage:    "parse",
			Message:  item.Message,
			File:     item.File,
			Location: parserLocation(item),
			Severity: finding.SeverityHigh,
		})
	}
	return diagnostics
}

// applyBaseline suppresses findings that match the loaded baseline file.
func applyBaseline(root string, findings []finding.Finding, diagnostics []Diagnostic, baselinePath string) ([]finding.Finding, BaselineSummary, []Diagnostic) {
	baselineSummary := BaselineSummary{}
	if baselinePath == "" {
		return findings, baselineSummary, diagnostics
	}
	displayPath := filepath.ToSlash(baselinePath)
	loadPath := baselinePath
	if !filepath.IsAbs(loadPath) {
		loadPath = filepath.Join(root, loadPath)
	}
	baselineSummary.Applied = true
	baselineSummary.Path = displayPath
	file, err := baseline.Load(loadPath)
	if err != nil {
		diagnostics = append(diagnostics, Diagnostic{
			Stage:    "baseline",
			Message:  err.Error(),
			File:     displayPath,
			Severity: finding.SeverityHigh,
		})
		return findings, baselineSummary, diagnostics
	}
	result := baseline.Apply(findings, file)
	baselineSummary.Entries = result.Entries
	baselineSummary.SuppressedFindings = result.SuppressedFindings
	baselineSummary.StaleEntries = result.StaleEntries
	return result.Findings, baselineSummary, diagnostics
}

// applyDiff filters findings against git diff lines from the configured base.
func applyDiff(root string, paths []string, findings []finding.Finding, diagnostics []Diagnostic, diffBase string) ([]finding.Finding, DiffSummary, []Diagnostic) {
	diffSummary := DiffSummary{}
	if diffBase == "" {
		return findings, diffSummary, diagnostics
	}
	diffSummary.Enabled = true
	diffSummary.Base = diffBase
	changed, err := diff.FromGit(root, diffBase, paths)
	if err != nil {
		diagnostics = append(diagnostics, Diagnostic{
			Stage:    "diff",
			Message:  err.Error(),
			Severity: finding.SeverityHigh,
		})
		return findings, diffSummary, diagnostics
	}
	result := diff.Filter(findings, changed)
	diffSummary.ChangedFiles = changed.ChangedFiles
	diffSummary.FilteredFindings = result.FilteredFindings
	diffSummary.Caveat = "diff mode is changed-line scoped and is not full-project proof for project-level rules"
	return result.Findings, diffSummary, diagnostics
}

// scannedPaths extracts the relative paths from discovered source files.
func scannedPaths(files []source.File) []string {
	scanned := make([]string, 0, len(files))
	for _, file := range files {
		scanned = append(scanned, file.Path)
	}
	return scanned
}

// skippedPaths copies discovery skip entries into report-shaped values.
func skippedPaths(items []source.SkippedPath) []SkippedPath {
	skipped := make([]SkippedPath, 0, len(items))
	for _, item := range items {
		skipped = append(skipped, SkippedPath{Path: item.Path, Reason: item.Reason})
	}
	return skipped
}

// inputsOrDefault returns paths or a single "." when no inputs were provided.
func inputsOrDefault(paths []string) []string {
	inputs := paths
	if len(inputs) == 0 {
		inputs = []string{"."}
	}
	return inputs
}

// parserLocation builds a Location from a parser diagnostic when line info exists.
func parserLocation(item parser.Diagnostic) *finding.Location {
	if item.Line == 0 && item.Column == 0 {
		return nil
	}
	return &finding.Location{Line: item.Line, Column: item.Column}
}
