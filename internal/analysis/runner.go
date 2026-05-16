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

type Options struct {
	Context        context.Context
	Root           string
	Paths          []string
	Format         string
	FailOn         finding.Severity
	Registry       rule.Registry
	IgnorePaths    []string
	IncludeIgnored bool
	BaselinePath   string
	DiffBase       string
}

func Run(options Options) (Report, error) {
	root, err := analysisRoot(options.Root)
	if err != nil {
		return Report{}, err
	}
	options = normalizeOptions(options)
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}

	discovery, err := source.Discover(source.Options{
		Context:        ctx,
		Root:           root,
		Paths:          options.Paths,
		IgnorePatterns: options.IgnorePaths,
		IncludeIgnored: options.IncludeIgnored,
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
	registry := options.Registry
	findings := registry.Analyze(units, rule.Context{Root: root})
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	findings, baselineSummary, diagnostics := applyBaseline(root, findings, diagnostics, options.BaselinePath)
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	findings, diffSummary, diagnostics := applyDiff(root, options.Paths, findings, diagnostics, options.DiffBase)

	displayRoot := filepath.ToSlash(root)
	return NewReport(ReportInput{
		Root:           displayRoot,
		Inputs:         inputsOrDefault(options.Paths),
		Format:         options.Format,
		FailOn:         options.FailOn,
		IncludeIgnored: options.IncludeIgnored,
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

func normalizeOptions(options Options) Options {
	if options.FailOn == "" {
		options.FailOn = finding.SeverityMedium
	}
	if options.Format == "" {
		options.Format = "text"
	}
	return options
}

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

func scannedPaths(files []source.File) []string {
	scanned := make([]string, 0, len(files))
	for _, file := range files {
		scanned = append(scanned, file.Path)
	}
	return scanned
}

func skippedPaths(items []source.SkippedPath) []SkippedPath {
	skipped := make([]SkippedPath, 0, len(items))
	for _, item := range items {
		skipped = append(skipped, SkippedPath{Path: item.Path, Reason: item.Reason})
	}
	return skipped
}

func inputsOrDefault(paths []string) []string {
	inputs := paths
	if len(inputs) == 0 {
		inputs = []string{"."}
	}
	return inputs
}

func parserLocation(item parser.Diagnostic) *finding.Location {
	if item.Line == 0 && item.Column == 0 {
		return nil
	}
	return &finding.Location{Line: item.Line, Column: item.Column}
}
