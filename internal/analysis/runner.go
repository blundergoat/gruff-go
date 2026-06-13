// Package analysis runner ties source discovery, parsing, and rule execution together.
// It produces a deterministic Report consumed by the CLI and report renderers.
package analysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	// FailOn is the threshold at or above which a finding triggers exit code 1.
	// FailThreshold (not Severity) so callers can express "never fail" via
	// finding.FailThresholdNone.
	FailOn finding.FailThreshold
	// Registry supplies the rules invoked against parsed units.
	Registry rule.Registry
	// IgnorePaths lists path patterns suppressed from discovery, merged on top of gitignore handling.
	IgnorePaths []string
	// IncludeIgnored disables gitignore and metadata directory pruning when true.
	IncludeIgnored bool
	// ReportAllSkippedInputs reports explicit input paths that are all skipped as diagnostics.
	ReportAllSkippedInputs bool
	// BaselinePath points at an optional baseline file used to suppress previously accepted findings.
	BaselinePath string
	// DiffBase enables changed-lines-only mode against this git revision when non-empty.
	DiffBase string
	// DiffMode enables changed-region filtering from working-tree, staged, unstaged, a base ref, or "-".
	DiffMode string
	// DiffPatch carries a unified diff supplied by the CLI when DiffMode is "-".
	DiffPatch []byte
	// ChangedRanges enables explicit changed-region filtering such as "3-3,8-10".
	ChangedRanges string
	// ChangedScope selects "symbol" (default) or "hunk" changed-region filtering.
	ChangedScope string
	// BaselineShow renders the unchanged/resolved baseline detail arrays and the
	// human-readable baseline-status section; counts are reported regardless.
	BaselineShow bool
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
	diagnostics := []Diagnostic{}
	if opts.ReportAllSkippedInputs {
		diagnostics = append(diagnostics, diagnosticsFromAllSkippedInputs(opts.Paths, discovery)...)
	}
	// Parse and analyse the full discovered project even in diff mode: project-level
	// rules (such as cross-file dead-code) and baseline classification need complete
	// context to avoid false positives, so the changed-region scope is applied to
	// emitted findings (applyChangedFilter below) rather than by pruning files before
	// they are parsed.
	changed, diffSummary, diagnostics := resolveChangedScope(ctx, root, discovery.Files, diagnostics, opts)

	projectFiles, err := projectContextFiles(root, opts, discovery.Files)
	if err != nil {
		return Report{}, err
	}
	units, parseDiagnostics := parser.Parse(discovery.Files)
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	projectUnits := units
	if !sameSourceFileSet(discovery.Files, projectFiles) {
		var projectParseDiagnostics []parser.Diagnostic
		projectUnits, projectParseDiagnostics = parser.Parse(projectFiles)
		// A sibling pulled in only for package context can strip evidence a
		// project rule depends on (an unparsed caller makes a used symbol look
		// dead), so surface its parse/read failures rather than letting them
		// drive a silent false positive. Primary-file diagnostics are reported
		// below, so only the context-only entries are added here.
		parseDiagnostics = append(parseDiagnostics, contextOnlyParseDiagnostics(projectParseDiagnostics, discovery.Files)...)
	}
	diagnostics = append(diagnostics, diagnosticsFromDiscovery(discovery.Missing)...)
	diagnostics = append(diagnostics, diagnosticsFromParser(parseDiagnostics)...)
	registry := opts.Registry
	findings := registry.AnalyzeWithProjectContext(units, projectUnits, rule.Context{Root: root, IncludeIgnored: opts.IncludeIgnored, ReportableFiles: reportableFileSet(discovery.Files)})
	findings = filterFindingsToFiles(findings, reportableFileSet(discovery.Files))
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	findings, baselineSummary, diagnostics := applyBaseline(root, findings, diagnostics, opts.BaselinePath, opts.BaselineShow)
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	findings, diffSummary = applyChangedFilter(findings, units, changed, diffSummary, opts.ChangedScope)

	displayRoot := filepath.ToSlash(root)
	return NewReport(ReportInput{
		Root:            displayRoot,
		Inputs:          inputsOrDefault(opts.Paths),
		Format:          opts.Format,
		FailOn:          opts.FailOn,
		IncludeIgnored:  opts.IncludeIgnored,
		Scanned:         scannedPaths(discovery.Files),
		Skipped:         skippedPaths(discovery.Skipped),
		Missing:         discovery.Missing,
		Diagnostics:     diagnostics,
		Findings:        findings,
		Definitions:     registry.Definitions(),
		Baseline:        baselineSummary,
		Diff:            diffSummary,
		SuppressedCount: suppressedCountPointer(diffSummary),
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

// normalizeOptions fills defaults for empty Options fields. Empty FailOn
// resolves to the canonical "analyse" default so programmatic callers get
// the same gate as the analyse CLI consumer.
func normalizeOptions(opts Options) Options {
	if opts.FailOn == "" {
		opts.FailOn = finding.DefaultFailThresholdFor("analyse")
	}
	if opts.Format == "" {
		opts.Format = "text"
	}
	if opts.ChangedScope == "" {
		opts.ChangedScope = "symbol"
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
			Severity: finding.SeverityError,
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
			Severity: finding.SeverityError,
		})
	}
	return diagnostics
}

// applyBaseline suppresses findings that match the loaded baseline file and
// classifies the run into new/unchanged/resolved. show populates the
// unchanged/resolved detail arrays (the --baseline-show flag); counts emit
// regardless.
func applyBaseline(root string, findings []finding.Finding, diagnostics []Diagnostic, baselinePath string, show bool) ([]finding.Finding, BaselineSummary, []Diagnostic) {
	baselineSummary := BaselineSummary{}
	if baselinePath == "" {
		return findings, baselineSummary, diagnostics
	}
	displayPath := filepath.ToSlash(baselinePath)
	loadPath := baselinePath
	if !filepath.IsAbs(loadPath) {
		loadPath = filepath.Join(root, loadPath)
	}
	baselineSummary.Path = displayPath
	file, err := baseline.Load(loadPath)
	if err != nil {
		diagnostics = append(diagnostics, Diagnostic{
			Stage:    "baseline",
			Message:  err.Error(),
			File:     displayPath,
			Severity: finding.SeverityError,
		})
		return findings, baselineSummary, diagnostics
	}
	// Applied marks a *successful* baseline comparison; it drives SARIF
	// baselineState and the summary's baseline-applied line. Setting it only after
	// Load succeeds keeps a missing or invalid baseline from labelling every
	// emitted result baselineState:"new" as though it had been compared against a
	// real baseline (the load failure is already surfaced as an error diagnostic).
	baselineSummary.Applied = true
	result := baseline.Apply(findings, file)
	baselineSummary.Entries = result.Entries
	baselineSummary.SuppressedFindings = result.SuppressedFindings
	baselineSummary.StaleEntries = result.StaleEntries
	baselineSummary.NewFindings = result.NewCount()
	baselineSummary.UnchangedFindings = result.UnchangedCount()
	baselineSummary.ResolvedFindings = result.ResolvedCount()
	// Detail arrays are populated only under --baseline-show; counts always emit.
	// Gating population (not just rendering) keeps the default JSON payload free of
	// the unchanged/resolved arrays regardless of omitempty subtleties.
	if show {
		baselineSummary.Show = true
		baselineSummary.Unchanged = result.Unchanged
		baselineSummary.Resolved = reportBaselineEntries(result.Resolved)
	}
	return result.Findings, baselineSummary, diagnostics
}

// reportBaselineEntries projects baseline resolved entries onto the report shape.
func reportBaselineEntries(entries []baseline.Entry) []BaselineEntry {
	out := make([]BaselineEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, BaselineEntry{RuleID: entry.RuleID, File: entry.File, Fingerprint: entry.Fingerprint})
	}
	return out
}

// resolveChangedScope computes the changed-line set for the requested diff mode.
// It does not prune the file set; callers apply the resulting scope to findings.
// ctx is threaded into the git subprocesses so an aborted scan cancels them.
//
// An explicit --diff/--since mode (DiffMode) is resolved before a bare DiffPatch so
// that --since wins over a --diff=- stdin patch (matching analyseFlagValues
// .resolvedDiffMode); a DiffPatch with no mode still applies for programmatic
// callers that supply a patch directly.
func resolveChangedScope(ctx context.Context, root string, files []source.File, diagnostics []Diagnostic, opts Options) (diff.ChangedLines, DiffSummary, []Diagnostic) {
	diffSummary := DiffSummary{}
	switch {
	case opts.ChangedRanges != "":
		changed, err := diff.ExplicitRanges("explicit", opts.ChangedRanges, sourcePaths(files))
		if err != nil {
			return diff.ChangedLines{}, diffSummary, appendDiffDiagnostic(diagnostics, err)
		}
		diffSummary.Enabled = true
		diffSummary.Base = "explicit"
		diffSummary.ChangedFiles = changed.ChangedFiles
		return changed, diffSummary, diagnostics
	case opts.DiffMode == "-":
		changed := diff.Parse("stdin", opts.DiffPatch)
		diffSummary.Enabled = true
		diffSummary.Base = "stdin"
		diffSummary.ChangedFiles = changed.ChangedFiles
		return changed, diffSummary, diagnostics
	case opts.DiffMode != "":
		changed, err := diff.FromMode(ctx, root, opts.DiffMode, opts.Paths)
		if err != nil {
			return diff.ChangedLines{}, diffSummary, appendDiffDiagnostic(diagnostics, err)
		}
		diffSummary.Enabled = true
		diffSummary.Base = opts.DiffMode
		diffSummary.ChangedFiles = changed.ChangedFiles
		return changed, diffSummary, diagnostics
	case len(opts.DiffPatch) > 0:
		changed := diff.Parse("stdin", opts.DiffPatch)
		diffSummary.Enabled = true
		diffSummary.Base = "stdin"
		diffSummary.ChangedFiles = changed.ChangedFiles
		return changed, diffSummary, diagnostics
	case opts.DiffBase != "":
		changed, err := diff.FromGit(ctx, root, opts.DiffBase, opts.Paths)
		if err != nil {
			return diff.ChangedLines{}, diffSummary, appendDiffDiagnostic(diagnostics, err)
		}
		diffSummary.Enabled = true
		diffSummary.Base = opts.DiffBase
		diffSummary.ChangedFiles = changed.ChangedFiles
		return changed, diffSummary, diagnostics
	default:
		return diff.ChangedLines{}, diffSummary, diagnostics
	}
}

// appendDiffDiagnostic records a diff-stage failure as an error-severity
// Diagnostic so the scan continues and reports the problem instead of aborting -
// the changed-region filter is best-effort, not fatal to the run.
func appendDiffDiagnostic(diagnostics []Diagnostic, err error) []Diagnostic {
	return append(diagnostics, Diagnostic{
		Stage:    "diff",
		Message:  err.Error(),
		Severity: finding.SeverityError,
	})
}

// sourcePaths projects discovered source files down to their path strings - the
// form the diff and changed-file filters compare against.
func sourcePaths(files []source.File) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	return paths
}

// applyChangedFilter filters findings against the resolved changed regions.
// Composite findings are line-stable by design (so baseline matching survives
// underlying code shifts), which means diff.Filter treats them as "no location"
// and keeps them whenever the file has any changed line. After the line-based
// filter runs, prune composites whose underlying evidence did not survive -
// otherwise --diff-base scans surface composites for code the diff did not
// touch.
func applyChangedFilter(findings []finding.Finding, units []parser.Unit, changed diff.ChangedLines, diffSummary DiffSummary, changedScope string) ([]finding.Finding, DiffSummary) {
	if !diffSummary.Enabled {
		return findings, diffSummary
	}
	result := filterFindingsByChangedScope(findings, changed, units, changedScope)
	kept, pruned := pruneOrphanedComposites(result.Findings)
	diffSummary.FilteredFindings = result.FilteredFindings + pruned
	diffSummary.Caveat = "diff mode is changed-region scoped and is not full-project proof for project-level rules"
	return kept, diffSummary
}

// filterFindingsByChangedScope applies the changed-region filter at the requested
// granularity: "hunk" keeps only findings on changed lines, while the default
// symbol scope keeps a finding when its enclosing function was touched - so a
// one-line edit still surfaces the whole function's issues for review.
func filterFindingsByChangedScope(findings []finding.Finding, changed diff.ChangedLines, units []parser.Unit, changedScope string) diff.FilterResult {
	if changedScope == "hunk" {
		return diff.Filter(findings, changed)
	}
	functionsByFile := map[string][]parser.Function{}
	for _, unit := range units {
		functionsByFile[unit.File.Path] = unit.Functions
	}
	kept := make([]finding.Finding, 0, len(findings))
	filtered := 0
	for _, item := range findings {
		if changedScopeMatches(item, changed, functionsByFile[item.File]) {
			kept = append(kept, item)
			continue
		}
		filtered++
	}
	return diff.FilterResult{Findings: kept, FilteredFindings: filtered}
}

// changedScopeMatches reports whether one finding survives the symbol-scope diff
// filter: a located finding is kept when its own line range changed or when the
// function enclosing it changed; an unlocated (file-level) finding falls back to
// whether the file changed at all.
func changedScopeMatches(item finding.Finding, changed diff.ChangedLines, functions []parser.Function) bool {
	if item.Location == nil || item.Location.Line == 0 {
		return diff.FileChanged(changed, item.File)
	}
	start := item.Location.Line
	end := item.Location.EndLine
	if end == 0 || end < start {
		end = start
	}
	if diff.RangeChanged(changed, item.File, start, end) {
		return true
	}
	function, ok := enclosingFunction(start, item.Symbol, functions)
	return ok && diff.RangeChanged(changed, item.File, function.Line, function.EndLine)
}

// enclosingFunction finds the function containing line, preferring one whose name
// matches the finding's symbol and, among matches, the tightest span; it falls
// back to any function covering the line so nested or method-receiver symbols
// still resolve to something.
func enclosingFunction(line int, symbol string, functions []parser.Function) (parser.Function, bool) {
	var best parser.Function
	found := false
	for _, function := range functions {
		if line < function.Line || line > function.EndLine {
			continue
		}
		if symbol != "" && function.Name != symbol && !strings.HasSuffix(function.Name, "."+symbol) {
			continue
		}
		if !found || function.EndLine-function.Line < best.EndLine-best.Line {
			best = function
			found = true
		}
	}
	if found {
		return best, true
	}
	for _, function := range functions {
		if line >= function.Line && line <= function.EndLine {
			return function, true
		}
	}
	return parser.Function{}, false
}

// suppressedCountPointer returns a pointer to the diff-filtered count, or nil when
// diff mode is off, so JSON output omits suppressedCount entirely rather than
// reporting a misleading 0 when no filtering actually happened.
func suppressedCountPointer(diffSummary DiffSummary) *int {
	if !diffSummary.Enabled {
		return nil
	}
	return &diffSummary.FilteredFindings
}

// scannedPaths extracts the relative paths from discovered source files.
func scannedPaths(files []source.File) []string {
	scanned := make([]string, 0, len(files))
	for _, file := range files {
		scanned = append(scanned, file.Path)
	}
	return scanned
}

// skippedPaths copies discovery skip entries into report-shaped values,
// carrying the ignore source and matched glob through to the report so a hook
// or agent can see not just that a path was excluded but which layer and which
// configured pattern excluded it.
func skippedPaths(items []source.SkippedPath) []SkippedPath {
	skipped := make([]SkippedPath, 0, len(items))
	for _, item := range items {
		skipped = append(skipped, SkippedPath{
			Path:    item.Path,
			Reason:  item.Reason,
			Source:  item.Source,
			Pattern: item.Pattern,
		})
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
