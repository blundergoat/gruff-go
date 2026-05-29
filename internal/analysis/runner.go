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
	changed, diffSummary, diagnostics := resolveChangedScope(root, opts.Paths, discovery.Files, diagnostics, opts)
	if diffSummary.Enabled && opts.ChangedRanges == "" {
		discovery.Files = filterDiscoveredChangedFiles(discovery.Files, changed)
	}

	units, parseDiagnostics := parser.Parse(discovery.Files)
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	diagnostics = append(diagnostics, diagnosticsFromDiscovery(discovery.Missing)...)
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
			Severity: finding.SeverityError,
		})
		return findings, baselineSummary, diagnostics
	}
	result := baseline.Apply(findings, file)
	baselineSummary.Entries = result.Entries
	baselineSummary.SuppressedFindings = result.SuppressedFindings
	baselineSummary.StaleEntries = result.StaleEntries
	return result.Findings, baselineSummary, diagnostics
}

// resolveChangedScope computes changed files before parsing so directory scans
// can avoid analysing files that are outside the requested diff.
func resolveChangedScope(root string, paths []string, files []source.File, diagnostics []Diagnostic, opts Options) (diff.ChangedLines, DiffSummary, []Diagnostic) {
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
	case len(opts.DiffPatch) > 0:
		changed := diff.Parse("stdin", opts.DiffPatch)
		diffSummary.Enabled = true
		diffSummary.Base = "stdin"
		diffSummary.ChangedFiles = changed.ChangedFiles
		return changed, diffSummary, diagnostics
	case opts.DiffMode != "":
		changed, err := diff.FromMode(root, opts.DiffMode, paths)
		if err != nil {
			return diff.ChangedLines{}, diffSummary, appendDiffDiagnostic(diagnostics, err)
		}
		diffSummary.Enabled = true
		diffSummary.Base = opts.DiffMode
		diffSummary.ChangedFiles = changed.ChangedFiles
		return changed, diffSummary, diagnostics
	case opts.DiffBase != "":
		changed, err := diff.FromGit(root, opts.DiffBase, paths)
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

func appendDiffDiagnostic(diagnostics []Diagnostic, err error) []Diagnostic {
	return append(diagnostics, Diagnostic{
		Stage:    "diff",
		Message:  err.Error(),
		Severity: finding.SeverityError,
	})
}

func sourcePaths(files []source.File) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	return paths
}

func filterDiscoveredChangedFiles(files []source.File, changed diff.ChangedLines) []source.File {
	filtered := make([]source.File, 0, len(files))
	for _, file := range files {
		if diff.FileChanged(changed, file.Path) {
			filtered = append(filtered, file)
		}
	}
	return filtered
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

func suppressedCountPointer(diffSummary DiffSummary) *int {
	if !diffSummary.Enabled {
		return nil
	}
	return &diffSummary.FilteredFindings
}

// pruneOrphanedComposites drops composite findings whose recorded underlying
// fingerprints are not present among the surviving non-composite findings.
// A composite is identified by a non-empty underlyingFingerprints metadata
// slice; that is the contract composite rules use when emitting evidence.
func pruneOrphanedComposites(findings []finding.Finding) ([]finding.Finding, int) {
	survivingFingerprints := collectNonCompositeFingerprints(findings)
	kept := make([]finding.Finding, 0, len(findings))
	pruned := 0
	for _, candidate := range findings {
		if compositeEvidenceSurvives(candidate, survivingFingerprints) {
			kept = append(kept, candidate)
			continue
		}
		pruned++
	}
	return kept, pruned
}

// collectNonCompositeFingerprints returns the set of fingerprints belonging to
// non-composite findings. Composites are identified by an underlyingFingerprints
// metadata slice and are excluded from the surviving-evidence set.
func collectNonCompositeFingerprints(findings []finding.Finding) map[string]struct{} {
	out := map[string]struct{}{}
	for _, candidate := range findings {
		if _, isComposite := compositeUnderlyingFingerprints(candidate); isComposite {
			continue
		}
		if candidate.Fingerprint != "" {
			out[candidate.Fingerprint] = struct{}{}
		}
	}
	return out
}

// compositeEvidenceSurvives reports whether the candidate should be kept after
// composite pruning. Non-composite findings always survive; composites survive
// only when at least one of their recorded underlying fingerprints is in the
// surviving set.
func compositeEvidenceSurvives(candidate finding.Finding, survivingFingerprints map[string]struct{}) bool {
	underlying, isComposite := compositeUnderlyingFingerprints(candidate)
	if !isComposite {
		return true
	}
	for _, fp := range underlying {
		if _, ok := survivingFingerprints[fp]; ok {
			return true
		}
	}
	return false
}

// compositeUnderlyingFingerprints extracts the recorded underlying fingerprint
// set from a composite finding's metadata. Returns (fingerprints, true) when
// the finding carries an underlyingFingerprints slice. The slice may be empty
// for composites whose evidence had no fingerprints, in which case the
// composite still counts as composite but is treated as orphan-eligible.
func compositeUnderlyingFingerprints(item finding.Finding) ([]string, bool) {
	if item.Metadata == nil {
		return nil, false
	}
	raw, ok := item.Metadata["underlyingFingerprints"]
	if !ok {
		return nil, false
	}
	switch values := raw.(type) {
	case []string:
		return values, true
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if str, ok := value.(string); ok {
				out = append(out, str)
			}
		}
		return out, true
	}
	return nil, false
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
