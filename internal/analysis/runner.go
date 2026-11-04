// Package analysis runner ties source discovery, parsing, and rule execution together.
//
// It produces a deterministic Report consumed by the CLI and report renderers.
// Sensitive exclusions, inline suppressions, the baseline and the changed-region filter then decide which findings the user sees.
package analysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blundergoat/gruff-go/internal/baseline"
	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/diff"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/rule"
	"github.com/blundergoat/gruff-go/internal/source"
)

// Options configures a single Analyze invocation.
//
// The CLI builds it from the user's flags and .gruff-go.yaml; a programmatic caller may fill it directly.
// Analyze fills an empty FailOn, Format, ChangedScope or DeepScanBudget with defaults; a nil Context, empty Root and empty Paths also fall back.
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
	// It is a FailThreshold, not a Severity, so finding.FailThresholdNone can say "never fail on findings".
	FailOn finding.FailThreshold
	// MinConfidence is the confidence floor for the exit gate; Analyze passes it to NewReport, whose summary exit code ignores it.
	MinConfidence finding.Confidence
	// FailOnNew asks the exit gate to fail on any finding the baseline classifies as new; NewReport's summary exit code ignores it.
	FailOnNew bool
	// Registry supplies the rules invoked against parsed units.
	Registry rule.Registry
	// IgnorePaths lists path patterns suppressed from discovery, merged on top of gitignore handling.
	IgnorePaths []string
	// SensitiveExclusions carries the project's validated sensitiveExclusions entries from the config.
	// Each removes the sensitive-data findings its scope claims and is counted into the report's suppression audit.
	SensitiveExclusions []SensitiveExclusion
	// DeepScanBudget bounds AST-backed analysis after source extension classification.
	DeepScanBudget DeepScanBudget
	// IncludeIgnored disables gitignore and metadata directory pruning when true; .git, .hg and .svn directories below the analysis root stay skipped.
	IncludeIgnored bool
	// ReportAllSkippedInputs reports explicit input paths that are all skipped as
	// fatal diagnostics. Advisory hook mode intentionally leaves this disabled.
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
	// ChangedRangesProvided records that --changed-ranges was passed, so an empty value is refused as naming nothing, not read as no filter.
	// A programmatic caller may leave it false and set ChangedRanges alone.
	ChangedRangesProvided bool
	// ChangedScope selects "symbol" (default) or "hunk" changed-region filtering.
	ChangedScope string
	// BaselineShow renders the unchanged/resolved baseline detail arrays and the
	// human-readable baseline-status section; counts are reported regardless.
	BaselineShow bool
}

// DeepScanBudget is the effective paired limit after defaults, config, and CLI precedence.
//
// The user sets it in the deepScanBudget block of .gruff-go.yaml.
// When Enabled is true, a file above either bound keeps its text-level rules but skips AST-backed deep analysis.
// An empty Override makes Analyze substitute the enabled default bounds and set Override to "default".
type DeepScanBudget struct {
	Enabled  bool
	MaxLines int
	MaxBytes int
	Override string
}

// Analyze runs discovery, parsing, and rules against the configured root.
//
// opts supplies the root, inputs, registry, baseline and diff scope; normalizeOptions fills its empty fields with defaults.
// It returns the Report of the findings left after exclusions, baseline and diff filtering, with diagnostics and path lists.
//
// It returns an error when root resolution, discovery or parseWithProjectContext fails, or when opts.Context is done.
// Baseline, diff and parse failures become diagnostics in the Report instead of an error.
func Analyze(opts Options) (Report, error) {
	root, err := analysisRoot(opts.Root)
	// A root that does not exist or names a file ends the run here with an error, before any file is read.
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
	// Discovery errors end the run with no report; a missing input path is not one, it becomes a diagnostic below.
	if err != nil {
		return Report{}, err
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	diagnostics := []Diagnostic{}
	// When every explicit input path is skipped, this reports it as fatal; advisory hook mode leaves it off and stays quiet.
	if opts.ReportAllSkippedInputs {
		diagnostics = append(diagnostics, diagnosticsFromAllSkippedInputs(opts.Paths, discovery)...)
	}
	// Parse and analyse the full discovered project even in diff mode.
	//
	// Project-level rules such as cross-file dead-code, and baseline classification, need full context to avoid false positives.
	// The changed-region scope is applied to emitted findings in applyChangedFilter instead of pruning files before they are parsed.
	changed, diffSummary, diagnostics := resolveChangedScope(ctx, root, discovery.Files, diagnostics, opts)

	units, projectUnits, parseDiagnostics, err := parseWithProjectContext(ctx, root, opts, discovery)
	// Only a failure to gather package siblings or a cancelled run ends here; a file that fails to parse becomes a diagnostic instead.
	if err != nil {
		return Report{}, err
	}
	diagnostics = append(diagnostics, diagnosticsFromDiscovery(discovery.Missing)...)
	diagnostics = append(diagnostics, diagnosticsFromParser(parseDiagnostics)...)
	registry := opts.Registry
	findings := registry.AnalyzeWithProjectContext(units, projectUnits, rule.Context{Root: root, IncludeIgnored: opts.IncludeIgnored, ReportableFiles: reportableFileSet(discovery.Files)})
	findings = filterFindingsToFiles(findings, reportableFileSet(discovery.Files))
	// A scope the run could not read leaves nothing scoped to report. Publishing the unscoped findings beside the
	// diagnostic would read as a successful narrow scan at a scope the run never applied.
	if hasUnreadableChangedScope(diagnostics) {
		findings = nil
	}
	// The baseline identity separates same-named declarations by ordinal, which
	// only the parsed units can rank; assigning here reaches analyse and hook alike.
	findings = finding.AssignSymbolOrdinalsFromInventory(findings, declarationPositionFor(units), sameNamedDeclarationLinesFor(units))
	// Excluded before baseline and diff so a suppressed finding is absent from
	// scoring, exit codes, and baseline classification alike.
	findings, suppressions := ApplySensitiveExclusions(findings, opts.SensitiveExclusions)
	// A configured entry claims its findings first, so its count stays what the user wrote it for.
	findings, suppressions = ApplyBuiltInTestPathSkip(findings, suppressions)
	// Another tool's comment naming the same check suppresses a finding where it was written (section 13c).
	findings, suppressions, suppressedFindings := ApplyInlineSuppressions(findings, suppressions, sourcesByFile(units))
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
		MinConfidence:   opts.MinConfidence,
		FailOnNew:       opts.FailOnNew,
		IncludeIgnored:  opts.IncludeIgnored,
		Suppressions:    suppressions,
		Suppressed:      suppressedFindings,
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

// analysisRoot resolves the supplied root to an absolute directory path before discovery starts.
//
// It returns the absolute path of root, or the current working directory when root is empty.
// It returns an error when the working directory or absolute path cannot be resolved, os.Stat fails, or the path is not a directory.
func analysisRoot(root string) (string, error) {
	if root == "" {
		return os.Getwd()
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(rootAbs)
	// A mistyped or deleted root fails here, and the scan stops with that error before discovery.
	if err != nil {
		return "", err
	}
	// A file used as the root stops the scan here with an error, before discovery.
	if !info.IsDir() {
		return "", fmt.Errorf("analysis root is not a directory: %s", root)
	}
	return rootAbs, nil
}

// normalizeOptions fills defaults for empty Options fields before Analyze uses them.
//
// Empty FailOn resolves to the canonical "analyse" default, so programmatic callers get the same gate as gruff-go analyse.
// It returns opts with an empty FailOn, Format ("text") or ChangedScope ("symbol") set to its default.
// A DeepScanBudget with an empty Override is replaced whole by the enabled default line and byte bounds, with Override "default".
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
	if opts.DeepScanBudget.Override == "" {
		opts.DeepScanBudget = DeepScanBudget{
			Enabled:  true,
			MaxLines: cfgpkg.DefaultDeepScanMaxLines,
			MaxBytes: cfgpkg.DefaultDeepScanMaxBytes,
			Override: "default",
		}
	}
	return opts
}

// parserBudget projects the effective analysis option into the parser package's narrow contract.
// It returns a parser.DeepScanBudget that copies the Enabled, MaxLines, MaxBytes and Override fields of budget unchanged.
func parserBudget(budget DeepScanBudget) parser.DeepScanBudget {
	return parser.DeepScanBudget{
		Enabled:  budget.Enabled,
		MaxLines: budget.MaxLines,
		MaxBytes: budget.MaxBytes,
		Override: budget.Override,
	}
}

// diagnosticsFromDiscovery turns each missing path from discovery into a "path does not exist" diagnostic in the report.
// It returns one error-severity discovery Diagnostic per path, or an empty non-nil slice when paths is empty.
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

// diagnosticsFromParser lifts each parser-stage diagnostic into the unified analysis Diagnostic shape.
//
// An entry without NonFatal gets stage "parse" and error severity, so a file that fails to parse shows as an error diagnostic.
// A NonFatal one gets stage "analysis", advisory severity and InvalidatesRun set to false.
// It returns one Diagnostic per entry of parseDiagnostics, in order, or an empty non-nil slice when parseDiagnostics is empty.
func diagnosticsFromParser(parseDiagnostics []parser.Diagnostic) []Diagnostic {
	diagnostics := []Diagnostic{}
	for _, parseDiagnostic := range parseDiagnostics {
		stage := "parse"
		severity := finding.SeverityError
		var invalidatesRun *bool
		if parseDiagnostic.NonFatal {
			stage = "analysis"
			severity = finding.SeverityAdvisory
			value := false
			invalidatesRun = &value
		}
		diagnostics = append(diagnostics, Diagnostic{
			DiagnosticType: parseDiagnostic.Type,
			Stage:          stage,
			Message:        parseDiagnostic.Message,
			File:           parseDiagnostic.File,
			Location:       parserLocation(parseDiagnostic),
			Severity:       severity,
			InvalidatesRun: invalidatesRun,
		})
	}
	return diagnostics
}

// applyBaseline suppresses findings that match the loaded baseline file and classifies the run into new, unchanged and resolved.
//
// show, set by --baseline-show, fills the unchanged and resolved detail arrays; the counts are emitted regardless.
// A relative baselinePath is joined to root; an empty baselinePath returns findings and diagnostics unchanged with a zero BaselineSummary.
//
// It returns the findings the baseline kept, each stamped with its status, the summary, and diagnostics plus one warning per collision.
// A baseline that fails to load or apply adds an error Diagnostic and returns findings unsuppressed, with Applied left false.
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
	// The report labels the baseline by file name: gruff-baseline.json reads "default" even when the user passed that path themselves.
	baselineSummary.Source = baselineSource(baselinePath)
	file, err := baseline.Load(loadPath)
	// A missing or invalid baseline file lands here; the run goes on with every finding unsuppressed and an error diagnostic.
	if err != nil {
		diagnostics = append(diagnostics, Diagnostic{
			Stage: "baseline",
			// The load error names the joined host path; the report names the baseline as the user gave it.
			Message:  strings.ReplaceAll(err.Error(), loadPath, displayPath),
			File:     displayPath,
			Severity: finding.SeverityError,
		})
		return findings, baselineSummary, diagnostics
	}
	// Applied marks a successful baseline comparison; it drives SARIF baselineState and the summary's baseline-applied line.
	//
	// It is set only after Load and Apply succeed, so a missing or invalid baseline never labels every result baselineState "new".
	// That failure already shows as an error diagnostic instead.
	result, err := baseline.Apply(findings, file)
	// A foreign baseline or an unidentifiable finding is refused before matching;
	// applying it would report every entry resolved and invite a destructive regenerate.
	if err != nil {
		diagnostics = append(diagnostics, Diagnostic{
			Stage:    "baseline",
			Message:  err.Error(),
			File:     displayPath,
			Severity: finding.SeverityError,
		})
		return findings, baselineSummary, diagnostics
	}
	baselineSummary.Applied = true
	baselineSummary.Entries = result.Entries
	baselineSummary.SuppressedFindings = result.SuppressedFindings
	baselineSummary.StaleEntries = result.StaleEntries
	// newFindings is the gated set the exit code fails on: new, collision, and not-eligible findings alike.
	// The envelope's baseline container admits no new keys yet, so the finer split surfaces once the schema can name it.
	baselineSummary.NewFindings = result.GatedCount()
	baselineSummary.UnchangedFindings = result.UnchangedCount()
	baselineSummary.ResolvedFindings = result.ResolvedCount()
	// Every collision is reported by name, so the user can see which identity could not separate two declarations.
	for _, collision := range result.Collisions {
		diagnostics = append(diagnostics, Diagnostic{
			Stage:          "baseline",
			Message:        fmt.Sprintf("collision: identity %s covers %d declarations of %s for rule %s in %s; none is suppressed", collision.Identity, len(collision.Subjects), strings.Join(collision.Subjects, ", "), collision.RuleID, collision.Path),
			File:           collision.Path,
			Severity:       finding.SeverityWarning,
			InvalidatesRun: new(bool),
		})
	}
	// Detail arrays are filled only under --baseline-show; counts always emit.
	// Gating the data, not just its rendering, keeps the default JSON payload free of the unchanged and resolved arrays whatever omitempty does.
	if show {
		baselineSummary.Show = true
		baselineSummary.Unchanged = result.Unchanged
		baselineSummary.Resolved = reportBaselineEntries(result.Resolved)
	}
	return stampBaselineStatuses(findings, result), baselineSummary, diagnostics
}

// stampBaselineStatuses labels each surviving finding with what the baseline made of it.
//
// SARIF publishes baselineState "new" for a genuinely new finding only: a collision and a sensitive
// finding are permanently unsuppressable rather than freshly introduced, and stamping them "new" would
// tell a code-scanning reader that a long-standing secret had just appeared.
//
// Statuses in result are matched to currentFindings by index and keyed by Fingerprint; a status past the end of currentFindings is dropped.
// It returns a new slice of the findings in result, each with BaselineStatus set; one whose Fingerprint has no status gets an empty one.
func stampBaselineStatuses(currentFindings []finding.Finding, result baseline.ApplyResult) []finding.Finding {
	statusByFinding := map[string]string{}
	for index, status := range result.Statuses {
		if index < len(currentFindings) {
			statusByFinding[currentFindings[index].Fingerprint] = string(status)
		}
	}
	stamped := make([]finding.Finding, 0, len(result.Findings))
	for _, gatedFinding := range result.Findings {
		gatedFinding.BaselineStatus = statusByFinding[gatedFinding.Fingerprint]
		stamped = append(stamped, gatedFinding)
	}
	return stamped
}

// DefaultBaselineFileName is the one filename every port writes and auto-discovers.
//
// baselineSource reports any baseline with this base name as "default" in the report, whether it was auto-discovered or named by the user.
const DefaultBaselineFileName = "gruff-baseline.json"

// baselineSource labels the report's baseline by its file name, not by how the user chose the path.
//
// It returns "default" when the base name of baselinePath is DefaultBaselineFileName, and "explicit" otherwise.
// It judges by file name alone, so a path the user named that ends in that file name also reads "default".
func baselineSource(baselinePath string) string {
	if filepath.Base(baselinePath) == DefaultBaselineFileName {
		return "default"
	}
	return "explicit"
}

// reportBaselineEntries projects baseline resolved entries onto the report shape.
// It returns one BaselineEntry per entry, in order, copying RuleID, Path as File, Identity, Subject and Count; no entries gives an empty slice.
func reportBaselineEntries(entries []baseline.ResolvedEntry) []BaselineEntry {
	resolvedEntries := make([]BaselineEntry, 0, len(entries))
	for _, entry := range entries {
		resolvedEntries = append(resolvedEntries, BaselineEntry{RuleID: entry.RuleID, File: entry.Path, Identity: entry.Identity, Subject: entry.Subject, Count: entry.Count})
	}
	return resolvedEntries
}

// declarationPositionFor maps a symbol-bearing finding to the line its declaration begins on, using the parsed function spans.
//
// A finding inside a function body shares that function's position, so two findings on one declaration share an ordinal.
// A finding on no known declaration keeps its own line as its position.
//
// Only a function in units whose name the Symbol names, per symbolNamesFunction, and whose span covers the line counts as that declaration.
// It returns a closure giving that start line, else the finding's own line, which is 1 when the finding has no location or a zero line.
func declarationPositionFor(units []parser.Unit) func(finding.Finding) int {
	functionsByFile := map[string][]parser.Function{}
	for _, unit := range units {
		functionsByFile[unit.File.Path] = unit.Functions
	}
	return func(item finding.Finding) int {
		line := 1
		if item.Location != nil && item.Location.Line > 0 {
			line = item.Location.Line
		}
		for _, function := range functionsByFile[item.File] {
			if !symbolNamesFunction(item.Symbol, function.Name) || line < function.Line || line > max(function.Line, function.EndLine) {
				continue
			}
			return function.Line
		}
		return line
	}
}

// sameNamedDeclarationLinesFor lists, for a finding, the start line of every parsed function in its file that its symbol names.
//
// A bare method name such as Process names A.Process and B.Process alike, so a clean same-named method still takes its ordinal slot.
// It returns a closure over the functions in units that gives those lines in parser order, or an empty non-nil slice when none matches.
func sameNamedDeclarationLinesFor(units []parser.Unit) func(finding.Finding) []int {
	functionsByFile := map[string][]parser.Function{}
	for _, unit := range units {
		functionsByFile[unit.File.Path] = unit.Functions
	}
	return func(item finding.Finding) []int {
		lines := []int{}
		for _, function := range functionsByFile[item.File] {
			if symbolNamesFunction(item.Symbol, function.Name) {
				lines = append(lines, function.Line)
			}
		}
		return lines
	}
}

// symbolNamesFunction accepts the parser's receiver-qualified name and the unqualified name a rule may emit for the same declaration.
// It reports true when symbol equals functionName or the part of functionName after its first dot, and false otherwise.
func symbolNamesFunction(symbol, functionName string) bool {
	if symbol == functionName {
		return true
	}
	_, unqualified, found := strings.Cut(functionName, ".")
	return found && symbol == unqualified
}

// resolveChangedScope computes the changed-line set for the scope the user asked for with --changed-ranges, --diff, --since or --diff-base.
//
// It does not prune the file set; callers apply the resulting scope to findings.
// ctx is threaded into the git subprocesses so an aborted scan cancels them.
//
// An explicit --diff or --since mode in DiffMode is resolved before a bare DiffPatch, so --since wins over a --diff=- stdin patch.
// This matches analyseFlagValues.resolvedDiffMode; a DiffPatch with no mode still applies for programmatic callers that supply a patch.
//
// ChangedRanges in opts, when given or flagged by ChangedRangesProvided, outranks every diff mode and is resolved against the paths in files.
// A DiffMode other than "-" and a DiffBase are resolved in root, limited to opts.Paths.
//
// It returns the changed lines, a DiffSummary with Enabled, Base and ChangedFiles set, and diagnostics unchanged.
// With no scope requested the summary stays disabled; an unreadable scope gives empty lines, a disabled summary and an added diff diagnostic.
func resolveChangedScope(ctx context.Context, root string, files []source.File, diagnostics []Diagnostic, opts Options) (diff.ChangedLines, DiffSummary, []Diagnostic) {
	diffSummary := DiffSummary{}
	switch {
	case opts.ChangedRangesProvided || opts.ChangedRanges != "":
		changed, err := diff.ExplicitRanges("explicit", opts.ChangedRanges, sourcePaths(files))
		// A malformed --changed-ranges value lands here; the run reports no findings and exits 2.
		if err != nil {
			return diff.ChangedLines{}, diffSummary, appendDiffDiagnostic(diagnostics, err)
		}
		diffSummary.Enabled = true
		diffSummary.Base = "explicit"
		diffSummary.ChangedFiles = changed.ChangedFiles
		return changed, diffSummary, diagnostics
	// With --diff=-, the patch read from stdin alone decides the changed regions and git is not run.
	case opts.DiffMode == "-":
		changed := diff.Parse("stdin", opts.DiffPatch)
		diffSummary.Enabled = true
		diffSummary.Base = "stdin"
		diffSummary.ChangedFiles = changed.ChangedFiles
		return changed, diffSummary, diagnostics
	case opts.DiffMode != "":
		changed, err := diff.FromMode(ctx, root, opts.DiffMode, opts.Paths)
		// A --since ref git cannot resolve, or a root outside a git repository, lands here; the run reports no findings and exits 2.
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
		// A --diff-base revision that does not exist, or a root outside a git repository, lands here with the same exit 2.
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

// ChangedRegionDiagnosticType is the one type every port publishes when it cannot read the changed-region scope it was asked to analyse.
//
// It covers a scope from --changed-ranges, --diff or --since alike, as FAMILY-CONTRACT.md section 6 requires.
// A consumer reading a scoped run's failure therefore need not know which analyser produced it.
// In gruff-go such a diagnostic also clears every finding from the run, since nothing scoped could be read.
const ChangedRegionDiagnosticType = "changed-region"

// appendDiffDiagnostic records a diff-stage failure as a fatal, error-severity Diagnostic.
//
// Analyze then reports no findings, because a scope the run could not read leaves nothing scoped to report, and ResolveExitCode returns 2.
// Nonfatal diff limitations use DiffSummary.Caveat instead.
// It returns diagnostics with one changed-region Diagnostic appended, at stage "diff" and with the text of err as its message.
func appendDiffDiagnostic(diagnostics []Diagnostic, err error) []Diagnostic {
	return append(diagnostics, Diagnostic{
		DiagnosticType: ChangedRegionDiagnosticType,
		Stage:          "diff",
		Message:        err.Error(),
		Severity:       finding.SeverityError,
	})
}

// hasUnreadableChangedScope reports whether the run failed to read the scope it was asked to analyse.
// It is true when any entry in diagnostics has DiagnosticType ChangedRegionDiagnosticType, and false when none does or diagnostics is empty.
func hasUnreadableChangedScope(diagnostics []Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.DiagnosticType == ChangedRegionDiagnosticType {
			return true
		}
	}
	return false
}

// sourcePaths projects discovered source files down to their path strings, the form the diff and changed-file filters compare against.
// It returns the Path of each file in order, or an empty non-nil slice when files is empty.
func sourcePaths(files []source.File) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	return paths
}

// applyChangedFilter narrows findings to the changed regions, then drops composites whose underlying evidence did not survive.
//
// Composite findings are line-stable by design, so baseline matching survives shifts in the code beneath them.
// The changed-line filter therefore treats them as having no location and keeps them whenever their file has any changed line.
// Without the pruning, --diff-base scans would surface composites for code the diff did not touch.
//
// When diffSummary is not Enabled it returns findings and diffSummary unchanged.
// Otherwise it filters by the lines in changed at the changedScope granularity, using units for function spans, then prunes orphaned composites.
// It returns the kept findings and diffSummary with FilteredFindings counting both removals and the project-level Caveat set.
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

// filterFindingsByChangedScope applies the changed-region filter at the requested granularity, hunk or symbol.
//
// Hunk scope keeps findings on changed lines, unlocated findings in changed files, and every finding in a wholly changed file.
// Symbol scope, the default, keeps a finding whose own lines or enclosing function changed.
//
// Any changedScope other than "hunk" takes the symbol path, which checks the lines in changed against function spans read from units.
// It returns a diff.FilterResult with the kept findings and FilteredFindings counting the findings dropped.
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

// changedScopeMatches reports whether one finding survives the symbol-scope diff filter; false drops it from the scoped report.
//
// A located finding is kept when its own line range changed or when the function enclosing it changed.
// An unlocated, file-level finding falls back to whether its file changed at all.
//
// item is the finding under test, changed holds the changed lines, and functions lists the parsed functions of its file for enclosingFunction.
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

// enclosingFunction finds the function containing line, preferring the tightest one whose name matches the finding's symbol.
//
// It falls back to any function covering the line, so nested or method-receiver symbols still resolve to something.
// functions is the parsed function list of the finding's file; an empty symbol lets every covering function match, so the tightest wins.
// It returns the chosen function and true, or a zero parser.Function and false when no function in functions covers line.
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

// suppressedCountPointer returns a pointer to the diff-filtered count, or nil when diff mode is off.
//
// The nil case makes JSON output omit suppressedCount entirely instead of reporting a misleading 0 when no filtering happened.
// diffSummary is a copy, so the pointer addresses its own FilteredFindings and later changes to the caller's summary do not show through.
func suppressedCountPointer(diffSummary DiffSummary) *int {
	if !diffSummary.Enabled {
		return nil
	}
	return &diffSummary.FilteredFindings
}

// scannedPaths extracts the relative paths from discovered source files.
// It returns the Path of each file in order, or an empty non-nil slice when files is empty.
func scannedPaths(files []source.File) []string {
	scanned := make([]string, 0, len(files))
	for _, file := range files {
		scanned = append(scanned, file.Path)
	}
	return scanned
}

// skippedPaths copies discovery skip entries into report-shaped values for the report's skipped list.
//
// The ignore source and matched glob are carried through, so a hook or agent sees which layer and which configured pattern excluded a path.
// It returns one SkippedPath per entry of items, copying Path, Reason, Source and Pattern, or an empty non-nil slice when items is empty.
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
// It returns a Location with the Line and Column of item, or nil when both are zero; a nonzero column alone still yields a Location.
func parserLocation(item parser.Diagnostic) *finding.Location {
	if item.Line == 0 && item.Column == 0 {
		return nil
	}
	return &finding.Location{Line: item.Line, Column: item.Column}
}

// parseWithProjectContext parses the discovered files, plus any package siblings a project rule needs to be right.
//
// The two unit sets are returned separately because only the discovered files are reportable: a sibling is read to
// prove a symbol is used, never to be scanned in its own right.
//
// discovery holds the reportable files, root and opts go to projectContextFiles to pick siblings, and opts.DeepScanBudget bounds each parse.
// It returns the discovered units, the project units (the same slice when no sibling is added), and parse diagnostics plus sibling-only ones.
// It returns an error with nil slices when projectContextFiles fails or ctx is done after the discovered files are parsed.
func parseWithProjectContext(ctx context.Context, root string, opts Options, discovery source.Result) ([]parser.Unit, []parser.Unit, []parser.Diagnostic, error) {
	projectFiles, err := projectContextFiles(root, opts, discovery.Files)
	// A failure gathering sibling files for package context stops the run here, before any file is parsed.
	if err != nil {
		return nil, nil, nil, err
	}

	units, parseDiagnostics := parser.ParseWithBudget(discovery.Files, parserBudget(opts.DeepScanBudget))

	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}

	projectUnits := units

	// When siblings were added for package context, surface their parse and read failures rather than risk a silent false positive.
	//
	// A sibling read only for package context can hide evidence a project rule needs; an unparsed caller makes a used symbol look dead.
	// Primary-file diagnostics are reported by the caller, so only context-only entries are added here.
	if !sameSourceFileSet(discovery.Files, projectFiles) {
		var projectParseDiagnostics []parser.Diagnostic

		projectUnits, projectParseDiagnostics = parser.ParseWithBudget(projectFiles, parserBudget(opts.DeepScanBudget))
		parseDiagnostics = append(parseDiagnostics, contextOnlyParseDiagnostics(projectParseDiagnostics, discovery.Files)...)
	}

	return units, projectUnits, parseDiagnostics, nil
}
