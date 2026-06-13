// Package analysis defines the gruff-go analysis report contract.
// It combines source discovery, parser diagnostics, rule findings, filtering,
// scoring, and metadata into the stable outputs used by the CLI, dashboard,
// baselines, and downstream tooling.
package analysis

import (
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
	"github.com/blundergoat/gruff-go/internal/scoring"
)

// SchemaVersion identifies the stable cross-port analysis report schema.
const SchemaVersion = "gruff.analysis.v2"

// Diagnostic describes a non-finding problem encountered while building a report.
type Diagnostic struct {
	// Stage names the pipeline phase (discovery, parser, scoring) that emitted this diagnostic.
	Stage string `json:"stage"`
	// Message is the human-readable description of the problem.
	Message string `json:"message"`
	// File is the project-relative path the diagnostic relates to, if any.
	File string `json:"file,omitempty"`
	// Location pinpoints the line and column inside File when known.
	Location *finding.Location `json:"location,omitempty"`
	// Severity drives whether the run aborts and which exit code it returns.
	Severity finding.Severity `json:"severity"`
}

// Report is the full structured result of one analysis run.
type Report struct {
	// SchemaVersion pins the report document contract consumers can rely on.
	SchemaVersion string `json:"schemaVersion"`
	// Tool identifies the scanner binary and version that produced the report.
	Tool Tool `json:"tool"`
	// Run captures invocation flags and the working directory used.
	Run RunMetadata `json:"run"`
	// Summary aggregates counts and the resolved exit code for the run.
	Summary Summary `json:"summary"`
	// Baseline records how a loaded baseline file suppressed findings.
	Baseline BaselineSummary `json:"baseline"`
	// Diff records changed-line filtering applied against a git base.
	Diff DiffSummary `json:"diff"`
	// SuppressedCount counts findings excluded as outside the changed region.
	SuppressedCount *int `json:"suppressedCount,omitempty"`
	// DisplayFilter records presentation-only filters that hid findings.
	DisplayFilter DisplayFilterSummary `json:"displayFilter"`
	// Score holds the grade and pillar breakdown produced by the scoring engine.
	Score scoring.Score `json:"score"`
	// Rules lists every rule definition active for the run.
	Rules []rule.Definition `json:"rules"`
	// Paths lists files scanned, skipped, and missing during discovery.
	Paths Paths `json:"paths"`
	// Diagnostics carries non-finding problems (e.g. parse errors) emitted during the run.
	Diagnostics []Diagnostic `json:"diagnostics"`
	// Findings is the sorted list of rule findings produced by the run.
	Findings []finding.Finding `json:"findings"`
}

// Tool identifies the scanner binary that produced a report.
type Tool struct {
	// Name is the scanner binary name ("gruff-go").
	Name string `json:"name"`
	// Version is the released version literal embedded in the binary.
	Version string `json:"version"`
}

// RunMetadata records invocation settings that shaped a report.
type RunMetadata struct {
	// WorkingDirectory is the absolute root the run was invoked against.
	WorkingDirectory string `json:"workingDirectory"`
	// Inputs lists the explicit project-relative paths requested on the command line.
	Inputs []string `json:"inputs"`
	// Format is the rendered output format (text, json, sarif, etc.).
	Format string `json:"format"`
	// FailOn names the severity that triggers exit code 1.
	FailOn string `json:"failOn"`
	// IncludeIgnored is true when the run scanned paths that .gitignore would otherwise skip.
	IncludeIgnored bool `json:"includeIgnored,omitempty"`
}

// Summary aggregates high-level counts and exit status for a report.
type Summary struct {
	// FilesScanned is the number of source files actually analysed.
	FilesScanned int `json:"filesScanned"`
	// FilesSkipped is the number of discovered files that were excluded before scanning.
	FilesSkipped int `json:"filesSkipped"`
	// DiagnosticsCount totals the non-finding problems emitted during the run.
	DiagnosticsCount int `json:"diagnosticsCount"`
	// FindingsCount totals the rule findings retained after filtering.
	FindingsCount int `json:"findingsCount"`
	// CountsBySeverity buckets the finding count by severity label.
	CountsBySeverity map[string]int `json:"countsBySeverity"`
	// CountsByPillar buckets the finding count by quality pillar.
	CountsByPillar map[string]int `json:"countsByPillar"`
	// ExitCode is the resolved CLI exit code (0 clean, 1 above-threshold, 2 internal diagnostic).
	ExitCode int `json:"exitCode"`
	// ParserMode names the parser strategy used (currently always parser-only).
	ParserMode string `json:"parserMode"`
	// TypeLoadingEnabled is true if go/types loading was used; false in parser-only mode.
	TypeLoadingEnabled bool `json:"typeLoadingEnabled"`
}

// BaselineSummary records how a baseline affected findings, classified into the
// three states from ADR-012. The count fields are always emitted (additive);
// the Unchanged/Resolved detail arrays render only when Show is set (the
// --baseline-show flag), so default JSON stays compact and text/HTML stay
// byte-identical to pre-M24 output.
type BaselineSummary struct {
	// Applied is true when a baseline file was successfully loaded and used.
	Applied bool `json:"applied"`
	// Path is the project-relative location of the baseline file, if applied.
	Path string `json:"path,omitempty"`
	// Entries is the total number of suppression entries declared in the baseline file.
	Entries int `json:"entries"`
	// SuppressedFindings is the count of findings the baseline hid this run (== UnchangedFindings).
	SuppressedFindings int `json:"suppressedFindings"`
	// StaleEntries is the count of baseline entries that matched no current finding (== ResolvedFindings).
	StaleEntries int `json:"staleEntries"`
	// NewFindings counts current findings absent from the baseline (the gated set M26 fails on).
	NewFindings int `json:"newFindings"`
	// UnchangedFindings counts current findings the baseline matched and suppressed.
	UnchangedFindings int `json:"unchangedFindings"`
	// ResolvedFindings counts baseline entries that no current finding matched (fixed since the baseline).
	ResolvedFindings int `json:"resolvedFindings"`
	// Unchanged lists the suppressed findings; populated and rendered only under --baseline-show.
	Unchanged []finding.Finding `json:"unchanged,omitempty"`
	// Resolved lists the resolved baseline entries; populated and rendered only under --baseline-show.
	Resolved []BaselineEntry `json:"resolved,omitempty"`
	// Show is the --baseline-show directive; it gates rendering of the detail arrays and is never serialised.
	Show bool `json:"-"`
}

// BaselineEntry is a report-shaped resolved baseline entry: a finding identity
// (rule, file, fingerprint) with no live location, fixed since the baseline.
type BaselineEntry struct {
	// RuleID is the rule whose finding was resolved.
	RuleID string `json:"ruleId"`
	// File is the repo-relative path the resolved finding targeted.
	File string `json:"file"`
	// Fingerprint is the stable identity hash of the resolved finding.
	Fingerprint string `json:"fingerprint"`
}

// DiffSummary records changed-line filtering applied to findings.
type DiffSummary struct {
	// Enabled is true when --diff-base was honoured and changed-line filtering ran.
	Enabled bool `json:"enabled"`
	// Base is the git ref or commit findings were diffed against.
	Base string `json:"base,omitempty"`
	// ChangedFiles is the sorted set of project-relative files in the diff.
	ChangedFiles []string `json:"changedFiles"`
	// FilteredFindings counts how many findings the diff filter dropped from the report.
	FilteredFindings int `json:"filteredFindings"`
	// Caveat carries any user-facing note about diff resolution gaps.
	Caveat string `json:"caveat,omitempty"`
}

// DisplayFilterSummary records presentation-only finding filters.
type DisplayFilterSummary struct {
	// Applied is true when one or more presentation filters narrowed the rendered output.
	Applied bool `json:"applied"`
	// IncludeRules limits rendered findings to the listed rule IDs.
	IncludeRules []string `json:"includeRules"`
	// ExcludeRules hides findings whose rule ID matches an entry.
	ExcludeRules []string `json:"excludeRules"`
	// IncludePillars limits rendered findings to the listed pillars.
	IncludePillars []string `json:"includePillars"`
	// ExcludePillars hides findings whose pillar matches an entry.
	ExcludePillars []string `json:"excludePillars"`
	// HiddenFindings counts how many real findings the display filter suppressed from output.
	HiddenFindings int `json:"hiddenFindings"`
	// Caveat carries any user-facing note when the filter changed the rendered totals.
	Caveat string `json:"caveat,omitempty"`
}

// Paths lists files scanned, skipped, and missing during discovery.
type Paths struct {
	// Scanned is the sorted set of project-relative files that reached the analysers.
	Scanned []string `json:"scanned"`
	// IgnoredPaths lists config paths.ignore matches as bare strings for cross-port consumers.
	IgnoredPaths []string `json:"ignoredPaths"`
	// Skipped lists discovered files that were excluded together with the reason.
	Skipped []SkippedPath `json:"skipped"`
	// Missing lists user-requested inputs that did not exist on disk.
	Missing []string `json:"missing"`
}

// SkippedPath records why a project-relative path was excluded.
type SkippedPath struct {
	// Path is the project-relative file that was excluded from scanning.
	Path string `json:"path"`
	// Reason is the human-readable explanation (gitignore, vendored directory, etc.).
	Reason string `json:"reason"`
	// Source classifies the deciding ignore layer: config | gitignore | default | generated.
	// Additive (omitempty) so existing {path,reason} JSON/SARIF consumers keep working.
	Source string `json:"source,omitempty"`
	// Pattern is the exact config paths.ignore glob that matched; set only when Source is config.
	Pattern string `json:"pattern,omitempty"`
}

// ReportInput contains inputs needed to assemble a Report.
type ReportInput struct {
	// Root is the absolute working directory the run was launched from.
	Root string
	// Inputs lists the user-supplied project-relative paths the run targeted.
	Inputs []string
	// Format is the rendered output format requested on the CLI.
	Format string
	// FailOn is the resolved threshold that maps to exit code 1. FailThreshold
	// rather than Severity so None ("never fail") is representable.
	FailOn finding.FailThreshold
	// IncludeIgnored is true when the run intentionally crossed .gitignore boundaries.
	IncludeIgnored bool
	// Scanned is the project-relative file list that survived discovery filtering.
	Scanned []string
	// Skipped is the discovery list of excluded paths plus their reasons.
	Skipped []SkippedPath
	// Missing names user-requested paths that did not exist on disk.
	Missing []string
	// Diagnostics is the accumulated set of non-finding problems from discovery and parsing.
	Diagnostics []Diagnostic
	// Findings is the accumulated rule findings before exit-code resolution.
	Findings []finding.Finding
	// Definitions is the active rule registry's metadata, included in the report.
	Definitions []rule.Definition
	// Baseline is the pre-computed BaselineSummary from any loaded baseline.
	Baseline BaselineSummary
	// Diff is the pre-computed DiffSummary when --diff-base ran.
	Diff DiffSummary
	// SuppressedCount is present when changed-region filtering ran.
	SuppressedCount *int
}

// NewReport assembles a deterministic report from analysis inputs.
func NewReport(input ReportInput) Report {
	scanned := nonNilStrings(input.Scanned)
	skipped := nonNilSkipped(input.Skipped)
	ignoredPaths := configIgnoredPaths(skipped)
	missing := nonNilStrings(input.Missing)
	diagnostics := nonNilDiagnostics(input.Diagnostics)
	findings := nonNilFindings(input.Findings)
	definitions := nonNilDefinitions(input.Definitions)
	input.Diff.ChangedFiles = nonNilStrings(input.Diff.ChangedFiles)
	exitCode := ResolveExitCode(diagnostics, findings, input.FailOn)
	report := Report{
		SchemaVersion: SchemaVersion,
		Tool: Tool{
			Name:    "gruff-go",
			Version: "0.4.0",
		},
		Run: RunMetadata{
			WorkingDirectory: input.Root,
			Inputs:           input.Inputs,
			Format:           input.Format,
			FailOn:           string(input.FailOn),
			IncludeIgnored:   input.IncludeIgnored,
		},
		Summary: Summary{
			FilesScanned:       len(scanned),
			FilesSkipped:       len(skipped),
			DiagnosticsCount:   len(diagnostics),
			FindingsCount:      len(findings),
			CountsBySeverity:   countSeverity(findings),
			CountsByPillar:     countPillar(findings),
			ExitCode:           exitCode,
			ParserMode:         "parser-only",
			TypeLoadingEnabled: false,
		},
		Baseline:        input.Baseline,
		Diff:            input.Diff,
		SuppressedCount: input.SuppressedCount,
		Score:           scoring.Calculate(findings),
		Rules:           definitions,
		Paths: Paths{
			Scanned:      scanned,
			IgnoredPaths: ignoredPaths,
			Skipped:      skipped,
			Missing:      missing,
		},
		Diagnostics: diagnostics,
		Findings:    findings,
	}
	SortReport(&report)
	return report
}

// nonNilStrings returns an empty string slice when values is nil.
func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// nonNilSkipped returns an empty skipped-path slice when values is nil.
func nonNilSkipped(values []SkippedPath) []SkippedPath {
	if values == nil {
		return []SkippedPath{}
	}
	return values
}

// nonNilDiagnostics returns an empty diagnostic slice when values is nil.
func nonNilDiagnostics(values []Diagnostic) []Diagnostic {
	if values == nil {
		return []Diagnostic{}
	}
	return values
}

// nonNilFindings returns an empty finding slice when values is nil.
func nonNilFindings(values []finding.Finding) []finding.Finding {
	if values == nil {
		return []finding.Finding{}
	}
	return values
}

// nonNilDefinitions returns an empty rule-definition slice when values is nil.
func nonNilDefinitions(values []rule.Definition) []rule.Definition {
	if values == nil {
		return []rule.Definition{}
	}
	return values
}

// ResolveExitCode returns the CLI exit code implied by diagnostics and findings.
// FailThreshold (not Severity) so the None sentinel disables the gate entirely.
func ResolveExitCode(diagnostics []Diagnostic, findings []finding.Finding, failOn finding.FailThreshold) int {
	if len(diagnostics) > 0 {
		return 2
	}
	for _, item := range findings {
		if failOn.IsTriggeredBy(item.Severity) {
			return 1
		}
	}
	return 0
}

// SortReport orders report collections for deterministic output.
func SortReport(report *Report) {
	slices.Sort(report.Paths.Scanned)
	slices.Sort(report.Paths.IgnoredPaths)
	slices.Sort(report.Paths.Missing)
	slices.SortFunc(report.Paths.Skipped, func(a, b SkippedPath) int {
		if a.Path == b.Path {
			return strings.Compare(a.Reason, b.Reason)
		}
		return strings.Compare(a.Path, b.Path)
	})
	slices.SortFunc(report.Diagnostics, compareDiagnostics)
	slices.SortFunc(report.Findings, rule.CompareFindings)
	slices.SortFunc(report.Rules, func(a, b rule.Definition) int {
		return strings.Compare(a.ID, b.ID)
	})
}

// configIgnoredPaths extracts the bare path list expected by cross-port
// consumers from detailed skipped entries. Only config paths.ignore exclusions
// are listed; git/default/generated skips remain available in paths.skipped.
func configIgnoredPaths(skipped []SkippedPath) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range skipped {
		if item.Source != "config" && item.Reason != "config-ignore" {
			continue
		}
		if _, ok := seen[item.Path]; ok {
			continue
		}
		seen[item.Path] = struct{}{}
		out = append(out, item.Path)
	}
	slices.Sort(out)
	return out
}

// compareDiagnostics orders diagnostics by file, line, stage, and message.
func compareDiagnostics(a, b Diagnostic) int {
	if a.File != b.File {
		return strings.Compare(a.File, b.File)
	}
	if locationLine(a.Location) != locationLine(b.Location) {
		return locationLine(a.Location) - locationLine(b.Location)
	}
	if a.Stage != b.Stage {
		return strings.Compare(a.Stage, b.Stage)
	}
	return strings.Compare(a.Message, b.Message)
}

// locationLine returns zero when a diagnostic has no location.
func locationLine(location *finding.Location) int {
	if location == nil {
		return 0
	}
	return location.Line
}

// countSeverity tallies findings into a map keyed by severity label, pre-populating the three canonical buckets so absent severities still appear with a zero count.
func countSeverity(findings []finding.Finding) map[string]int {
	counts := map[string]int{
		string(finding.SeverityAdvisory): 0,
		string(finding.SeverityWarning):  0,
		string(finding.SeverityError):    0,
	}
	for _, item := range findings {
		counts[string(item.Severity)]++
	}
	return counts
}

// countPillar counts findings by quality pillar.
func countPillar(findings []finding.Finding) map[string]int {
	counts := map[string]int{}
	for _, item := range findings {
		counts[string(item.Pillar)]++
	}
	return counts
}
