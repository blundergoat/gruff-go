// Package analysis defines the gruff-go analysis report contract.
// It combines source discovery, parser diagnostics, rule findings, filtering,
// scoring, and metadata into the stable outputs used by the CLI, dashboard,
// baselines, and downstream tooling.
package analysis

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
	"github.com/blundergoat/gruff-go/internal/scoring"
)

// SchemaVersion identifies the stable cross-port analysis report schema.
const SchemaVersion = "gruff.analysis.v3"

// SummarySchemaVersion identifies the strict projection of SchemaVersion that
// omits only the per-finding array.
const SummarySchemaVersion = "gruff.summary.v3"

// Diagnostic describes an operationally fatal, non-finding failure encountered
// while building a report.
type Diagnostic struct {
	// DiagnosticType is the stable machine identifier when the message has a named contract.
	DiagnosticType string `json:"diagnosticType,omitempty"`
	// Stage names the pipeline phase (discovery, parse, baseline, diff) that emitted this diagnostic.
	Stage string `json:"stage"`
	// Message is the human-readable description of the problem.
	Message string `json:"message"`
	// File is the project-relative path the diagnostic relates to, if any.
	File string `json:"file,omitempty"`
	// Location pinpoints the line and column inside File when known.
	Location *finding.Location `json:"location,omitempty"`
	// Severity is descriptive and currently always error; diagnostic presence,
	// rather than this value, resolves the run to exit code 2.
	Severity finding.Severity `json:"severity"`
	// InvalidatesRun is false only for visible degradation diagnostics; nil preserves legacy fatal semantics.
	InvalidatesRun *bool `json:"invalidatesRun,omitempty"`
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
	// Suppressions is the sensitive-exclusion audit: one row per configured
	// entry, including entries that matched nothing.
	Suppressions []SuppressionSummary `json:"suppressions"`
	// Score holds the grade and pillar breakdown produced by the scoring engine.
	Score scoring.Score `json:"score"`
	// Rules lists every rule definition active for the run.
	Rules []rule.Definition `json:"rules"`
	// Paths lists files scanned, skipped, and missing during discovery.
	Paths Paths `json:"paths"`
	// Diagnostics carries fatal operational failures (e.g. parse errors); any
	// entry resolves the run to exit code 2.
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
	// DiagnosticsCount totals the fatal operational failures emitted during the run.
	DiagnosticsCount int `json:"diagnosticsCount"`
	// FindingsCount totals the rule findings retained after filtering.
	FindingsCount int `json:"findingsCount"`
	// CountsBySeverity buckets the finding count by severity label.
	CountsBySeverity map[string]int `json:"countsBySeverity"`
	// CountsByPillar buckets the finding count by quality pillar.
	CountsByPillar map[string]int `json:"countsByPillar"`
	// ExitCode is the resolved CLI exit code (0 clean, 1 above-threshold, 2 fatal diagnostic).
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
	// Generated is true when this run wrote the baseline rather than compared against one.
	Generated bool `json:"generated"`
	// Source is how the path was chosen: "explicit" when the user named it, "default" when it was discovered.
	Source string `json:"source"`
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

// BaselineEntry is a report-shaped resolved baseline entry: a reviewed identity
// with no live location whose recorded count exceeds what the run found.
type BaselineEntry struct {
	// RuleID is the rule whose finding was resolved.
	RuleID string `json:"ruleId"`
	// File is the repo-relative path the resolved finding targeted.
	File string `json:"file"`
	// Identity is the ratified line-free identity of the resolved occurrence.
	Identity string `json:"identity"`
	// Subject is the identity's subject, so a reader sees what was reviewed.
	Subject string `json:"subject,omitempty"`
	// Count is how many reviewed occurrences of Identity are no longer present.
	Count int `json:"count"`
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
	// rather than Severity so None ("never fail on findings") is representable.
	FailOn finding.FailThreshold
	// IncludeIgnored is true when the run intentionally crossed .gitignore boundaries.
	IncludeIgnored bool
	// Scanned is the project-relative file list that survived discovery filtering.
	Scanned []string
	// Skipped is the discovery list of excluded paths plus their reasons.
	Skipped []SkippedPath
	// Missing names user-requested paths that did not exist on disk.
	Missing []string
	// Diagnostics is the accumulated set of fatal operational failures from all
	// analysis stages.
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
	// Suppressions is the audit row set produced by ApplySensitiveExclusions.
	Suppressions []SuppressionSummary
}

// NewReport assembles a deterministic report from analysis inputs.
func NewReport(input ReportInput) Report {
	scanned := nonNilStrings(input.Scanned)
	skipped := nonNilSkipped(input.Skipped)
	ignoredPaths := ignoredPathProjection(skipped)
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
			Version: "0.5.0",
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
		Suppressions:    nonNilSuppressions(input.Suppressions),
		Score:           scoring.Calculate(findings, evaluatedFileCount(scanned, diagnostics), ruleBackedPillars(definitions)...),
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

// nonNilSuppressions returns an empty audit slice instead of nil, so the report's
// suppressions key always serialises as an array for machine consumers.
func nonNilSuppressions(summaries []SuppressionSummary) []SuppressionSummary {
	if summaries == nil {
		return []SuppressionSummary{}
	}
	return summaries
}

// evaluatedFileCount returns the ratified scoring denominator: Go source files that survived the
// ignore rules and actually parsed. A file that failed to parse reached no rule, so counting it
// would divide real findings by files nothing was ever evaluated in, and an all-unparsable scan
// would report a perfect grade — which is exactly the outcome the applicability contract forbids.
// This is deliberately not len(Paths.Scanned), which also counts raw-text inputs such as README.md.
func evaluatedFileCount(scanned []string, diagnostics []Diagnostic) int {
	failed := map[string]struct{}{}
	// One file can emit several parse diagnostics, so path identity keeps the exclusion file-based.
	for _, diagnostic := range diagnostics {
		if diagnostic.Stage == "parse" && diagnostic.File != "" {
			failed[diagnostic.File] = struct{}{}
		}
	}
	count := 0
	for _, scannedPath := range scanned {
		if _, unparsed := failed[scannedPath]; unparsed {
			continue
		}
		if strings.EqualFold(path.Ext(scannedPath), ".go") {
			count++
		}
	}
	return count
}

// ruleBackedPillars returns each primary area represented in the rule catalogue.
// Reports use the set so clean areas still count toward the user's headline score.
func ruleBackedPillars(definitions []rule.Definition) []finding.Pillar {
	uniquePillars := map[finding.Pillar]struct{}{}
	// A configured-off rule still represents a product area in the published catalogue.
	for _, definition := range definitions {
		uniquePillars[definition.Pillar] = struct{}{}
	}
	pillars := make([]finding.Pillar, 0, len(uniquePillars))
	// Convert the set to a stable value list for deterministic report construction.
	for pillar := range uniquePillars {
		pillars = append(pillars, pillar)
	}
	slices.Sort(pillars)
	return pillars
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
// The None sentinel disables only the finding gate; any diagnostic still exits 2.
func ResolveExitCode(diagnostics []Diagnostic, findings []finding.Finding, failOn finding.FailThreshold) int {
	for _, diagnostic := range diagnostics {
		if diagnostic.InvalidatesRun == nil || *diagnostic.InvalidatesRun {
			return 2
		}
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

// ignoredPathProjection extracts the exact bare-path projection of detailed exclusions.
func ignoredPathProjection(skipped []SkippedPath) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range skipped {
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

// MarshalJSON exposes only the canonical v3 machine envelope. Internal report
// fields remain available to human, SARIF, hook, and scoring code without
// becoming accidental top-level JSON aliases.
func (report Report) MarshalJSON() ([]byte, error) {
	payload, err := report.MachineEnvelope()
	if err != nil {
		return nil, err
	}
	return json.Marshal(payload)
}

// MachineEnvelope projects the internal report into the family v3 contract.
func (report Report) MachineEnvelope() (map[string]any, error) {
	parts, err := report.buildMachineEnvelopeParts()
	if err != nil {
		return nil, err
	}
	payload := report.machineBaseEnvelope(parts)
	if err := report.addMachineOptionalSections(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// machineEnvelopeParts groups normalized path-bearing sections until the
// canonical payload is ready to assemble.
type machineEnvelopeParts struct {
	inputs       []string
	findings     []finding.Finding
	diagnostics  []map[string]any
	paths        map[string]any
	suppressions []map[string]any
	score        map[string]any
}

// buildMachineEnvelopeParts normalizes every path-bearing section before the
// report is assembled.
func (report Report) buildMachineEnvelopeParts() (machineEnvelopeParts, error) {
	inputs, err := machinePaths(report.Run.WorkingDirectory, report.Run.Inputs)
	if err != nil {
		return machineEnvelopeParts{}, fmt.Errorf("run inputs: %w", err)
	}
	findings, err := machineFindings(report.Run.WorkingDirectory, report.Findings)
	if err != nil {
		return machineEnvelopeParts{}, err
	}
	diagnostics, err := machineDiagnostics(report.Run.WorkingDirectory, report.Diagnostics)
	if err != nil {
		return machineEnvelopeParts{}, err
	}
	paths, err := report.machinePathPayload()
	if err != nil {
		return machineEnvelopeParts{}, err
	}
	suppressions, err := machineSuppressions(report.Run.WorkingDirectory, report.Suppressions)
	if err != nil {
		return machineEnvelopeParts{}, err
	}
	score, err := machineScore(report.Run.WorkingDirectory, report.Score)
	if err != nil {
		return machineEnvelopeParts{}, err
	}
	return machineEnvelopeParts{
		inputs:       inputs,
		findings:     findings,
		diagnostics:  diagnostics,
		paths:        paths,
		suppressions: suppressions,
		score:        score,
	}, nil
}

// machineBaseEnvelope assembles the required v3 sections from normalized
// values without adding feature-specific optional sections.
func (report Report) machineBaseEnvelope(parts machineEnvelopeParts) map[string]any {
	run := map[string]any{
		"failOn":      report.Run.FailOn,
		"format":      report.Run.Format,
		"inputs":      parts.inputs,
		"projectRoot": ".",
	}
	if report.Run.IncludeIgnored {
		run["includeIgnored"] = true
	}
	severity := report.Summary.CountsBySeverity
	summary := map[string]any{
		"analysedFiles": report.Summary.FilesScanned,
		"diagnostics":   len(report.Diagnostics),
		"exitCode":      report.Summary.ExitCode,
		"findings": map[string]int{
			"advisory": severity[string(finding.SeverityAdvisory)],
			"warning":  severity[string(finding.SeverityWarning)],
			"error":    severity[string(finding.SeverityError)],
			"total":    report.Summary.FindingsCount,
		},
		"findingsByPillar": report.Summary.CountsByPillar,
		"ignoredPaths":     len(report.Paths.IgnoredPaths),
		"missingPaths":     len(report.Paths.Missing),
		"skippedFiles":     len(report.Paths.Skipped),
		"extensions": map[string]any{
			"go": map[string]any{
				"summary": map[string]any{
					"parserMode":         report.Summary.ParserMode,
					"typeLoadingEnabled": report.Summary.TypeLoadingEnabled,
				},
			},
		},
	}
	if report.SuppressedCount != nil {
		summary["suppressedFindings"] = *report.SuppressedCount
	}
	payload := map[string]any{
		"schemaVersion": SchemaVersion,
		"tool":          report.Tool,
		"run":           run,
		"summary":       summary,
		"score":         parts.score,
		"diagnostics":   parts.diagnostics,
		"findings":      parts.findings,
		"paths":         parts.paths,
		"suppressions":  parts.suppressions,
	}
	return payload
}

// addMachineOptionalSections attaches native sections only when their source
// feature was active for this run.
func (report Report) addMachineOptionalSections(payload map[string]any) error {
	baseline, ok, err := report.machineBaseline()
	if err != nil {
		return err
	}
	if ok {
		payload["baseline"] = baseline
	}
	diff, ok, err := report.machineDiff()
	if err != nil {
		return err
	}
	if ok {
		payload["diff"] = diff
	}
	if report.DisplayFilter.Applied {
		displayFilter := map[string]any{
			"applied":        true,
			"excludePillars": nonNilStrings(report.DisplayFilter.ExcludePillars),
			"excludeRules":   nonNilStrings(report.DisplayFilter.ExcludeRules),
			"hiddenFindings": report.DisplayFilter.HiddenFindings,
			"includePillars": nonNilStrings(report.DisplayFilter.IncludePillars),
			"includeRules":   nonNilStrings(report.DisplayFilter.IncludeRules),
		}
		if report.DisplayFilter.Caveat != "" {
			displayFilter["caveat"] = report.DisplayFilter.Caveat
		}
		payload["displayFilter"] = displayFilter
	}
	if len(report.Rules) > 0 {
		payload["extensions"] = map[string]any{
			"go": map[string]any{
				"topLevel": map[string]any{"rules": report.Rules},
			},
		}
	}
	return nil
}

// MachineSummary returns the sole permitted compact projection: v3 analysis
// without findings and with its summary schema identifier.
func (report Report) MachineSummary() (map[string]any, error) {
	payload, err := report.MachineEnvelope()
	if err != nil {
		return nil, err
	}
	delete(payload, "findings")
	payload["schemaVersion"] = SummarySchemaVersion
	return payload, nil
}

// machinePathPayload projects analysed, skipped, ignored, and missing paths
// into the canonical v3 path section.
func (report Report) machinePathPayload() (map[string]any, error) {
	ignored, err := machinePaths(report.Run.WorkingDirectory, report.Paths.IgnoredPaths)
	if err != nil {
		return nil, fmt.Errorf("ignored paths: %w", err)
	}
	missing, err := machinePaths(report.Run.WorkingDirectory, report.Paths.Missing)
	if err != nil {
		return nil, fmt.Errorf("missing paths: %w", err)
	}
	scanned, err := machinePaths(report.Run.WorkingDirectory, report.Paths.Scanned)
	if err != nil {
		return nil, fmt.Errorf("scanned paths: %w", err)
	}
	details := make([]map[string]any, 0, len(report.Paths.Skipped))
	for _, skipped := range report.Paths.Skipped {
		path, pathErr := machinePath(report.Run.WorkingDirectory, skipped.Path)
		if pathErr != nil {
			return nil, fmt.Errorf("skipped path: %w", pathErr)
		}
		detail := map[string]any{"path": path, "reason": skipped.Reason, "source": skipped.Source}
		if skipped.Pattern != "" {
			detail["pattern"] = skipped.Pattern
		}
		details = append(details, detail)
	}
	return map[string]any{
		"analysedFiles": report.Summary.FilesScanned,
		"details":       details,
		"ignoredPaths":  ignored,
		"missingPaths":  missing,
		"extensions": map[string]any{
			"go": map[string]any{
				"paths": map[string]any{"scanned": scanned},
			},
		},
	}, nil
}

// machineBaseline projects an applied baseline while preserving its native
// matching results and optional detail lists.
func (report Report) machineBaseline() (map[string]any, bool, error) {
	if !report.Baseline.Applied {
		return nil, false, nil
	}
	payload := map[string]any{
		"applied":            true,
		"entries":            report.Baseline.Entries,
		"newFindings":        report.Baseline.NewFindings,
		"resolvedFindings":   report.Baseline.ResolvedFindings,
		"staleEntries":       report.Baseline.StaleEntries,
		"suppressedFindings": report.Baseline.SuppressedFindings,
		"unchangedFindings":  report.Baseline.UnchangedFindings,
	}
	if report.Baseline.Path != "" {
		path, err := machinePath(report.Run.WorkingDirectory, report.Baseline.Path)
		if err != nil {
			return nil, false, fmt.Errorf("baseline path: %w", err)
		}
		payload["path"] = path
	}
	if report.Baseline.Show {
		unchanged, err := machineFindings(report.Run.WorkingDirectory, report.Baseline.Unchanged)
		if err != nil {
			return nil, false, err
		}
		resolved := make([]BaselineEntry, len(report.Baseline.Resolved))
		copy(resolved, report.Baseline.Resolved)
		for index := range resolved {
			path, err := machinePath(report.Run.WorkingDirectory, resolved[index].File)
			if err != nil {
				return nil, false, fmt.Errorf("resolved baseline path: %w", err)
			}
			resolved[index].File = path
		}
		payload["unchanged"] = unchanged
		payload["resolved"] = resolved
	}
	return payload, true, nil
}

// machineDiff projects active changed-region metadata without recalculating
// the native diff result.
func (report Report) machineDiff() (map[string]any, bool, error) {
	if !report.Diff.Enabled {
		return nil, false, nil
	}
	changedFiles, err := machinePaths(report.Run.WorkingDirectory, report.Diff.ChangedFiles)
	if err != nil {
		return nil, false, fmt.Errorf("diff paths: %w", err)
	}
	payload := map[string]any{
		"base":             report.Diff.Base,
		"changedFileCount": len(changedFiles),
		"changedFiles":     changedFiles,
		"enabled":          true,
		"filteredFindings": report.Diff.FilteredFindings,
	}
	if report.Diff.Caveat != "" {
		payload["caveat"] = report.Diff.Caveat
	}
	return payload, true, nil
}

// machineFindings copies findings and normalizes only their serialized paths,
// preserving every native identity field.
func machineFindings(root string, values []finding.Finding) ([]finding.Finding, error) {
	out := make([]finding.Finding, len(values))
	copy(out, values)
	for index := range out {
		path, err := machinePath(root, out[index].File)
		if err != nil {
			return nil, fmt.Errorf("finding path: %w", err)
		}
		out[index].File = path
	}
	return out, nil
}

// machineDiagnostics projects native run diagnostics in their existing order.
func machineDiagnostics(root string, values []Diagnostic) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(values))
	for _, diagnostic := range values {
		payload, err := machineDiagnostic(root, diagnostic)
		if err != nil {
			return nil, err
		}
		out = append(out, payload)
	}
	return out, nil
}

// machineDiagnostic projects one diagnostic and keeps native-only location
// detail under the Go extension namespace.
func machineDiagnostic(root string, diagnostic Diagnostic) (map[string]any, error) {
	diagnosticType := diagnostic.DiagnosticType
	if diagnosticType == "" {
		diagnosticType = diagnostic.Stage
	}
	if diagnosticType == "" {
		diagnosticType = "analysis"
	}
	payload := map[string]any{
		"type":           diagnosticType,
		"message":        diagnostic.Message,
		"invalidatesRun": diagnostic.InvalidatesRun == nil || *diagnostic.InvalidatesRun,
	}
	if diagnostic.File != "" {
		path, err := machinePath(root, diagnostic.File)
		if err != nil {
			return nil, fmt.Errorf("diagnostic path: %w", err)
		}
		payload["file"] = path
	}
	if diagnostic.Stage != "" {
		payload["stage"] = diagnostic.Stage
	}
	if diagnostic.Severity != "" {
		payload["severity"] = diagnostic.Severity
	}
	addMachineDiagnosticLocation(payload, diagnostic.Location)
	return payload, nil
}

// addMachineDiagnosticLocation attaches available line data to the core
// diagnostic and preserves richer coordinates as a Go extension.
func addMachineDiagnosticLocation(payload map[string]any, source *finding.Location) {
	if source == nil {
		return
	}
	location := map[string]int{}
	if source.Line > 0 {
		payload["line"] = source.Line
		location["line"] = source.Line
	}
	if source.Column > 0 {
		location["column"] = source.Column
	}
	if source.EndLine > 0 {
		location["endLine"] = source.EndLine
	}
	if len(location) > 0 {
		payload["extensions"] = map[string]any{
			"go": map[string]any{"diagnostic": map[string]any{"location": location}},
		}
	}
}

// machineSuppressions normalizes suppression scopes while preserving audit
// counts and user-supplied reasons.
func machineSuppressions(root string, values []SuppressionSummary) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(values))
	for _, suppression := range values {
		paths, err := machinePaths(root, suppression.Paths)
		if err != nil {
			return nil, fmt.Errorf("suppression paths: %w", err)
		}
		payload := map[string]any{
			"index":      suppression.Index,
			"rule":       suppression.Rule,
			"paths":      paths,
			"reason":     suppression.Reason,
			"suppressed": suppression.Suppressed,
		}
		if suppression.Symbol != nil && *suppression.Symbol != "" {
			payload["symbol"] = *suppression.Symbol
		}
		out = append(out, payload)
	}
	return out, nil
}

// machineScore normalizes offender paths without changing any score produced
// by the native scoring engine.
func machineScore(root string, score scoring.Score) (map[string]any, error) {
	topOffenders := make([]scoring.FileScore, len(score.TopOffender))
	copy(topOffenders, score.TopOffender)
	for index := range topOffenders {
		path, err := machinePath(root, topOffenders[index].File)
		if err != nil {
			return nil, fmt.Errorf("score path: %w", err)
		}
		topOffenders[index].File = path
	}
	return map[string]any{
		"composite":                   map[string]any{"grade": score.Grade, "score": score.Composite},
		"evaluatedFiles":              score.EvaluatedFiles,
		"scoredPillars":               score.ScoredPillars,
		"clusters":                    score.Clusters,
		"ruleAttribution":             score.RuleAttribution,
		"pillars":                     score.PillarDetails,
		"topOffenders":                topOffenders,
		"coverage":                    score.Coverage,
		"complexityDistribution":      score.ComplexityDistribution,
		"complexityDistributionScope": score.ComplexityDistributionScope,
	}, nil
}

// machinePaths converts an ordered path list to project-relative POSIX form.
func machinePaths(root string, values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, value := range values {
		path, err := machinePath(root, value)
		if err != nil {
			return nil, err
		}
		out = append(out, path)
	}
	return out, nil
}

// machinePath converts one path to project-relative POSIX form and rejects
// values outside the report root.
func machinePath(root, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("empty path is not portable")
	}
	if len(value) >= 2 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' {
		return "", fmt.Errorf("Windows drive path %q is outside the project contract", value)
	}
	cleaned := filepath.Clean(value)
	if filepath.IsAbs(cleaned) {
		base := root
		if base == "" {
			return "", fmt.Errorf("absolute path %q has no project root", value)
		}
		relative, err := filepath.Rel(base, cleaned)
		if err != nil {
			return "", fmt.Errorf("path %q cannot be made project-relative: %w", value, err)
		}
		cleaned = relative
	}
	portable := filepath.ToSlash(cleaned)
	if portable == ".." || strings.HasPrefix(portable, "../") || strings.HasPrefix(portable, "/") || strings.Contains(portable, "\\") {
		return "", fmt.Errorf("path %q is outside the project root", value)
	}
	return portable, nil
}
