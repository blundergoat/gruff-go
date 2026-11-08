// Package analysis builds the Report an analysis run produces, from its exit code to its JSON envelope.
//
// It combines source discovery, parser diagnostics, rule findings, filtering, scoring and metadata into one sorted report.
// The CLI, dashboard, baselines and downstream tooling all read that report, so its JSON shape is a cross-port contract.
package analysis

import (
	"encoding/json"
	"errors"
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
//
// Every full JSON report carries it as schemaVersion; MachineSummary swaps in SummarySchemaVersion for the compact projection.
const SchemaVersion = "gruff.analysis.v3"

// SummarySchemaVersion identifies the strict projection of SchemaVersion that omits only the per-finding array.
//
// MachineSummary writes it in place of SchemaVersion, so a consumer can tell a summary from a full report before reading further.
const SummarySchemaVersion = "gruff.summary.v3"

// Diagnostic describes an operational failure or visible degradation encountered while building a report, never a rule finding.
//
// The user sees each one in the report's diagnostics list, and the summary counts them all.
// InvalidatesRun decides whether it forces exit code 2: a config that cannot load does, a degradation notice marked false does not.
type Diagnostic struct {
	// DiagnosticType is the stable machine identifier when the message has a named contract.
	DiagnosticType string `json:"diagnosticType,omitempty"`
	// Stage names the pipeline phase that emitted this diagnostic, such as config, discovery, parse, baseline or diff.
	Stage string `json:"stage"`
	// Message is the human-readable description of the problem.
	Message string `json:"message"`
	// File is the path the diagnostic relates to, if any; machine JSON omits it when it lies outside the project root.
	File string `json:"file,omitempty"`
	// Location pinpoints the line and column inside File when known.
	Location *finding.Location `json:"location,omitempty"`
	// Severity labels how serious the diagnostic is; InvalidatesRun, not Severity, decides whether the run exits 2.
	Severity finding.Severity `json:"severity"`
	// InvalidatesRun is false only for visible degradation diagnostics; nil preserves legacy fatal semantics.
	InvalidatesRun *bool `json:"invalidatesRun,omitempty"`
}

// Report is the full structured result of one analysis run.
//
// The text, JSON, SARIF, hook and dashboard outputs all read it; NewReport keeps its path, diagnostic, finding and rule lists sorted.
// MarshalJSON publishes only the v3 machine envelope, so internal fields never become accidental top-level JSON keys.
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
	// Diff records the changed-region filtering applied to findings.
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
	// Rules is the rule catalogue from ReportInput.Definitions, sorted by ID; machine JSON publishes it under the Go rules extension.
	Rules []rule.Definition `json:"rules"`
	// Paths lists files scanned, skipped, and missing during discovery.
	Paths Paths `json:"paths"`
	// Diagnostics carries operational failures, such as parse errors, and nonfatal degradation notices.
	// An entry whose InvalidatesRun is nil or true resolves the run to exit code 2.
	Diagnostics []Diagnostic `json:"diagnostics"`
	// Findings is the sorted list of rule findings produced by the run.
	Findings []finding.Finding `json:"findings"`
	// Suppressed holds the findings another tool's comment suppressed. The JSON envelope counts them only in
	// Suppressions; SARIF keeps each as a result marked suppressed (FAMILY-CONTRACT.md section 13c).
	Suppressed []SuppressedFinding `json:"-"`
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
	// WorkingDirectory is the scan root; a report for a run that failed at startup, such as on a bad config, records a dot instead.
	WorkingDirectory string `json:"workingDirectory"`
	// Inputs lists the operands the run recorded; machine JSON converts each to project-relative form or fails the envelope.
	Inputs []string `json:"inputs"`
	// Format is the rendered output format (text, json, sarif, etc.).
	Format string `json:"format"`
	// FailOn names the severity that triggers exit code 1.
	FailOn string `json:"failOn"`
	// IncludeIgnored records whether the run opted into paths .gitignore would otherwise skip, even when none were found.
	IncludeIgnored bool `json:"includeIgnored,omitempty"`
}

// Summary aggregates high-level counts and exit status for a report.
type Summary struct {
	// FilesScanned counts the scanned path list, including raw-text inputs and files that failed to parse.
	FilesScanned int `json:"filesScanned"`
	// FilesSkipped counts the discovery exclusion records in Paths.Skipped.
	FilesSkipped int `json:"filesSkipped"`
	// DiagnosticsCount counts every diagnostic the run emitted, nonfatal degradation notices included.
	DiagnosticsCount int `json:"diagnosticsCount"`
	// FindingsCount totals the rule findings retained after filtering.
	FindingsCount int `json:"findingsCount"`
	// CountsBySeverity buckets the finding count by severity label.
	CountsBySeverity map[string]int `json:"countsBySeverity"`
	// CountsByPillar buckets the finding count by quality pillar.
	CountsByPillar map[string]int `json:"countsByPillar"`
	// ExitCode is the resolved CLI exit code: 0 clean, 1 when a finding reaches the fail-on threshold, 2 when a diagnostic invalidates the run.
	ExitCode int `json:"exitCode"`
	// ParserMode names the parser strategy used (currently always parser-only).
	ParserMode string `json:"parserMode"`
	// TypeLoadingEnabled is true if go/types loading was used; false in parser-only mode.
	TypeLoadingEnabled bool `json:"typeLoadingEnabled"`
}

// BaselineSummary records how a baseline affected findings, classified into the three states from ADR-012.
//
// For an applied baseline, the count fields are additive and always emitted in the machine baseline section.
// The Unchanged and Resolved detail arrays render only when Show is set by --baseline-show, so default output omits them.
type BaselineSummary struct {
	// Applied is true when a baseline file was successfully loaded and used.
	Applied bool `json:"applied"`
	// Generated is true when this run wrote the baseline rather than compared against one.
	Generated bool `json:"generated"`
	// Source labels the baseline explicit or default; the machine baseline section publishes it unchanged.
	Source string `json:"source"`
	// Path is the baseline file location; machine JSON publishes it only for an applied baseline inside the project root.
	Path string `json:"path,omitempty"`
	// Entries is the total number of suppression entries declared in the baseline file.
	Entries int `json:"entries"`
	// SuppressedFindings is the count of findings the baseline hid this run (== UnchangedFindings).
	SuppressedFindings int `json:"suppressedFindings"`
	// StaleEntries equals ResolvedFindings, counting reviewed occurrences no longer present rather than whole entries.
	StaleEntries int `json:"staleEntries"`
	// NewFindings is the count of findings the baseline did not suppress, published as newFindings.
	NewFindings int `json:"newFindings"`
	// UnchangedFindings counts current findings the baseline matched and suppressed.
	UnchangedFindings int `json:"unchangedFindings"`
	// ResolvedFindings counts the reviewed occurrences the baseline match reports as no longer present, published as resolvedFindings.
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
	// Enabled is true when a changed-region scope was resolved and changed-line filtering ran.
	Enabled bool `json:"enabled"`
	// Base names the changed-region source the filtering used, such as a git ref.
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
	// Scanned is the sorted list of files discovery kept for scanning, including any that later failed to parse.
	Scanned []string `json:"scanned"`
	// IgnoredPaths lists every distinct skipped path as a sorted bare string for cross-port consumers, whatever excluded it.
	IgnoredPaths []string `json:"ignoredPaths"`
	// Skipped lists the discovery exclusion records together with their reasons.
	Skipped []SkippedPath `json:"skipped"`
	// Missing lists user-requested inputs that did not exist on disk.
	Missing []string `json:"missing"`
}

// SkippedPath records a path discovery excluded, or a .gitignore whose malformed rules were reported while its valid rules still apply.
type SkippedPath struct {
	// Path is the display path of the file or directory, absolute for an input outside the root; a .gitignore that failed to parse is recorded too.
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
//
// NewReport turns it into the published Report; FailedRunReport fills only the root, format, fail-on threshold and one diagnostic.
type ReportInput struct {
	// Root is the directory machine JSON makes paths project-relative against; FailedRunReport records whatever root its caller passes.
	Root string
	// Inputs lists the run's operands, copied into Run.Inputs; machine JSON converts them to project-relative form.
	Inputs []string
	// Format is the rendered output format requested on the CLI.
	Format string
	// FailOn is the resolved threshold that maps to exit code 1. FailThreshold
	// rather than Severity so None ("never fail on findings") is representable.
	FailOn finding.FailThreshold
	// MinConfidence is the confidence floor the caller resolved; NewReport's exit code does not apply it.
	MinConfidence finding.Confidence
	// FailOnNew asks for exit 1 on any finding the baseline classifies as new; NewReport's exit code does not apply it.
	FailOnNew bool
	// IncludeIgnored records whether the run opted into crossing .gitignore boundaries, copied into Run.IncludeIgnored.
	IncludeIgnored bool
	// Scanned lists the files that survived discovery filtering, as display paths that stay absolute for inputs outside the root.
	Scanned []string
	// Skipped is the discovery list of excluded paths plus their reasons.
	Skipped []SkippedPath
	// Missing names user-requested paths that did not exist on disk.
	Missing []string
	// Diagnostics accumulates operational failures and degradation notices from every analysis stage; the report publishes them all.
	Diagnostics []Diagnostic
	// Findings is the accumulated rule findings before exit-code resolution.
	Findings []finding.Finding
	// Definitions is the rule catalogue's metadata, published in the report's Rules list.
	Definitions []rule.Definition
	// Baseline is the pre-computed BaselineSummary from any loaded baseline.
	Baseline BaselineSummary
	// Diff is the pre-computed DiffSummary when changed-region filtering ran.
	Diff DiffSummary
	// SuppressedCount is present when changed-region filtering ran.
	SuppressedCount *int
	// Suppressions carries configured sensitiveExclusions rows, then built-in test-path and inline rows.
	Suppressions []SuppressionSummary
	// Suppressed is the findings ApplyInlineSuppressions removed, kept for SARIF.
	Suppressed []SuppressedFinding
}

// ConfigErrorDiagnosticType is the type every port publishes when it cannot load the configuration it was given.
//
// FailedRunReport files it under the config stage as a run-invalidating diagnostic, so a machine-format caller sees it with exit code 2.
const ConfigErrorDiagnosticType = "config-error"

// TargetErrorDiagnosticType is the type every port publishes when it refuses the scan targets it was given.
//
// Several targets outside the launch directory, for example, leave no single root to resolve them against.
// FailedRunReport files it under the discovery stage rather than config.
const TargetErrorDiagnosticType = "target-error"

// FailedRunReport builds the envelope a run that could not start still owes a caller who asked for a machine format.
//
// A run that never started has no findings and nothing discovered, so the envelope carries one run-invalidating diagnostic and empty lists.
// Printing only to stderr would leave a JSON consumer with no diagnostic, no type and no run block, where every other port publishes all three.
//
// root is the working directory the report records, format is the requested output format, and message is the diagnostic's text.
// diagnosticType names the diagnostic's type; TargetErrorDiagnosticType sets its stage to discovery, and any other type sets it to config.
// It returns a Report holding only that diagnostic, no findings and no paths, with the default advisory fail-on threshold and an exit code of 2.
func FailedRunReport(root, format, diagnosticType, message string) Report {
	stage := "config"
	// A refused target list fails while the run is choosing what to scan, not while it loads the configuration.
	if diagnosticType == TargetErrorDiagnosticType {
		stage = "discovery"
	}
	return NewReport(ReportInput{
		Root:   root,
		Format: format,
		// The run never reached its gate, so the envelope names the default threshold rather than leaving the
		// contract-required field empty.
		FailOn: finding.FailThresholdAdvisory,
		// InvalidatesRun stays nil, which counts as run-invalidating, so the caller sees exit code 2.
		Diagnostics: []Diagnostic{{
			DiagnosticType: diagnosticType,
			Stage:          stage,
			Message:        message,
			Severity:       finding.SeverityError,
		}},
	})
}

// NewReport assembles a deterministic report from analysis inputs.
//
// input carries the run settings, discovered paths, diagnostics, findings, rule definitions, and the baseline, diff and suppression summaries.
// It returns a sorted Report whose nil path, diagnostic, finding and rule lists become empty.
//
// Its score counts every scanned .go path that no parse-stage diagnostic names, including Go files the deep-scan budget left without an AST.
// Its exit code applies input.FailOn alone through ResolveExitCode, so input.MinConfidence and input.FailOnNew do not affect it.
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
			Version: "0.6.0",
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
		Suppressed:      input.Suppressed,
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

// nonNilSuppressions returns an empty audit slice instead of nil, so machine consumers always read the suppressions key as an array.
//
// summaries holds the suppression audit rows and is returned unchanged when it is not nil.
func nonNilSuppressions(summaries []SuppressionSummary) []SuppressionSummary {
	if summaries == nil {
		return []SuppressionSummary{}
	}
	return summaries
}

// evaluatedFileCount returns the scoring denominator: the scanned Go paths that no parse-stage diagnostic names.
//
// Counting a file no rule reached would dilute findings and give an all-unparsable scan a perfect grade, which the applicability contract forbids.
// This is deliberately not len(Paths.Scanned), which also counts raw-text inputs such as go.mod or a YAML file.
//
// scanned is the discovered file list, and diagnostics excludes every file that a parse-stage diagnostic names.
// Only paths whose extension is .go in any letter case count, and a scan with no such path returns 0.
// A Go file the deep-scan budget left without an AST carries an analysis-stage diagnostic, so it still counts.
func evaluatedFileCount(scanned []string, diagnostics []Diagnostic) int {
	parseFailedFiles := map[string]struct{}{}
	// One file can emit several parse diagnostics, so path identity keeps the exclusion file-based.
	for _, diagnostic := range diagnostics {
		if diagnostic.Stage == "parse" && diagnostic.File != "" {
			parseFailedFiles[diagnostic.File] = struct{}{}
		}
	}
	count := 0
	for _, scannedPath := range scanned {
		if _, unparsed := parseFailedFiles[scannedPath]; unparsed {
			continue
		}
		if strings.EqualFold(path.Ext(scannedPath), ".go") {
			count++
		}
	}
	return count
}

// ruleBackedPillars returns each primary area represented in the rule catalogue.
//
// Reports use the set so clean areas still count toward the user's headline score.
// definitions is the rule catalogue read; each distinct Pillar appears once in sorted order, and an empty catalogue gives an empty slice.
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
//
// The None sentinel disables only the finding gate; any run-invalidating diagnostic still exits 2.
// failOn is the lowest finding severity that exits 1, at any confidence and whatever the baseline status; otherwise the code is 0.
func ResolveExitCode(diagnostics []Diagnostic, findings []finding.Finding, failOn finding.FailThreshold) int {
	return ResolveGatedExitCode(diagnostics, findings, ExitGate{FailOn: failOn, MinConfidence: finding.ConfidenceLow})
}

// ExitGate carries the three dimensions the family contract lets a user gate on.
//
// Severity and confidence are independent floors, and a finding must clear both to trigger the severity check.
// FailOnNew gates a new finding whatever its severity or confidence; it is about review state rather than urgency.
type ExitGate struct {
	// FailOn is the lowest severity that reaches the gate.
	FailOn finding.FailThreshold
	// MinConfidence is the lowest confidence that reaches it, independent of severity.
	MinConfidence finding.Confidence
	// FailOnNew exits 1 for any finding the applied baseline classifies as new, whatever its severity.
	FailOnNew bool
}

// ResolveGatedExitCode decides the exit code under the full family gate.
//
// A run that could not complete still outranks everything: a diagnostic that invalidates the run exits 2 before any
// finding is weighed, because a partial scan's verdict is not a verdict.
//
// It returns 2 when an entry in diagnostics has InvalidatesRun nil or true, otherwise 1 when an entry in findings reaches the gate, else 0.
// A finding reaches gate when gate.FailOnNew is set and its baseline status is new, or when it clears both gate.FailOn and gate.MinConfidence.
func ResolveGatedExitCode(diagnostics []Diagnostic, findings []finding.Finding, gate ExitGate) int {
	for _, diagnostic := range diagnostics {
		if diagnostic.InvalidatesRun == nil || *diagnostic.InvalidatesRun {
			return 2
		}
	}

	for _, item := range findings {
		// The baseline dimension is independent of both floors: a new finding gates whatever its severity.
		if gate.FailOnNew && item.BaselineStatus == "new" {
			return 1
		}

		if gate.FailOn.IsTriggeredBy(item.Severity) && confidenceReachesFloor(item.Confidence, gate.MinConfidence) {
			return 1
		}
	}

	return 0
}

// confidenceRankOf orders the three confidence levels, ranking anything unrecognised highest.
//
// An unrated finding must not slip under a gate, so the safe default is the value that always reaches it.
// It returns 0 for low, 1 for medium, and 2 for high or any other value, including an empty one.
func confidenceRankOf(confidence finding.Confidence) int {
	switch confidence {
	case finding.ConfidenceLow:
		return 0
	case finding.ConfidenceMedium:
		return 1
	default:
		return 2
	}
}

// confidenceReachesFloor reports whether one finding's confidence clears the gate's floor.
//
// findingConfidence is the finding's rated confidence and floor is the gate's minimum, both ranked by confidenceRankOf.
// It reports false only when findingConfidence ranks below floor, so an unrecognised finding confidence always clears it.
func confidenceReachesFloor(findingConfidence, floor finding.Confidence) bool {
	return confidenceRankOf(findingConfidence) >= confidenceRankOf(floor)
}

// SortReport orders report collections for deterministic output, so two runs over the same files print the same order.
// report is sorted in place: path lists, skipped paths by path then reason, diagnostics, findings, and rules by ID.
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

// ignoredPathProjection extracts the exact bare-path projection of detailed exclusions for the report's ignoredPaths list.
//
// skipped is the detailed exclusion list; every entry counts whatever its source, and its reason, source and pattern are dropped.
// It returns each distinct Path once in sorted order, and an empty non-nil slice when skipped is empty.
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

// compareDiagnostics orders diagnostics by file, line, stage, and message, so the report lists them in the same order every run.
//
// It returns a negative number when a sorts before b, a positive number when a sorts after b, and 0 when all four fields match.
// A diagnostic with no location sorts as line 0.
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

// locationLine returns location's line, or zero when a diagnostic has no location, so it sorts first within its file.
func locationLine(location *finding.Location) int {
	if location == nil {
		return 0
	}
	return location.Line
}

// countSeverity tallies findings by severity label for the summary's per-severity counts.
//
// The advisory, warning and error buckets are pre-populated, so an absent severity still shows with a zero count.
// It returns a fresh map; empty findings yields only those three keys at 0, and any other severity label gets its own key.
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
// It returns a fresh map keyed by pillar label that holds only pillars with at least one finding, so empty findings gives an empty map.
func countPillar(findings []finding.Finding) map[string]int {
	counts := map[string]int{}
	for _, item := range findings {
		counts[string(item.Pillar)]++
	}
	return counts
}

// MarshalJSON exposes only the canonical v3 machine envelope whenever a Report is encoded as JSON.
//
// Internal report fields remain available to human, SARIF, hook and scoring code without becoming accidental top-level JSON aliases.
// It returns the JSON encoding of the MachineEnvelope payload.
// When building the envelope or encoding it fails, it returns nil bytes and that error.
func (report Report) MarshalJSON() ([]byte, error) {
	payload, err := report.MachineEnvelope()
	if err != nil {
		return nil, err
	}
	return json.Marshal(payload)
}

// MachineEnvelope projects the internal report into the family v3 contract that MarshalJSON and MachineSummary publish.
//
// It returns the required v3 sections plus whichever optional baseline, diff, displayFilter and Go rules sections this run produced.
// It fails with a nil map and an error when a path the envelope must publish cannot be put in project-relative POSIX form.
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

// buildMachineEnvelopeParts prepares the required machine sections and normalizes the paths they publish.
//
// It covers inputs, findings, diagnostics, path lists, suppression scopes and top-offender paths; score clusters pass through unchanged.
// Baseline and diff paths are normalized later, by addMachineOptionalSections.
//
// It returns the run inputs, findings, diagnostics, path section, suppressions and score in their machine form.
// When any section fails to normalize, it returns a zero machineEnvelopeParts and that section's error.
func (report Report) buildMachineEnvelopeParts() (machineEnvelopeParts, error) {
	inputs, err := machineInputs(report.Run.WorkingDirectory, report.Run.Inputs)
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

// machineBaseEnvelope assembles the required v3 sections from normalized values, leaving optional ones to addMachineOptionalSections.
//
// parts supplies the normalized inputs, score, diagnostics, findings, paths and suppressions; the counts come from the report itself.
// It returns a new map holding schemaVersion, tool, run, summary, score, diagnostics, findings, paths and suppressions, never nil.
func (report Report) machineBaseEnvelope(parts machineEnvelopeParts) map[string]any {
	run := map[string]any{
		"failOn":      report.Run.FailOn,
		"format":      report.Run.Format,
		"inputs":      parts.inputs,
		"projectRoot": ".",
	}
	// A run with IncludeIgnored set names includeIgnored even if no ignored file was found, and a default run omits the key.
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
	// suppressedFindings appears only when changed-region filtering ran, so a full scan's summary omits it.
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

// addMachineOptionalSections attaches native sections only when their source feature was active for this run.
//
// payload is the base envelope, extended in place with baseline, diff, displayFilter and the Go rules extension when each applies.
// It returns an error when a baseline or diff path cannot be normalized; a diff failure may leave the baseline section in payload.
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
	// The displayFilter section appears only when DisplayFilter.Applied is set, so a run without display filters omits it.
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
	// A report with an empty rule catalogue, such as one from FailedRunReport, omits the Go rules extension.
	if len(report.Rules) > 0 {
		payload["extensions"] = map[string]any{
			"go": map[string]any{
				"topLevel": map[string]any{"rules": report.Rules},
			},
		}
	}
	return nil
}

// MachineSummary returns the sole permitted compact projection: the v3 analysis envelope without findings, under SummarySchemaVersion.
//
// It fails with a nil map and the MachineEnvelope error when the full envelope cannot be built.
func (report Report) MachineSummary() (map[string]any, error) {
	payload, err := report.MachineEnvelope()
	if err != nil {
		return nil, err
	}
	delete(payload, "findings")
	payload["schemaVersion"] = SummarySchemaVersion
	return payload, nil
}

// machinePathPayload projects analysed, skipped, ignored and missing paths into the canonical v3 path section.
//
// It returns analysedFiles, per-skip details, ignoredPaths, missingPaths, and the scanned list under the Go extension.
// It fails with a nil map and an error naming the list when an ignored, missing, scanned or skipped path cannot be made project-relative.
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
		// Only a config paths.ignore match carries its glob, so the user can see which pattern excluded the file.
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

// machineBaseline projects an applied baseline while preserving its native matching results and optional detail lists.
//
// Every applied baseline carries the same fixed status and count keys, the staleEntries count included, so consumers need not recompute matches.
//
// It returns nil and false when no baseline was applied, otherwise the payload and true; the unchanged and resolved lists appear only under Show.
// The path key is left out when the baseline file lies outside the project root.
// It fails with an error when the baseline path cannot be normalized for any other reason, or when a shown finding or resolved entry path cannot.
func (report Report) machineBaseline() (map[string]any, bool, error) {
	if !report.Baseline.Applied {
		return nil, false, nil
	}
	payload := map[string]any{
		"applied":            true,
		"entries":            report.Baseline.Entries,
		"generated":          report.Baseline.Generated,
		"newFindings":        report.Baseline.NewFindings,
		"resolvedFindings":   report.Baseline.ResolvedFindings,
		"source":             report.Baseline.Source,
		"staleEntries":       report.Baseline.StaleEntries,
		"suppressedFindings": report.Baseline.SuppressedFindings,
		"unchangedFindings":  report.Baseline.UnchangedFindings,
	}
	if report.Baseline.Path != "" {
		path, err := machinePath(report.Run.WorkingDirectory, report.Baseline.Path)
		// A baseline kept outside the project has no project-relative form and a host path may not be published, so
		// the optional key is left out, as the other ports leave it out, rather than failing the whole report.
		if err != nil && !errors.Is(err, errOutsideProjectRoot) {
			return nil, false, fmt.Errorf("baseline path: %w", err)
		}
		if err == nil {
			payload["path"] = path
		}
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

// machineDiff projects active changed-region metadata without recalculating the native diff result.
//
// It returns nil and false when diff filtering was not enabled, otherwise the payload and true, with a caveat key only when one was recorded.
// It fails with an error when a changed file path cannot be made project-relative.
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

// machineFindings copies findings and normalizes only their serialized paths, preserving every native identity field.
//
// root is the report's working directory and values the findings to copy; values itself is not modified.
// It returns a new slice of the same length, empty when values is empty, with each File in project-relative POSIX form.
// It fails with a nil slice and an error when a finding's File cannot be made project-relative, an empty File included.
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
//
// root is the report's working directory and values the diagnostics to project, each through machineDiagnostic.
// It returns one map per diagnostic in the same order, and an empty slice when values is empty.
// It fails with a nil slice and the first error machineDiagnostic returns.
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

// machineDiagnostic projects one diagnostic and keeps native-only location detail under the Go extension namespace.
//
// root is the report's working directory and diagnostic the run diagnostic to project; an empty DiagnosticType falls back to Stage, then to analysis.
// It returns a map with type, message and invalidatesRun, plus file, stage, severity and line keys when set; a file outside root is left out.
// It fails with a nil map and an error when the diagnostic's File cannot be normalized for a reason other than lying outside root.
func machineDiagnostic(root string, diagnostic Diagnostic) (map[string]any, error) {
	diagnosticType := diagnostic.DiagnosticType
	// A diagnostic with no named type publishes its stage, such as parse, as its type.
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
		// A file named from outside the project, such as --baseline ../y.json run from a sibling directory, is left out of the payload.
		//
		// It has no project-relative form and a host path may not be published, so the key is omitted, as for the baseline path above.
		// Failing here would drop the whole envelope, exiting 2 with nothing on stdout, where the other four ports publish the report and omit the key.
		if err != nil && !errors.Is(err, errOutsideProjectRoot) {
			return nil, fmt.Errorf("diagnostic path: %w", err)
		}
		if err == nil {
			payload["file"] = path
		}
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

// addMachineDiagnosticLocation attaches available line data to the core diagnostic and keeps richer coordinates as a Go extension.
//
// payload is the diagnostic map, changed in place, and source the location; a nil source or one with no positive coordinate adds nothing.
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

// machineSuppressions normalizes suppression scopes while preserving audit counts and user-supplied reasons.
//
// root is the report's working directory and values the suppression audit rows to project.
// It returns one map per row in order, empty when values is empty, with symbol and source keys only when they are non-empty.
// It fails with a nil slice and an error when a row's Paths entry cannot be made project-relative.
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
		// Built-in and inline rows name their source; a configured row carries none.
		if suppression.Source != "" {
			payload["source"] = suppression.Source
		}
		out = append(out, payload)
	}
	return out, nil
}

// machineScore normalizes top-offender paths without changing any score the native scoring engine produced.
//
// Clusters, attribution, pillars and coverage pass through exactly as the scoring engine built them.
//
// root is the report's working directory and score the native result, whose TopOffender files are copied and then normalized.
// It returns the composite grade and score with the evaluated files, pillars, clusters, attribution, offenders, coverage and complexity sections.
// It fails with a nil map and an error when a top offender's File cannot be made project-relative.
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

// errOutsideProjectRoot marks a path that has no project-relative form, so a caller may omit an optional key for it.
//
// The baseline path and a diagnostic's file are omitted on it, machineInputs retries an operand once, and any other path fails the envelope.
var errOutsideProjectRoot = errors.New("outside the project root")

// machineInputs converts the operands a user typed to project-relative POSIX form for the run block's inputs list.
//
// An operand may be relative to the launch directory, which need not be the project root, so it can read as outside the root at first.
// One that reads as outside the root is measured again from the launch directory before it is refused; one inside is only cleaned.
//
// root is the project root and values the operands in the order they were typed.
// It returns their portable forms in the same order, and an empty slice when values is empty.
// It fails with a nil slice and an error when an operand cannot be made project-relative, such as one outside root from both starting points.
func machineInputs(root string, values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, value := range values {
		portable, err := machinePath(root, value)
		if errors.Is(err, errOutsideProjectRoot) {
			if resolved, absErr := filepath.Abs(value); absErr == nil {
				portable, err = machinePath(root, resolved)
			}
		}
		if err != nil {
			return nil, err
		}
		out = append(out, portable)
	}
	return out, nil
}

// machinePaths converts an ordered path list to project-relative POSIX form.
//
// root is the directory the paths are made relative to and values the paths to convert, each through machinePath.
// It returns the converted paths in the same order, and an empty slice when values is empty.
// It fails with a nil slice and the first machinePath error, such as for a path outside root.
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

// machinePath converts one path to project-relative POSIX form and rejects values outside the report root.
//
// root is the directory an absolute value is made relative to, and value is the path to convert after filepath.Clean.
// It returns the cleaned slash-separated path, or an empty string and an error if value is empty or a Windows drive path.
// An absolute value returns an empty string and an error when root is empty or filepath.Rel cannot make it relative to root.
//
// A value outside root, or one still holding a backslash, fails with an empty string and an error wrapping errOutsideProjectRoot.
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
		return "", fmt.Errorf("path %q is %w", value, errOutsideProjectRoot)
	}
	return portable, nil
}
