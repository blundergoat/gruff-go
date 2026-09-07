// Package cli builds the JSON payload consumed by coding-agent hooks.
// This file keeps findings, changed-scope counts, ignored paths, and config
// status in one stable user-facing gruff.hook.v1 response.
package cli

import (
	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/diff"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// hookReport is the top-level gruff.hook.v1 payload returned to an agent.
// It combines visible findings with changed-scope, ignored-path, analyzer, and
// configuration context so the user can understand what the hook considered.
type hookReport struct {
	ContractVersion string           `json:"contractVersion"`
	Analyzer        hookAnalyzer     `json:"analyzer"`
	Run             hookRun          `json:"run"`
	Findings        []hookFinding    `json:"findings"`
	Diagnostics     []hookDiagnostic `json:"diagnostics"`
	Suppressed      hookSuppressed   `json:"suppressed"`
	// Suppressions is the section 13a audit: one row per configured exclusion this run applied.
	Suppressions []hookSuppression `json:"suppressions"`
	Ignored      hookIgnored       `json:"ignored"`
	Config       hookConfigState   `json:"config"`
}

// hookSuppression is one configured sensitive exclusion and what it removed from this run.
//
// A surface that applies an exclusion must report its count on that same surface: a hook may decline to filter, but it
// may never filter in silence, because a consumer who cannot see the exclusion reads a clean payload as a clean file.
type hookSuppression struct {
	// Rule is the one sensitive-data rule the entry names.
	Rule string `json:"rule"`
	// Path is the one project-relative path the entry names.
	Path string `json:"path"`
	// Symbol narrows the entry further, and is omitted rather than null when the entry names none.
	Symbol string `json:"symbol,omitempty"`
	// Reason is the written rationale a reviewer reads instead of the finding.
	Reason string `json:"reason"`
	// Suppressed counts what this entry removed from this run; zero is reported, never hidden.
	Suppressed int `json:"suppressed"`
}

// hookRun is the audit block a consumer needs to trust a verdict: what ran, over what, and against which baseline.
//
// Without it a clean payload is ambiguous, because a run that analysed nothing and a run that found nothing look the
// same on the wire.
type hookRun struct {
	Mode          string          `json:"mode"`
	Scope         string          `json:"scope"`
	Paths         []string        `json:"paths"`
	AnalysedFiles int             `json:"analysedFiles"`
	Baseline      hookRunBaseline `json:"baseline"`
}

// hookRunBaseline says whether a baseline was applied and which one, so a suppressed finding is explicable.
type hookRunBaseline struct {
	Applied       bool    `json:"applied"`
	SchemaVersion *string `json:"schemaVersion"`
	Path          *string `json:"path"`
}

// hookDiagnostic projects a runtime diagnostic into the gruff.hook.v1 field vocabulary.
type hookDiagnostic struct {
	Type string `json:"type"`
	// Severity distinguishes a note from a run that could not happen, which v1 left the consumer to infer.
	Severity       string `json:"severity"`
	Message        string `json:"message"`
	File           string `json:"file,omitempty"`
	Line           int    `json:"line,omitempty"`
	InvalidatesRun *bool  `json:"invalidatesRun,omitempty"`
}

// hookSuppressed reports findings dropped only by changed-region scope.
// Baseline matches are reviewed debt rather than scope drops, preserving the
// existing meaning of the count shown to hook consumers.
type hookSuppressed struct {
	Count int `json:"count"`
}

// hookIgnored groups paths excluded from the user's hook scan.
// The nested shape keeps ignore explanations separate from actionable findings
// while remaining stable for gruff.hook.v1 consumers.
type hookIgnored struct {
	Paths []hookIgnoredPath `json:"paths"`
}

// hookIgnoredPath describes one file omitted from a user's hook scan.
// Source and optional pattern explain whether project config or ignore policy
// made the decision, so agents do not try to fix out-of-scope code.
type hookIgnoredPath struct {
	Path    string `json:"path"`
	Source  string `json:"source"`
	Pattern string `json:"pattern,omitempty"`
}

// hookConfigState reports whether the user's project config loaded safely.
// A nil Error means scanning used valid policy; a message gives the agent a
// practical configuration failure instead of pretending findings are complete.
type hookConfigState struct {
	SchemaOK bool             `json:"schemaOk"`
	Error    *hookConfigError `json:"error"`
}

// hookConfigError carries a remediation beside the message, because a configuration a consumer cannot fix is a dead end.
type hookConfigError struct {
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

// hookFinding is one actionable result normalized for the coding-agent UI.
// It carries user location, message, remediation, metadata, and both identities
// without changing the analyzer's internal Finding payload.
type hookFinding struct {
	RuleID   string           `json:"ruleId"`
	Pillar   finding.Pillar   `json:"pillar"`
	Severity finding.Severity `json:"severity"`
	Scope    string           `json:"scope"`
	File     string           `json:"file"`
	Line     *int             `json:"line"`
	// EndLine is always present: a consumer locating a finding cannot treat an absent span as a single line by guessing.
	EndLine *int    `json:"endLine"`
	Symbol  *string `json:"symbol"`
	// SymbolOrdinal is the declaration ordinal the ratified identity hashes, so a consumer can recompute it.
	SymbolOrdinal int    `json:"symbolOrdinal"`
	Message       string `json:"message"`
	Remediation   string `json:"remediation"`
	// Confidence is what the confidence gate reads; an unrated finding reports high so it cannot slip under a gate.
	Confidence finding.Confidence `json:"confidence"`
	// BaselineStatus is what an applied baseline made of this finding, and null when none was applied.
	BaselineStatus *string        `json:"baselineStatus"`
	Metadata       map[string]any `json:"metadata"`
	// StableIdentity is the ratified family identity, and null for a sensitive finding, which is never given one.
	StableIdentity *string `json:"stableIdentity"`
	// Fingerprint is this port's own hash, kept beside the family identity so neither scheme has to serve both jobs.
	Fingerprint string `json:"fingerprint"`
}

// hookReportInput groups everything one hook run produced, so the builder reads as one decision rather than six.
type hookReportInput struct {
	// analysisReport is the scan the payload describes.
	analysisReport analysis.Report
	// ruleDefinitions supply the catalogue remediation a finding falls back to.
	ruleDefinitions []rule.Definition
	// changedLines is the region the user edited, empty when no region selector was given.
	changedLines diff.ChangedLines
	// changedScopeEnabled is true when a changed line widens to its enclosing declaration.
	changedScopeEnabled bool
	// hookBaseline is the prior review state, disabled when the user named none.
	hookBaseline hookFindingBaseline
	// hookFlags are the user's choices, which the audit block reports back.
	hookFlags hookFlagValues
}

// buildHookReport applies baseline/changed filters and wraps hook metadata.
// Use it to produce the complete JSON response returned to the user's agent.
func buildHookReport(input hookReportInput) hookReport {
	analysisReport := input.analysisReport
	visibleFindings, changedScopeSuppressed := hookFindings(analysisReport.Findings, input.ruleDefinitions, input.changedLines, input.changedScopeEnabled, input.hookBaseline)
	return hookReport{
		ContractVersion: hookContractVersion,
		Analyzer:        hookAnalyzer{Name: analysisReport.Tool.Name, Version: analysisReport.Tool.Version},
		Run:             hookRunFor(analysisReport, input.hookFlags, input.changedScopeEnabled, input.hookBaseline),
		Findings:        visibleFindings,
		Diagnostics:     hookDiagnostics(analysisReport.Diagnostics),
		Suppressed:      hookSuppressed{Count: changedScopeSuppressed},
		Suppressions:    hookSuppressions(analysisReport.Suppressions),
		Ignored:         hookIgnored{Paths: hookIgnoredPaths(analysisReport.Paths.Skipped)},
		Config:          hookConfigState{SchemaOK: true, Error: nil},
	}
}

// hookDiagnostics retains non-fatal budget notes in-band without changing hook exit semantics.
func hookDiagnostics(diagnostics []analysis.Diagnostic) []hookDiagnostic {
	out := make([]hookDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		label := diagnostic.DiagnosticType
		if label == "" {
			label = diagnostic.Stage
		}
		line := 0
		if diagnostic.Location != nil {
			line = diagnostic.Location.Line
		}
		out = append(out, hookDiagnostic{
			Type:           label,
			Severity:       hookDiagnosticSeverity(diagnostic),
			Message:        diagnostic.Message,
			File:           diagnostic.File,
			Line:           line,
			InvalidatesRun: diagnostic.InvalidatesRun,
		})
	}
	return out
}

// hookIgnoredPaths converts scan skips into explanations for the user's agent.
// Empty input produces the contract's required empty path list.
func hookIgnoredPaths(skippedPaths []analysis.SkippedPath) []hookIgnoredPath {
	ignoredPaths := make([]hookIgnoredPath, 0, len(skippedPaths))
	// Preserve each skip explanation so the agent can report why a path was omitted.
	for _, skippedPath := range skippedPaths {
		ignoredPaths = append(ignoredPaths, hookIgnoredPath{Path: skippedPath.Path, Source: skippedPath.Source, Pattern: skippedPath.Pattern})
	}
	return ignoredPaths
}

// hookDiagnosticSeverity names what a diagnostic means for the run, which decides the exit code.
//
// A diagnostic that invalidates the run is fatal: analysis could not happen, so its verdict is not a verdict. Anything
// else is a warning the consumer reads in-band without the run failing.
func hookDiagnosticSeverity(diagnostic analysis.Diagnostic) string {
	if diagnostic.InvalidatesRun != nil && *diagnostic.InvalidatesRun {
		return "fatal"
	}

	return "warning"
}

// hookRunFor fills the audit block from what the run actually did.
//
// The file count is the one figure that separates a clean scan from a scan of nothing, which is why the contract makes
// it required rather than optional.
func hookRunFor(analysisReport analysis.Report, hookFlags hookFlagValues, changedScopeEnabled bool, hookBaseline hookFindingBaseline) hookRun {
	paths := hookFlags.paths

	// The operands are reported as the user gave them, and an empty list still serialises as a list rather than null.
	if paths == nil {
		paths = []string{}
	}

	return hookRun{
		Mode:          hookRunMode(hookFlags),
		Scope:         hookRunScope(hookFlags, changedScopeEnabled),
		Paths:         paths,
		AnalysedFiles: len(analysisReport.Paths.Scanned),
		Baseline:      hookBaseline.runBaseline(),
	}
}

// hookRunMode names which region selector chose the work, so a consumer can tell a targeted run from a whole-tree one.
func hookRunMode(hookFlags hookFlagValues) string {
	// Explicit ranges are the narrowest selector and win when both are given, which is what resolveHookChanged does.
	if hookFlags.changedRanges != "" {
		return "changed-ranges"
	}

	if hookFlags.diffMode != "" {
		return "diff"
	}

	return "full"
}

// hookRunScope names how wide each changed line was taken to be, which decides what a clean result actually proves.
func hookRunScope(hookFlags hookFlagValues, changedScopeEnabled bool) string {
	// Changed-scope widens every changed line to its enclosing declaration, so a symbol is the unit that was judged.
	if changedScopeEnabled {
		return "symbol"
	}

	// A region selector that produced no usable scope still narrowed the run to the changed lines themselves.
	if hookFlags.changedRanges != "" || hookFlags.diffMode != "" {
		return "hunk"
	}

	return "file"
}

// hookSuppressions projects the run's sensitive-exclusion audit into the hook's row shape.
//
// A run with no configured exclusions reports an empty list rather than null, so a consumer parses one shape whether
// exclusions were configured or not.
func hookSuppressions(summaries []analysis.SuppressionSummary) []hookSuppression {
	rows := make([]hookSuppression, 0, len(summaries))

	for _, summary := range summaries {
		row := hookSuppression{Rule: summary.Rule, Reason: summary.Reason, Suppressed: summary.Suppressed}

		// Section 13a gives each entry exactly one path; the analysis audit carries it in the family's array shape.
		if len(summary.Paths) > 0 {
			row.Path = summary.Paths[0]
		}

		// A symbol narrows an entry where a port stamps one, and is absent rather than empty when the entry names none.
		if summary.Symbol != nil {
			row.Symbol = *summary.Symbol
		}

		rows = append(rows, row)
	}

	return rows
}
