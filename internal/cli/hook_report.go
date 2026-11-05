// Package cli builds the JSON payload consumed by coding-agent hooks.
//
// This file keeps findings, changed-scope counts, ignored paths and config status in one stable, user-facing gruff.hook.v2 response.
package cli

import (
	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/diff"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// hookReport is the top-level gruff.hook.v2 payload returned to an agent.
//
// It joins visible findings with changed-scope, ignored-path, analyzer and config context, so the user can see what the hook considered.
type hookReport struct {
	ContractVersion string           `json:"contractVersion"`
	Analyzer        hookAnalyzer     `json:"analyzer"`
	Run             hookRun          `json:"run"`
	Findings        []hookFinding    `json:"findings"`
	Diagnostics     []hookDiagnostic `json:"diagnostics"`
	Suppressed      hookSuppressed   `json:"suppressed"`
	// Suppressions is the section 13a audit: configured, built-in and inline rows, including configured entries that matched nothing.
	Suppressions []hookSuppression `json:"suppressions"`
	Ignored      hookIgnored       `json:"ignored"`
	Config       hookConfigState   `json:"config"`
}

// hookSuppression records one configured, built-in or inline suppression scope and the number of findings it removed from this run.
//
// A surface that applies an exclusion must report its count on that same surface: a hook may decline to filter, but never filters in silence.
// A consumer who cannot see the exclusion would read a clean payload as a clean file.
type hookSuppression struct {
	// Rule is the rule ID whose findings the row counts, which need not be a sensitive-data rule.
	Rule string `json:"rule"`
	// Path is the row's single display path, copied from the analysis audit; a scan input outside the analysis root can leave it absolute.
	Path string `json:"path"`
	// Symbol narrows the entry further, and is omitted rather than null when the entry names none.
	Symbol string `json:"symbol,omitempty"`
	// Reason is the written rationale a reviewer reads instead of the finding.
	Reason string `json:"reason"`
	// Suppressed counts what this entry removed from this run; zero is reported, never hidden.
	Suppressed int `json:"suppressed"`
	// Source is built-in for a test-path skip, inline for a suppression comment, and omitted for a configured entry.
	Source string `json:"source,omitempty"`
}

// hookRun is the audit block a consumer needs to trust a verdict: what ran, over what, and against which baseline.
//
// Without it a clean payload is ambiguous, because a run that analysed nothing and a run that found nothing look the same on the wire.
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

// hookDiagnostic projects a runtime diagnostic into the gruff.hook.v2 field vocabulary.
type hookDiagnostic struct {
	Type string `json:"type"`
	// Severity is fatal on a fatal error payload, or on a projected analysis diagnostic whose InvalidatesRun is explicitly true.
	// A projected diagnostic with nil InvalidatesRun reads warning, although analysis treats nil as run-invalidating.
	Severity       string `json:"severity"`
	Message        string `json:"message"`
	File           string `json:"file,omitempty"`
	Line           int    `json:"line,omitempty"`
	InvalidatesRun *bool  `json:"invalidatesRun,omitempty"`
}

// hookSuppressed reports findings dropped only by changed-region scope.
// Baseline matches are reviewed debt, not scope drops, so they stay out of this count, which keeps its existing meaning for hook consumers.
type hookSuppressed struct {
	Count int `json:"count"`
}

// hookIgnored groups paths excluded from the user's hook scan.
// The nested shape keeps ignore explanations apart from actionable findings and stays stable for gruff.hook.v2 consumers.
type hookIgnored struct {
	Paths []hookIgnoredPath `json:"paths"`
}

// hookIgnoredPath describes one file or directory omitted from a user's hook scan.
// Source and the optional pattern say whether project config or ignore policy made the call, so agents do not try to fix out-of-scope code.
type hookIgnoredPath struct {
	Path    string `json:"path"`
	Source  string `json:"source"`
	Pattern string `json:"pattern,omitempty"`
}

// hookConfigState reports whether the user's project config loaded safely.
//
// A nil Error means scanning used valid policy.
// A set Error gives the agent a practical configuration failure instead of pretending the findings are complete.
type hookConfigState struct {
	SchemaOK bool             `json:"schemaOk"`
	Error    *hookConfigError `json:"error"`
}

// hookConfigError carries a remediation beside the message, because a configuration a consumer cannot fix is a dead end.
type hookConfigError struct {
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

// hookFinding is one actionable result normalized for the user's coding agent.
// It carries the location, message, remediation, metadata and both identities without changing the analyzer's internal Finding payload.
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
	// changedScopeEnabled turns on changed-region filtering of findings against changedLines, which the audit block reports as the symbol scope.
	changedScopeEnabled bool
	// hookBaseline is the prior review state, disabled when the user named none.
	hookBaseline hookFindingBaseline
	// hookFlags are the user's choices, which the audit block reports back.
	hookFlags hookFlagValues
}

// buildHookReport applies the baseline and changed-region filters to the analysis findings and wraps them in hook metadata.
//
// input carries the analysis report, rule definitions, changed lines, changed-scope flag, baseline and hook flags of one hook run.
// It returns the complete JSON response for the user's agent; Config always reports schemaOk true and a null error from this builder.
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

// hookDiagnostics copies every analysis diagnostic into the payload, so non-fatal budget notes reach the agent in-band.
//
// It returns one row per entry of diagnostics, in order, typed by DiagnosticType or else Stage, with line zero when there is no location.
// The result is an empty, non-nil slice when diagnostics is empty; only an entry whose InvalidatesRun is explicitly true gets fatal severity.
// The projection leaves hook exit semantics unchanged.
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
//
// It returns one row per entry of skippedPaths, in order, copying its path, source and pattern.
// Empty input produces the contract's required empty path list rather than null.
func hookIgnoredPaths(skippedPaths []analysis.SkippedPath) []hookIgnoredPath {
	ignoredPaths := make([]hookIgnoredPath, 0, len(skippedPaths))
	// Preserve each skip explanation so the agent can report why a path was omitted.
	for _, skippedPath := range skippedPaths {
		ignoredPaths = append(ignoredPaths, hookIgnoredPath{Path: skippedPath.Path, Source: skippedPath.Source, Pattern: skippedPath.Pattern})
	}
	return ignoredPaths
}

// hookDiagnosticSeverity names what a diagnostic means for the run; neither the analysis exit code nor hookExitCode reads the label.
//
// It returns the string fatal when the diagnostic's InvalidatesRun is set to true, and warning when it is nil or false.
// A nil InvalidatesRun still makes the hook exit 2, so a warning can accompany exit 2; under --fail-on-diagnostics a warning can cause exit 1.
func hookDiagnosticSeverity(diagnostic analysis.Diagnostic) string {
	if diagnostic.InvalidatesRun != nil && *diagnostic.InvalidatesRun {
		return "fatal"
	}

	return "warning"
}

// hookRunFor fills the audit block from what the run actually did.
//
// The file count is what separates a clean scan from a scan of nothing, which is why the contract makes it required.
// A run with no scanned paths reports analysedFiles 0; a scanned file that failed to parse still counts, and its diagnostic names the failure.
//
// It returns the run block: Mode and Paths come from hookFlags, Scope also reads changedScopeEnabled, and Baseline describes hookBaseline.
// AnalysedFiles counts the scanned paths in analysisReport, and Paths is an empty, non-nil list when the user gave no operands.
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

// hookRunMode names the changed-region selector the user requested, or full when none was requested, even if explicit paths narrowed the scan.
// It returns changed-ranges when hookFlags sets explicit ranges, which win over a diff mode, diff for a diff mode alone, and full otherwise.
func hookRunMode(hookFlags hookFlagValues) string {
	// When both selectors are given, explicit ranges take precedence over the diff mode, as they do in resolveHookChanged.
	if hookFlags.changedRanges != "" {
		return "changed-ranges"
	}

	if hookFlags.diffMode != "" {
		return "diff"
	}

	return "full"
}

// hookRunScope labels the run by its active filter or else the requested selector, so a hunk label need not mean findings were filtered.
// It returns symbol when changedScopeEnabled is true, hunk when hookFlags sets changed ranges or a diff mode, and file otherwise.
func hookRunScope(hookFlags hookFlagValues, changedScopeEnabled bool) string {
	// With filtering on the run is labelled symbol, though only line and symbol findings are matched against changedLines.
	if changedScopeEnabled {
		return "symbol"
	}

	// A requested selector keeps the hunk label even with filtering off, including the unfiltered fallback when the git base is missing.
	if hookFlags.changedRanges != "" || hookFlags.diffMode != "" {
		return "hunk"
	}

	return "file"
}

// hookSuppressions projects the run's suppression audit, configured, built-in and inline rows alike, into the hook's row shape.
//
// summaries map to rows in order; each row takes the summary's first path and its symbol, left empty and so omitted when the summary has none.
// It returns one row per summary in order, and an empty list rather than null for empty or nil summaries, so a consumer parses one shape.
func hookSuppressions(summaries []analysis.SuppressionSummary) []hookSuppression {
	rows := make([]hookSuppression, 0, len(summaries))

	for _, summary := range summaries {
		row := hookSuppression{Rule: summary.Rule, Reason: summary.Reason, Suppressed: summary.Suppressed, Source: summary.Source}

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
