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
	Findings        []hookFinding    `json:"findings"`
	Diagnostics     []hookDiagnostic `json:"diagnostics"`
	Suppressed      hookSuppressed   `json:"suppressed"`
	Ignored         hookIgnored      `json:"ignored"`
	Config          hookConfigState  `json:"config"`
}

// hookDiagnostic projects a runtime diagnostic into the gruff.hook.v1 field vocabulary.
type hookDiagnostic struct {
	Type           string `json:"type"`
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
	SchemaOK bool    `json:"schemaOk"`
	Error    *string `json:"error"`
}

// hookFinding is one actionable result normalized for the coding-agent UI.
// It carries user location, message, remediation, metadata, and both identities
// without changing the analyzer's internal Finding payload.
type hookFinding struct {
	RuleID         string           `json:"ruleId"`
	Pillar         finding.Pillar   `json:"pillar"`
	Severity       finding.Severity `json:"severity"`
	Scope          string           `json:"scope"`
	File           string           `json:"file"`
	Line           *int             `json:"line"`
	EndLine        *int             `json:"endLine,omitempty"`
	Symbol         *string          `json:"symbol"`
	Message        string           `json:"message"`
	Remediation    string           `json:"remediation"`
	Metadata       map[string]any   `json:"metadata"`
	StableIdentity string           `json:"stableIdentity"`
	Fingerprint    string           `json:"fingerprint,omitempty"`
}

// buildHookReport applies baseline/changed filters and wraps hook metadata.
// Use it to produce the complete JSON response returned to the user's agent.
func buildHookReport(analysisReport analysis.Report, ruleDefinitions []rule.Definition, changedLines diff.ChangedLines, changedScopeEnabled bool, hookBaseline hookFindingBaseline) hookReport {
	visibleFindings, changedScopeSuppressed := hookFindings(analysisReport.Findings, ruleDefinitions, changedLines, changedScopeEnabled, hookBaseline)
	return hookReport{
		ContractVersion: hookContractVersion,
		Analyzer:        hookAnalyzer{Name: analysisReport.Tool.Name, Version: analysisReport.Tool.Version},
		Findings:        visibleFindings,
		Diagnostics:     hookDiagnostics(analysisReport.Diagnostics),
		Suppressed:      hookSuppressed{Count: changedScopeSuppressed},
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
