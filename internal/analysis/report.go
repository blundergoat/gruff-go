// Package analysis orchestrates scanner runs and assembles stable reports.
package analysis

import (
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
	"github.com/blundergoat/gruff-go/internal/scoring"
)

const SchemaVersion = "gruff-go.analysis.v0.1"

type Diagnostic struct {
	Stage    string            `json:"stage"`
	Message  string            `json:"message"`
	File     string            `json:"file,omitempty"`
	Location *finding.Location `json:"location,omitempty"`
	Severity finding.Severity  `json:"severity"`
}

type Report struct {
	SchemaVersion string               `json:"schemaVersion"`
	Tool          Tool                 `json:"tool"`
	Run           RunMetadata          `json:"run"`
	Summary       Summary              `json:"summary"`
	Baseline      BaselineSummary      `json:"baseline"`
	Diff          DiffSummary          `json:"diff"`
	DisplayFilter DisplayFilterSummary `json:"displayFilter"`
	Score         scoring.Score        `json:"score"`
	Rules         []rule.Definition    `json:"rules"`
	Paths         Paths                `json:"paths"`
	Diagnostics   []Diagnostic         `json:"diagnostics"`
	Findings      []finding.Finding    `json:"findings"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type RunMetadata struct {
	WorkingDirectory string   `json:"workingDirectory"`
	Inputs           []string `json:"inputs"`
	Format           string   `json:"format"`
	FailOn           string   `json:"failOn"`
	IncludeIgnored   bool     `json:"includeIgnored,omitempty"`
}

type Summary struct {
	FilesScanned       int            `json:"filesScanned"`
	FilesSkipped       int            `json:"filesSkipped"`
	DiagnosticsCount   int            `json:"diagnosticsCount"`
	FindingsCount      int            `json:"findingsCount"`
	CountsBySeverity   map[string]int `json:"countsBySeverity"`
	CountsByPillar     map[string]int `json:"countsByPillar"`
	ExitCode           int            `json:"exitCode"`
	ParserMode         string         `json:"parserMode"`
	TypeLoadingEnabled bool           `json:"typeLoadingEnabled"`
}

type BaselineSummary struct {
	Applied            bool   `json:"applied"`
	Path               string `json:"path,omitempty"`
	Entries            int    `json:"entries"`
	SuppressedFindings int    `json:"suppressedFindings"`
	StaleEntries       int    `json:"staleEntries"`
}

type DiffSummary struct {
	Enabled          bool     `json:"enabled"`
	Base             string   `json:"base,omitempty"`
	ChangedFiles     []string `json:"changedFiles"`
	FilteredFindings int      `json:"filteredFindings"`
	Caveat           string   `json:"caveat,omitempty"`
}

type DisplayFilterSummary struct {
	Applied        bool     `json:"applied"`
	IncludeRules   []string `json:"includeRules"`
	ExcludeRules   []string `json:"excludeRules"`
	IncludePillars []string `json:"includePillars"`
	ExcludePillars []string `json:"excludePillars"`
	HiddenFindings int      `json:"hiddenFindings"`
	Caveat         string   `json:"caveat,omitempty"`
}

type Paths struct {
	Scanned []string      `json:"scanned"`
	Skipped []SkippedPath `json:"skipped"`
	Missing []string      `json:"missing"`
}

type SkippedPath struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

func NewReport(root string, inputs []string, format string, failOn finding.Severity, includeIgnored bool, scanned []string, skipped []SkippedPath, missing []string, diagnostics []Diagnostic, findings []finding.Finding, definitions []rule.Definition, baseline BaselineSummary, diff DiffSummary) Report {
	scanned = nonNilStrings(scanned)
	skipped = nonNilSkipped(skipped)
	missing = nonNilStrings(missing)
	diagnostics = nonNilDiagnostics(diagnostics)
	findings = nonNilFindings(findings)
	definitions = nonNilDefinitions(definitions)
	diff.ChangedFiles = nonNilStrings(diff.ChangedFiles)
	exitCode := ResolveExitCode(diagnostics, findings, failOn)
	report := Report{
		SchemaVersion: SchemaVersion,
		Tool: Tool{
			Name:    "gruff-go",
			Version: "0.1.0-dev",
		},
		Run: RunMetadata{
			WorkingDirectory: root,
			Inputs:           inputs,
			Format:           format,
			FailOn:           string(failOn),
			IncludeIgnored:   includeIgnored,
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
		Baseline: baseline,
		Diff:     diff,
		Score:    scoring.Calculate(findings),
		Rules:    definitions,
		Paths: Paths{
			Scanned: scanned,
			Skipped: skipped,
			Missing: missing,
		},
		Diagnostics: diagnostics,
		Findings:    findings,
	}
	SortReport(&report)
	return report
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilSkipped(values []SkippedPath) []SkippedPath {
	if values == nil {
		return []SkippedPath{}
	}
	return values
}

func nonNilDiagnostics(values []Diagnostic) []Diagnostic {
	if values == nil {
		return []Diagnostic{}
	}
	return values
}

func nonNilFindings(values []finding.Finding) []finding.Finding {
	if values == nil {
		return []finding.Finding{}
	}
	return values
}

func nonNilDefinitions(values []rule.Definition) []rule.Definition {
	if values == nil {
		return []rule.Definition{}
	}
	return values
}

func ResolveExitCode(diagnostics []Diagnostic, findings []finding.Finding, failOn finding.Severity) int {
	if len(diagnostics) > 0 {
		return 2
	}
	for _, item := range findings {
		if item.Severity.AtLeast(failOn) {
			return 1
		}
	}
	return 0
}

func SortReport(report *Report) {
	slices.Sort(report.Paths.Scanned)
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

func locationLine(location *finding.Location) int {
	if location == nil {
		return 0
	}
	return location.Line
}

func countSeverity(findings []finding.Finding) map[string]int {
	counts := map[string]int{
		string(finding.SeverityInfo):     0,
		string(finding.SeverityLow):      0,
		string(finding.SeverityMedium):   0,
		string(finding.SeverityHigh):     0,
		string(finding.SeverityCritical): 0,
	}
	for _, item := range findings {
		counts[string(item.Severity)]++
	}
	return counts
}

func countPillar(findings []finding.Finding) map[string]int {
	counts := map[string]int{}
	for _, item := range findings {
		counts[string(item.Pillar)]++
	}
	return counts
}
