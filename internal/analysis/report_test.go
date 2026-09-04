// Package analysis tests cover report assembly and exit-code resolution.
// These tests exercise the public Analyze entrypoint and helpers.
// They protect the score and diagnostics users receive from each CLI scan.
package analysis

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestResolveExitCode verifies exit codes for diagnostics and severity thresholds.
func TestResolveExitCode(t *testing.T) {
	if got := ResolveExitCode([]Diagnostic{{Message: "bad"}}, nil, finding.FailThresholdWarning); got != 2 {
		t.Fatalf("diagnostic exit = %d, want 2", got)
	}
	nonFatal := false
	if got := ResolveExitCode([]Diagnostic{{Message: "bounded", InvalidatesRun: &nonFatal}}, nil, finding.FailThresholdWarning); got != 0 {
		t.Fatalf("non-fatal diagnostic exit = %d, want 0", got)
	}
	findings := []finding.Finding{{Severity: finding.SeverityWarning}}
	if got := ResolveExitCode(nil, findings, finding.FailThresholdWarning); got != 1 {
		t.Fatalf("finding exit = %d, want 1", got)
	}
	if got := ResolveExitCode(nil, findings, finding.FailThresholdError); got != 0 {
		t.Fatalf("below threshold exit = %d, want 0", got)
	}
}

// TestNewReportScoresCleanRegisteredPillars verifies the CLI headline includes
// clean catalogue areas while its detail fields stay limited to findings.
func TestNewReportScoresCleanRegisteredPillars(t *testing.T) {
	report := NewReport(ReportInput{
		Findings: []finding.Finding{
			{File: "size.go", Pillar: finding.PillarSize, Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh},
			{File: "complex.go", Pillar: finding.PillarComplexity, Severity: finding.SeverityError, Confidence: finding.ConfidenceMedium},
		},
		Definitions: []rule.Definition{
			{Pillar: finding.PillarSize, DefaultEnabled: true},
			{Pillar: finding.PillarComplexity, DefaultEnabled: true},
			{Pillar: finding.PillarDocumentation, DefaultEnabled: false},
		},
		// The ratified denominator counts Go files that survived discovery, so the scan needs some.
		Scanned: []string{"size.go", "complex.go"},
	})

	// Two evaluated files: size carries a high-confidence warning (weight 4, density 2.00, score
	// 52.38), complexity a medium-confidence error (weight 9, density 4.50, score 51.09), and clean
	// documentation scores 100. The ratified mean of the three is 67.82.
	const wantComposite = 67.82
	if report.Score.EvaluatedFiles == nil || *report.Score.EvaluatedFiles != 2 {
		t.Fatalf("evaluatedFiles = %v, want the two scanned Go files", report.Score.EvaluatedFiles)
	}
	// The disabled documentation rule still makes documentation a clean rule-backed area.
	if report.Score.Composite == nil || *report.Score.Composite != wantComposite {
		t.Fatalf("composite = %v, want %v", report.Score.Composite, wantComposite)
	}
	// Every scored pillar now carries a row, while the finding-bearing map stays limited to findings.
	if len(report.Score.Pillars) != 2 || len(report.Score.PillarDetails) != 3 {
		t.Fatalf("pillar shape changed: %#v", report.Score)
	}
	// A clean area should improve the total without inventing a detail row for the user.
	if _, exists := report.Score.Pillars[string(finding.PillarDocumentation)]; exists {
		t.Fatalf("clean documentation pillar appeared in details: %#v", report.Score.Pillars)
	}
}
