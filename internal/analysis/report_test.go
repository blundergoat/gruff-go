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
	})

	wantComposite := (92 + 78 + 100) / 3
	// The disabled documentation rule still makes documentation a clean rule-backed area.
	if report.Score.Composite != wantComposite {
		t.Fatalf("composite = %d, want %d", report.Score.Composite, wantComposite)
	}
	// Clean areas affect the mean without appearing as invented finding evidence.
	if len(report.Score.Pillars) != 2 || len(report.Score.PillarDetails) != 2 {
		t.Fatalf("finding-bearing details changed shape: %#v", report.Score)
	}
	// A clean area should improve the total without inventing a detail row for the user.
	if _, exists := report.Score.Pillars[string(finding.PillarDocumentation)]; exists {
		t.Fatalf("clean documentation pillar appeared in details: %#v", report.Score.Pillars)
	}
}
