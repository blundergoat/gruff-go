// Package analysis tests cover report assembly and exit-code resolution.
//
// These tests call NewReport and ResolveExitCode directly to check report scores and exit codes for diagnostics and findings.
package analysis

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestResolveExitCode pins the exit codes a user or CI job sees for diagnostics and the --fail-on severity threshold.
//
// A failure here means a scan would pass or fail CI with a different exit code than before.
func TestResolveExitCode(t *testing.T) {
	if got := ResolveExitCode([]Diagnostic{{Message: "bad"}}, nil, finding.FailThresholdWarning); got != 2 {
		t.Fatalf("diagnostic exit = %d, want 2", got)
	}
	// A diagnostic explicitly marked as not invalidating the run must not fail CI on its own.
	nonFatal := false
	if got := ResolveExitCode([]Diagnostic{{Message: "bounded", InvalidatesRun: &nonFatal}}, nil, finding.FailThresholdWarning); got != 0 {
		t.Fatalf("non-fatal diagnostic exit = %d, want 0", got)
	}
	findings := []finding.Finding{{Severity: finding.SeverityWarning}}
	if got := ResolveExitCode(nil, findings, finding.FailThresholdWarning); got != 1 {
		t.Fatalf("finding exit = %d, want 1", got)
	}
	// A warning under --fail-on error stays below the threshold, so the run still exits 0.
	if got := ResolveExitCode(nil, findings, finding.FailThresholdError); got != 0 {
		t.Fatalf("below threshold exit = %d, want 0", got)
	}
}

// TestNewReportScoresCleanRegisteredPillars verifies the CLI headline includes clean catalogue areas,
// while Pillars stays limited to areas with findings.
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
	// A wrong evaluated-file count changes the densities of the pillars with findings, and so the expected composite score.
	if report.Score.EvaluatedFiles == nil || *report.Score.EvaluatedFiles != 2 {
		t.Fatalf("evaluatedFiles = %v, want the two scanned Go files", report.Score.EvaluatedFiles)
	}
	// The disabled documentation rule still makes documentation a clean rule-backed area.
	if report.Score.Composite == nil || *report.Score.Composite != wantComposite {
		t.Fatalf("composite = %v, want %v", report.Score.Composite, wantComposite)
	}
	// PillarDetails carries a row for every scored pillar, while Pillars stays limited to the two pillars with findings.
	if len(report.Score.Pillars) != 2 || len(report.Score.PillarDetails) != 3 {
		t.Fatalf("pillar shape changed: %#v", report.Score)
	}
	// Clean documentation raises the composite score without appearing in Pillars, which lists only areas with findings.
	if _, exists := report.Score.Pillars[string(finding.PillarDocumentation)]; exists {
		t.Fatalf("clean documentation pillar appeared in details: %#v", report.Score.Pillars)
	}
}
