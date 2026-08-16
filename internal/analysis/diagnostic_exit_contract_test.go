// Package analysis tests pin the fatal diagnostic exit contract independently
// from the finding severity gate.
package analysis

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestDiagnosticExitContractAcrossStagesAndThresholds proves every diagnostic
// stage wins over both the finding gate and any simultaneously reported finding.
func TestDiagnosticExitContractAcrossStagesAndThresholds(t *testing.T) {
	stages := []string{"discovery", "parse", "baseline", "diff"}
	thresholds := []finding.FailThreshold{
		finding.FailThresholdNone,
		finding.FailThresholdAdvisory,
		finding.FailThresholdWarning,
		finding.FailThresholdError,
	}
	findings := []finding.Finding{{Severity: finding.SeverityError}}

	for _, stage := range stages {
		for _, threshold := range thresholds {
			t.Run(stage+"/"+string(threshold), func(t *testing.T) {
				diagnostics := []Diagnostic{{
					Stage:    stage,
					Message:  "operational failure",
					Severity: finding.SeverityError,
				}}
				if got := ResolveExitCode(diagnostics, findings, threshold); got != 2 {
					t.Fatalf("ResolveExitCode(%s diagnostic, threshold %s) = %d, want 2", stage, threshold, got)
				}
			})
		}
	}
}

// TestDiagnosticExitContractKeepsFindingGateSeparate covers clean, disabled,
// below-threshold, and at-threshold finding-only runs.
func TestDiagnosticExitContractKeepsFindingGateSeparate(t *testing.T) {
	tests := []struct {
		name      string
		findings  []finding.Finding
		threshold finding.FailThreshold
		want      int
	}{
		{name: "no findings", threshold: finding.FailThresholdAdvisory, want: 0},
		{name: "gate disabled", findings: []finding.Finding{{Severity: finding.SeverityError}}, threshold: finding.FailThresholdNone, want: 0},
		{name: "below threshold", findings: []finding.Finding{{Severity: finding.SeverityAdvisory}}, threshold: finding.FailThresholdWarning, want: 0},
		{name: "at threshold", findings: []finding.Finding{{Severity: finding.SeverityWarning}}, threshold: finding.FailThresholdWarning, want: 1},
		{name: "above threshold", findings: []finding.Finding{{Severity: finding.SeverityError}}, threshold: finding.FailThresholdWarning, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveExitCode(nil, tt.findings, tt.threshold); got != tt.want {
				t.Fatalf("ResolveExitCode(finding-only, threshold %s) = %d, want %d", tt.threshold, got, tt.want)
			}
		})
	}
}
