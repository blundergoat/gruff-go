// Package analysis tests pin the fatal diagnostic exit contract independently from the finding severity gate.
//
// A fatal discovery, parse, baseline or diff diagnostic, one with InvalidatesRun unset or true, forces exit 2 at every --fail-on threshold.
// Nonfatal diagnostics leave the finding gate in control, and finding-only runs exit 0 or 1.
// A fatal-diagnostic test failure means an incomplete run could report exit 0 or 1 and look like a normal pass or fail in CI.
package analysis

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestDiagnosticExitContractAcrossStagesAndThresholds checks that fatal diagnostics override findings at every --fail-on threshold.
//
// Each discovery, parse, baseline and diff stage, under every --fail-on threshold including the disabled gate, must exit 2.
// A failure names the stage and threshold whose run let the finding gate decide the exit code instead.
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

// TestDiagnosticExitContractKeepsFindingGateSeparate checks runs with no diagnostics, where only findings and --fail-on set the exit code.
//
// Clean, gate-disabled and below-threshold runs exit 0; runs with a finding at or above the threshold exit 1.
// A failure means findings alone set the wrong exit code, for example a disabled gate that still fails CI.
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
