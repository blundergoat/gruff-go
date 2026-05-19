// Package analysis tests cover report assembly and exit-code resolution.
// These tests exercise the public Analyze entrypoint and helpers.
package analysis

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestResolveExitCode verifies exit codes for diagnostics and severity thresholds.
func TestResolveExitCode(t *testing.T) {
	if got := ResolveExitCode([]Diagnostic{{Message: "bad"}}, nil, finding.SeverityMedium); got != 2 {
		t.Fatalf("diagnostic exit = %d, want 2", got)
	}
	findings := []finding.Finding{{Severity: finding.SeverityHigh}}
	if got := ResolveExitCode(nil, findings, finding.SeverityMedium); got != 1 {
		t.Fatalf("finding exit = %d, want 1", got)
	}
	if got := ResolveExitCode(nil, findings, finding.SeverityCritical); got != 0 {
		t.Fatalf("below threshold exit = %d, want 0", got)
	}
}
