package analysis

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestAnalyzeReportsMissingPathAsDiagnostic asserts missing inputs surface as discovery diagnostics.
// A failure means a typo such as gruff-go analyse missing.go no longer exits 2 or reports the problem outside the discovery stage.
func TestAnalyzeReportsMissingPathAsDiagnostic(t *testing.T) {
	t.Chdir(t.TempDir())
	report, err := Analyze(Options{
		Paths:    []string{"missing.go"},
		FailOn:   finding.FailThresholdWarning,
		Registry: rule.Defaults(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// A missing input must exit 2 even with no findings, so CI never reads the typo as a clean scan.
	if report.Summary.ExitCode != 2 {
		t.Fatalf("exit code = %d, want 2", report.Summary.ExitCode)
	}
	if len(report.Diagnostics) != 1 || report.Diagnostics[0].Stage != "discovery" {
		t.Fatalf("diagnostics = %#v, want discovery diagnostic", report.Diagnostics)
	}
}
