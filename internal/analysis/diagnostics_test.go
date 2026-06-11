package analysis

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestAnalyzeReportsMissingPathAsDiagnostic asserts missing inputs surface as discovery diagnostics.
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
	if report.Summary.ExitCode != 2 {
		t.Fatalf("exit code = %d, want 2", report.Summary.ExitCode)
	}
	if len(report.Diagnostics) != 1 || report.Diagnostics[0].Stage != "discovery" {
		t.Fatalf("diagnostics = %#v, want discovery diagnostic", report.Diagnostics)
	}
}
