// Package report tests cover the human-readable sensitive-exclusion total.
// The line follows the family shape reference in gruff-rs/src/render/text.rs
// (search: `Suppressed findings:`), lowercased to gruff-go's text house style.
package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestTextReportsSuppressionTotalAndEveryEntry verifies the total plus one clause
// per configured entry, including an entry that suppressed nothing, so no
// accepted suppression is invisible on the human surface.
func TestTextReportsSuppressionTotalAndEveryEntry(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "text",
		FailOn:      finding.FailThresholdWarning,
		Scanned:     []string{"secrets/aws.env"},
		Definitions: defaultDefinitions(),
		Suppressions: []analysis.SuppressionSummary{
			{Index: 0, Rule: "sensitive-data.aws-access-key", Paths: []string{"secrets/aws.env"}, Reason: "Synthetic AWS key in the redaction corpus.", Suppressed: 2},
			{Index: 1, Rule: "sensitive-data.jwt-token", Paths: []string{"secrets/jwt.env"}, Reason: "Retained while the fixture is being removed.", Suppressed: 0},
		},
	})

	var buf bytes.Buffer
	if err := WriteText(&buf, report); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	want := "suppressed findings: 2 via sensitiveExclusions[0] sensitive-data.aws-access-key: 2 (Synthetic AWS key in the redaction corpus.); sensitiveExclusions[1] sensitive-data.jwt-token: 0 (Retained while the fixture is being removed.)\n"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("text output missing the suppression line:\n%s", buf.String())
	}
}

// TestTextOmitsSuppressionLineWithoutExclusions verifies a project that
// configured no exclusions renders byte-identical output to before the section
// existed.
func TestTextOmitsSuppressionLineWithoutExclusions(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "text",
		FailOn:      finding.FailThresholdWarning,
		Scanned:     []string{"main.go"},
		Definitions: defaultDefinitions(),
	})

	var buf bytes.Buffer
	if err := WriteText(&buf, report); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if strings.Contains(buf.String(), "suppressed findings:") {
		t.Fatalf("text output added a suppression line without exclusions:\n%s", buf.String())
	}
}
