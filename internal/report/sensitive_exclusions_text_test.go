// Package report tests cover the human-readable sensitive-exclusion total.
//
// The line follows the family shape in gruff-rs/src/render/text.rs (search: Suppressed findings:), lowercased to gruff-go's text house style.
// These tests pin that line: zero-count entries stay listed, inline rows name their file, and a report with no suppression rows omits it.
package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestTextReportsSuppressionTotalAndEveryEntry checks the text report prints the suppression total and one clause per configured entry.
// An entry that suppressed nothing still gets a 0 clause, so every accepted exclusion stays visible in text output.
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

// TestTextOmitsSuppressionLineWithoutExclusions checks that a report with no suppression rows omits the suppressed-findings line.
// A failure means a report with an empty suppression audit printed a suppression line anyway.
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

// TestTextNamesInlineRowsByTheirFile checks an inline row is labelled inline with its file name, then rule ID, count and reason.
// The clause audits another tool's suppression comment with its file, rule ID, count and reason, as FAMILY-CONTRACT.md section 13c requires.
func TestTextNamesInlineRowsByTheirFile(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root: "/repo", Inputs: []string{"."}, Format: "text", FailOn: finding.FailThresholdWarning, Scanned: []string{"main.go"},
		Definitions: defaultDefinitions(),
		Suppressions: []analysis.SuppressionSummary{
			{Index: 0, Rule: "size.function-length", Paths: []string{"main.go"}, Reason: analysis.InlineSuppressionReason, Suppressed: 1, Source: analysis.SuppressionSourceInline},
		},
	})

	var buf bytes.Buffer
	if err := WriteText(&buf, report); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	want := "suppressed findings: 1 via inline[main.go] size.function-length: 1 (" + analysis.InlineSuppressionReason + ")\n"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("text output missing the inline clause:\n%s", buf.String())
	}
}
