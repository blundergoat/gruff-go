// Package report's M06 agreement test pins one property the ratified contract makes load-bearing:
// the composite a person reads in the terminal and the composite a script reads from the envelope
// come from one calculation and must never disagree.
//
// A renderer that formats the score itself, rather than printing the value the scorer produced, can
// drift from the machine view without any test noticing - which is exactly what C4 exists to stop.
package report

import (
	"bytes"
	"regexp"
	"strconv"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// canonicalComposite matches the composite line FAMILY-CONTRACT section 1 fixes: a grade letter and a
// two-decimal score out of one hundred.
var canonicalComposite = regexp.MustCompile(`(?m)^Composite: ([A-F]) \((\d+\.\d{2}) / 100\)$`)

// agreementReport builds one scored report both views render from.
func agreementReport(t *testing.T) analysis.Report {
	t.Helper()

	return analysis.NewReport(analysis.ReportInput{
		Root: "/workspace",
		Findings: []finding.Finding{
			{RuleID: "complexity.cognitive", Pillar: finding.PillarComplexity, Severity: finding.SeverityWarning, Confidence: finding.ConfidenceMedium, File: "a.go", Location: &finding.Location{Line: 3}, Message: "too complex"},
			{RuleID: "docs.package-comment", Pillar: finding.PillarDocumentation, Severity: finding.SeverityAdvisory, Confidence: finding.ConfidenceHigh, File: "b.go", Location: &finding.Location{Line: 1}, Message: "no package comment"},
		},
		Definitions: []rule.Definition{
			{Pillar: finding.PillarComplexity, DefaultEnabled: true},
			{Pillar: finding.PillarDocumentation, DefaultEnabled: true},
			{Pillar: finding.PillarSecurity, DefaultEnabled: true},
		},
		Scanned: []string{"a.go", "b.go", "c.go", "d.go"},
	})
}

// compositeFromText extracts the grade and score the canonical block published, failing the test when
// the block is absent or malformed rather than silently skipping the comparison.
func compositeFromText(t *testing.T, rendered string) (string, float64) {
	t.Helper()

	match := canonicalComposite.FindStringSubmatch(rendered)
	if match == nil {
		t.Fatalf("no canonical composite line in:\n%s", rendered)
	}

	value, err := strconv.ParseFloat(match[2], 64)
	if err != nil {
		t.Fatalf("composite %q is not a number: %v", match[2], err)
	}

	return match[1], value
}

// TestTextAndMachineViewsAgreeOnTheComposite proves both human views publish exactly the score and
// grade the envelope carries, for `analyse` and for `summary`.
func TestTextAndMachineViewsAgreeOnTheComposite(t *testing.T) {
	report := agreementReport(t)
	envelope, err := report.MachineEnvelope()
	if err != nil {
		t.Fatalf("machine envelope: %v", err)
	}

	machineScore, ok := envelope["score"].(map[string]any)
	if !ok {
		t.Fatal("machine envelope carries no score object")
	}

	composite, ok := machineScore["composite"].(map[string]any)
	if !ok {
		t.Fatal("machine score carries no composite object")
	}

	wantScore, ok := composite["score"].(*float64)
	if !ok || wantScore == nil {
		t.Fatalf("machine composite score = %#v, want a published number", composite["score"])
	}

	wantGrade, ok := composite["grade"].(*string)
	if !ok || wantGrade == nil {
		t.Fatalf("machine composite grade = %#v, want a published letter", composite["grade"])
	}

	views := map[string]func(*bytes.Buffer) error{
		"analyse": func(buffer *bytes.Buffer) error { return WriteText(buffer, report) },
		"summary": func(buffer *bytes.Buffer) error { return WriteSummaryText(buffer, report, SummaryOptions{Top: 5}) },
	}

	for name, render := range views {
		buffer := &bytes.Buffer{}
		if err := render(buffer); err != nil {
			t.Fatalf("%s render: %v", name, err)
		}

		grade, score := compositeFromText(t, buffer.String())

		if score != *wantScore {
			t.Errorf("%s text composite %v disagrees with machine composite %v", name, score, *wantScore)
		}

		if grade != *wantGrade {
			t.Errorf("%s text grade %q disagrees with machine grade %q", name, grade, *wantGrade)
		}
	}
}

// TestCanonicalBlockLeadsBothViews proves FAMILY-CONTRACT section 1's ordering: the masthead and the
// two-line composite block are the first three lines, and port-local detail sits below them.
func TestCanonicalBlockLeadsBothViews(t *testing.T) {
	report := agreementReport(t)
	views := map[string]func(*bytes.Buffer) error{
		"analyse": func(buffer *bytes.Buffer) error { return WriteText(buffer, report) },
		"summary": func(buffer *bytes.Buffer) error { return WriteSummaryText(buffer, report, SummaryOptions{Top: 5}) },
	}

	for name, render := range views {
		buffer := &bytes.Buffer{}
		if err := render(buffer); err != nil {
			t.Fatalf("%s render: %v", name, err)
		}

		lines := bytes.Split(buffer.Bytes(), []byte("\n"))
		if len(lines) < 3 {
			t.Fatalf("%s rendered %d lines, want at least the canonical block", name, len(lines))
		}

		if !canonicalComposite.Match(append(append([]byte{}, lines[1]...), '\n')) {
			t.Errorf("%s line 2 is not the canonical composite line: %q", name, lines[1])
		}

		if !bytes.HasPrefix(lines[2], []byte("Findings: ")) {
			t.Errorf("%s line 3 is not the canonical tally: %q", name, lines[2])
		}
	}
}
