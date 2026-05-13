package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

func TestMachineReportFormats(t *testing.T) {
	item := finding.Finding{
		RuleID:      "size-file-length",
		Message:     "too long",
		File:        "main.go",
		Location:    &finding.Location{Line: 12},
		Severity:    finding.SeverityMedium,
		Confidence:  finding.ConfidenceHigh,
		Pillar:      finding.PillarSize,
		Fingerprint: "abc123",
	}
	report := analysis.NewReport("/repo", []string{"."}, "sarif", finding.SeverityMedium, []string{"main.go"}, nil, nil, nil, []finding.Finding{item}, rule.Defaults().Definitions(), analysis.BaselineSummary{}, analysis.DiffSummary{})

	var sarif bytes.Buffer
	if err := WriteSARIF(&sarif, report); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(sarif.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid sarif json: %v\n%s", err, sarif.String())
	}
	if parsed["version"] != "2.1.0" || !strings.Contains(sarif.String(), `"ruleId": "size-file-length"`) {
		t.Fatalf("sarif output = %s", sarif.String())
	}

	var summary bytes.Buffer
	if err := WriteSummaryJSON(&summary, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.String(), `"findingsCount": 1`) || strings.Contains(summary.String(), `"findings":`) {
		t.Fatalf("summary output = %s", summary.String())
	}

	var github bytes.Buffer
	if err := WriteGitHub(&github, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(github.String(), "::warning file=main.go,line=12,title=size-file-length::too long") {
		t.Fatalf("github output = %s", github.String())
	}
}
