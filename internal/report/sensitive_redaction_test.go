package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestSensitiveRedactionAcrossFormats is the load-bearing redaction guarantee
// from M07: raw secret values must not appear in any output format, even
// when a rule emits a "preview" in its metadata.
func TestSensitiveRedactionAcrossFormats(t *testing.T) {
	rawSecret := "AKIAIOSFODNN7EXAMPLE"
	rawPassword := "supersecretpassword"
	rawPrivateKey := "-----BEGIN RSA PRIVATE KEY-----"

	report := analysis.NewReport(
		"/repo",
		[]string{"."},
		"json",
		finding.SeverityMedium,
		false,
		[]string{"secrets.env"},
		nil, nil, nil,
		[]finding.Finding{
			{
				RuleID:     "sensitive-data.aws-access-key",
				Message:    "AWS access key id detected",
				File:       "secrets.env",
				Location:   &finding.Location{Line: 1},
				Severity:   finding.SeverityHigh,
				Confidence: finding.ConfidenceHigh,
				Pillar:     finding.PillarSensitiveData,
				Metadata:   map[string]any{"preview": "AKIAIO..." + "PLE"},
			},
			{
				RuleID:     "sensitive-data.connection-string",
				Message:    "connection string with embedded password detected",
				File:       "secrets.env",
				Location:   &finding.Location{Line: 2},
				Severity:   finding.SeverityHigh,
				Confidence: finding.ConfidenceMedium,
				Pillar:     finding.PillarSensitiveData,
				Metadata:   map[string]any{"preview": "postgres://app:su..." + "ders"},
			},
			{
				RuleID:     "sensitive-data.private-key",
				Message:    "private key literal detected",
				File:       "secrets.env",
				Location:   &finding.Location{Line: 3},
				Severity:   finding.SeverityCritical,
				Confidence: finding.ConfidenceHigh,
				Pillar:     finding.PillarSensitiveData,
				Metadata:   map[string]any{"preview": "-----B..." + "KEY-"},
			},
		},
		rule.Defaults().Definitions(),
		analysis.BaselineSummary{},
		analysis.DiffSummary{},
	)

	formats := []struct {
		name string
		emit func(*bytes.Buffer) error
	}{
		{"text", func(buf *bytes.Buffer) error { return WriteText(buf, report) }},
		{"json", func(buf *bytes.Buffer) error { return WriteJSON(buf, report) }},
		{"summary-json", func(buf *bytes.Buffer) error { return WriteSummaryJSON(buf, report) }},
		{"sarif", func(buf *bytes.Buffer) error { return WriteSARIF(buf, report) }},
		{"github", func(buf *bytes.Buffer) error { return WriteGitHub(buf, report) }},
		{"html", func(buf *bytes.Buffer) error { return WriteHTML(buf, report, HTMLOptions{}) }},
	}

	leaks := []string{rawSecret, rawPassword, rawPrivateKey}

	for _, format := range formats {
		t.Run(format.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := format.emit(&buf); err != nil {
				t.Fatalf("emit %s: %v", format.name, err)
			}
			out := buf.String()
			for _, leak := range leaks {
				if strings.Contains(out, leak) {
					t.Errorf("%s output leaks raw secret %q", format.name, leak)
				}
			}
		})
	}
}
