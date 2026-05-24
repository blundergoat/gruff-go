package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/baseline"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestSensitiveRedactionAcrossFormats protects the redaction contract: raw
// secret values must not appear in any output format, even when a rule emits a
// "preview" in its metadata.
func TestSensitiveRedactionAcrossFormats(t *testing.T) {
	rawSecret := "AKIAIOSFODNN7EXAMPLE"
	rawPassword := "supersecretpassword"
	rawPrivateKey := "-----BEGIN RSA PRIVATE KEY-----"
	rawNPMToken := "npm_00000000000000000000ZZ"
	rawGitLabToken := "glpat-aBcDeFgHiJkLmNoPqRsTuVwXyZ"

	report := analysis.NewReport(analysis.ReportInput{
		Root:    "/repo",
		Inputs:  []string{"."},
		Format:  "json",
		FailOn:  finding.SeverityMedium,
		Scanned: []string{"secrets.env"},
		Findings: []finding.Finding{
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
			{
				RuleID:     "sensitive-data.npm-token",
				Message:    "npm token literal detected",
				File:       "secrets.env",
				Location:   &finding.Location{Line: 4},
				Severity:   finding.SeverityHigh,
				Confidence: finding.ConfidenceHigh,
				Pillar:     finding.PillarSensitiveData,
				Metadata:   map[string]any{"preview": "npm_00..." + "00ZZ"},
			},
			{
				RuleID:     "sensitive-data.gitlab-token",
				Message:    "GitLab token literal detected",
				File:       "secrets.env",
				Location:   &finding.Location{Line: 5},
				Severity:   finding.SeverityHigh,
				Confidence: finding.ConfidenceHigh,
				Pillar:     finding.PillarSensitiveData,
				Metadata:   map[string]any{"preview": "glpat-..." + "VwXyZ"},
			},
		},
		Definitions: defaultDefinitions(),
	})

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

	leaks := []string{rawSecret, rawPassword, rawPrivateKey, rawNPMToken, rawGitLabToken}

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

func TestSensitiveRedactionAcrossRealArtifacts(t *testing.T) {
	rawSecret := "abcdefghijklmnopqrstuvwxyz123456"
	root := t.TempDir()
	secretLine := "auth_token = " + strconv.Quote(rawSecret)
	if err := os.WriteFile(filepath.Join(root, "secrets.env"), []byte(secretLine+"\n"), 0o600); err != nil {
		t.Fatalf("write secret fixture: %v", err)
	}

	reportData, err := analysis.Analyze(analysis.Options{
		Root:     root,
		Paths:    []string{"secrets.env"},
		Format:   "json",
		FailOn:   finding.SeverityMedium,
		Registry: rule.Defaults(),
	})
	if err != nil {
		t.Fatalf("analysis run: %v", err)
	}
	if len(reportData.Findings) != 1 || reportData.Findings[0].RuleID != "sensitive-data.secret-pattern" {
		t.Fatalf("findings = %#v, want one sensitive-data.secret-pattern finding", reportData.Findings)
	}
	encodedFinding, err := json.Marshal(reportData.Findings[0])
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	if strings.Contains(string(encodedFinding), rawSecret) {
		t.Fatalf("finding carries raw secret: %s", encodedFinding)
	}

	baselineFile := baseline.FromFindings(reportData.Findings)
	baselineJSON, err := baseline.Marshal(baselineFile)
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	applyResult := baseline.Apply(reportData.Findings, baselineFile)
	if applyResult.SuppressedFindings != 1 || len(applyResult.Findings) != 0 {
		t.Fatalf("baseline apply = %#v, want one suppressed finding", applyResult)
	}

	artifacts := map[string]string{
		"baseline": string(baselineJSON),
	}
	for _, format := range []struct {
		name string
		emit func(*bytes.Buffer) error
	}{
		{"text", func(buf *bytes.Buffer) error { return WriteText(buf, reportData) }},
		{"json", func(buf *bytes.Buffer) error { return WriteJSON(buf, reportData) }},
		{"summary-json", func(buf *bytes.Buffer) error { return WriteSummaryJSON(buf, reportData) }},
		{"sarif", func(buf *bytes.Buffer) error { return WriteSARIF(buf, reportData) }},
		{"github", func(buf *bytes.Buffer) error { return WriteGitHub(buf, reportData) }},
		{"html", func(buf *bytes.Buffer) error { return WriteHTML(buf, reportData, HTMLOptions{Interactive: true}) }},
	} {
		var buf bytes.Buffer
		if err := format.emit(&buf); err != nil {
			t.Fatalf("emit %s: %v", format.name, err)
		}
		artifacts[format.name] = buf.String()
	}
	artifacts["dashboard-html"] = InjectScanMetadata(artifacts["html"], ScanMetadata{
		ExitCode:    reportData.Summary.ExitCode,
		DurationMs:  12,
		ProjectRoot: root,
		Command:     "gruff-go analyse --format html secrets.env",
	})

	for name, artifact := range artifacts {
		if strings.Contains(artifact, rawSecret) {
			t.Fatalf("%s artifact leaks raw secret %q:\n%s", name, rawSecret, artifact)
		}
	}
}
