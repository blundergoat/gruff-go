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
	rawPassword := "supersecretQ7UX"
	rawPrivateKey := "-----BEGIN RSA PRIVATE KEY-----"
	rawNPMToken := "npm_00000000000000000000ZZ"
	rawGitLabToken := "glpat-aBcDeFgHiJkLmNoPqRsTuVwXyZ"

	report := analysis.NewReport(analysis.ReportInput{
		Root:    "/repo",
		Inputs:  []string{"."},
		Format:  "json",
		FailOn:  finding.FailThresholdWarning,
		Scanned: []string{"secrets.env"},
		Findings: []finding.Finding{
			{
				RuleID:     "sensitive-data.aws-access-key",
				Message:    "AWS access key id detected",
				File:       "secrets.env",
				Location:   &finding.Location{Line: 1},
				Severity:   finding.SeverityError,
				Confidence: finding.ConfidenceHigh,
				Pillar:     finding.PillarSensitiveData,
				Metadata:   map[string]any{"preview": "[redacted:aws-access-key]"},
			},
			{
				RuleID:     "sensitive-data.connection-string",
				Message:    "connection string with embedded password detected",
				File:       "secrets.env",
				Location:   &finding.Location{Line: 2},
				Severity:   finding.SeverityError,
				Confidence: finding.ConfidenceMedium,
				Pillar:     finding.PillarSensitiveData,
				Metadata:   map[string]any{"preview": "[redacted:connection-string:postgres]"},
			},
			{
				RuleID:     "sensitive-data.private-key",
				Message:    "private key literal detected",
				File:       "secrets.env",
				Location:   &finding.Location{Line: 3},
				Severity:   finding.SeverityError,
				Confidence: finding.ConfidenceHigh,
				Pillar:     finding.PillarSensitiveData,
				Metadata:   map[string]any{"preview": "[redacted:private-key]"},
			},
			{
				RuleID:     "sensitive-data.npm-token",
				Message:    "npm token literal detected",
				File:       "secrets.env",
				Location:   &finding.Location{Line: 4},
				Severity:   finding.SeverityError,
				Confidence: finding.ConfidenceHigh,
				Pillar:     finding.PillarSensitiveData,
				Metadata:   map[string]any{"preview": "[redacted:npm-token]"},
			},
			{
				RuleID:     "sensitive-data.gitlab-token",
				Message:    "GitLab token literal detected",
				File:       "secrets.env",
				Location:   &finding.Location{Line: 5},
				Severity:   finding.SeverityError,
				Confidence: finding.ConfidenceHigh,
				Pillar:     finding.PillarSensitiveData,
				Metadata:   map[string]any{"preview": "[redacted:gitlab-token]"},
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
		{"markdown", func(buf *bytes.Buffer) error { return WriteMarkdown(buf, report) }},
	}

	leaks := []string{
		rawSecret, rawSecret[4:10], rawSecret[len(rawSecret)-4:],
		rawPassword, rawPassword[:6], rawPassword[len(rawPassword)-4:],
		rawPrivateKey, rawPrivateKey[:6],
		rawNPMToken, rawNPMToken[4:10], rawNPMToken[len(rawNPMToken)-4:],
		rawGitLabToken, rawGitLabToken[6:12], rawGitLabToken[len(rawGitLabToken)-4:],
	}

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
		FailOn:   finding.FailThresholdWarning,
		Registry: rule.Defaults(),
	})
	if err != nil {
		t.Fatalf("analysis run: %v", err)
	}
	// Two findings since 2026-09-07: sensitive-data.high-entropy-string is enabled by default
	// under the ratified contract, and the same artifact trips it alongside the secret-pattern
	// rule. Both must redact, which is what this test is really about.
	if len(reportData.Findings) != 2 {
		t.Fatalf("findings = %#v, want the secret-pattern and high-entropy findings", reportData.Findings)
	}
	byRule := map[string]bool{}
	for _, item := range reportData.Findings {
		byRule[item.RuleID] = true
	}
	for _, wanted := range []string{"sensitive-data.secret-pattern", "sensitive-data.high-entropy-string"} {
		if !byRule[wanted] {
			t.Fatalf("findings = %#v, want one %s finding", reportData.Findings, wanted)
		}
	}
	encodedFinding, err := json.Marshal(reportData.Findings[0])
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	if strings.Contains(string(encodedFinding), rawSecret) {
		t.Fatalf("finding carries raw secret: %s", encodedFinding)
	}

	baselineFile, err := baseline.FromFindings(reportData.Findings)
	if err != nil {
		t.Fatalf("build baseline: %v", err)
	}
	baselineJSON, err := baseline.Marshal(baselineFile)
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	applyResult, err := baseline.Apply(reportData.Findings, baselineFile)
	if err != nil {
		t.Fatalf("apply baseline: %v", err)
	}
	// A secret is never baseline-eligible: it is counted, never stored as an entry, and never hidden on the next run.
	// Both sensitive findings are covered since the high-entropy rule became default-enabled on 2026-09-07, which
	// strengthens this control rather than weakening it: two secrets must now stay visible where one did.
	if applyResult.NotEligibleFindings != 2 || applyResult.SuppressedFindings != 0 || len(applyResult.Findings) != 2 || len(baselineFile.Occurrences) != 0 {
		t.Fatalf("baseline apply = %#v, want the sensitive finding counted and still visible", applyResult)
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
		{"markdown", func(buf *bytes.Buffer) error { return WriteMarkdown(buf, reportData) }},
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
