// Package report renders gruff-go analysis results into output formats.
// This file holds the core tests for the HTML report renderer.
package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// defaultDefinitions returns the rule definitions registered by Defaults for test fixtures.
func defaultDefinitions() []rule.Definition {
	defaults := rule.Defaults()
	return defaults.Definitions()
}

// TestWriteHTMLRendersCoreSections checks that the rendered HTML contains every required document section.
func TestWriteHTMLRendersCoreSections(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()

	requiredFragments := []string{
		`<!DOCTYPE html>`,
		`<html lang="en-NZ">`,
		`<div class="paper">`,
		`<span class="corner-tr"></span><span class="corner-bl"></span>`,
		`<header class="masthead">`,
		`<div class="wordmark">gruff</div>`,
		`<section class="verdict">`,
		`<div class="grade-stamp `,
		`<h2 class="section-head">pillar grades`,
		`<h2 class="section-head">top offenders`,
		`<th scope="col">file</th>`,
		`<h2 class="section-head">distribution`,
		`<h2 class="section-head">flagged findings`,
		`<footer class="footer">`,
	}
	for _, fragment := range requiredFragments {
		if !strings.Contains(body, fragment) {
			t.Errorf("missing fragment %q in rendered HTML", fragment)
		}
	}
}

// TestWriteHTMLSelfContained ensures the rendered HTML references no external links or scripts.
func TestWriteHTMLSelfContained(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	forbidden := []string{
		`<link `,
		`<script src=`,
		`http://`,
		`https://`,
	}
	for _, fragment := range forbidden {
		if strings.Contains(body, fragment) {
			t.Errorf("rendered HTML must be self-contained; found %q", fragment)
		}
	}
}

// TestWriteHTMLCelebrationSubtitle verifies the celebratory subtitle when there are no flagged findings.
func TestWriteHTMLCelebrationSubtitle(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "html",
		FailOn:      finding.SeverityMedium,
		Scanned:     []string{"main.go"},
		Definitions: defaultDefinitions(),
	})
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	if !strings.Contains(out.String(), "No medium or higher severity findings flagged.") {
		t.Errorf("expected celebration subtitle, got: %s", out.String())
	}
}

// TestWriteHTMLDataDrivenSubtitle verifies the data-driven subtitle when threshold findings exist.
func TestWriteHTMLDataDrivenSubtitle(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "at medium or higher severity across") {
		t.Errorf("expected data-driven subtitle, got: %s", body)
	}
}

// TestWriteHTMLSeverityTiers checks the severity badges render with the correct tier class.
func TestWriteHTMLSeverityTiers(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	cases := []struct {
		fragment string
		desc     string
	}{
		{`<div class="severity fail">critical</div>`, "critical severity uses fail tier"},
		{`<div class="severity fail">high</div>`, "high severity uses fail tier"},
		{`<div class="severity warn">medium</div>`, "medium severity uses warn tier"},
		{`<div class="severity note">low</div>`, "low severity uses note tier"},
	}
	for _, tc := range cases {
		if !strings.Contains(body, tc.fragment) {
			t.Errorf("%s: missing %q", tc.desc, tc.fragment)
		}
	}
}

// TestWriteHTMLEditorLinkNone asserts that file locations are emitted as plain spans when editor links are disabled.
func TestWriteHTMLEditorLinkNone(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	if strings.Contains(body, `<a class="loc-link" href=`) {
		t.Error("EditorLink=none should not emit href anchors")
	}
	if !strings.Contains(body, `<span class="loc-link" tabindex="0" data-path=`) {
		t.Error("EditorLink=none should emit selectable span data-path")
	}
}

// TestWriteHTMLEditorLinkVSCode asserts the VS Code editor scheme is emitted when requested.
func TestWriteHTMLEditorLinkVSCode(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{EditorLink: "vscode", ProjectRoot: "/repo"}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, `href="vscode://file/repo/`) {
		t.Errorf("EditorLink=vscode should emit vscode:// href; got body: %s", body)
	}
}

// TestWriteHTMLEditorLinkPhpStorm asserts the PhpStorm editor scheme is emitted when requested.
func TestWriteHTMLEditorLinkPhpStorm(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{EditorLink: "phpstorm", ProjectRoot: "/repo"}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, `href="phpstorm://open?file=`) {
		t.Errorf("EditorLink=phpstorm should emit phpstorm:// href; got body: %s", body)
	}
}

// TestWriteHTMLCyclomaticSummaryAndBins checks the histogram caption and bin tier classes render correctly.
func TestWriteHTMLCyclomaticSummaryAndBins(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "exceed CC 10") {
		t.Error("expected cyclomatic summary above histogram")
	}
	if !strings.Contains(body, `class="bar warn"`) {
		t.Error("11-15 bin should render with warn class")
	}
	if !strings.Contains(body, `class="bar fail"`) {
		t.Error("16-20 or 21+ bin should render with fail class")
	}
}

// TestWriteHTMLEscapesMaliciousInput ensures user-supplied strings are HTML-escaped in the rendered report.
func TestWriteHTMLEscapesMaliciousInput(t *testing.T) {
	malicious := finding.Finding{
		RuleID:     "test.rule",
		Message:    `<script>alert("xss")</script>`,
		File:       `evil.go"`,
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceHigh,
		Pillar:     finding.PillarSize,
	}
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{`<img src=x>`},
		Format:      "html",
		FailOn:      finding.SeverityMedium,
		Scanned:     []string{"evil.go"},
		Findings:    []finding.Finding{malicious},
		Definitions: defaultDefinitions(),
	})
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	if strings.Contains(body, `<script>alert("xss")</script>`) {
		t.Error("malicious script payload was not escaped")
	}
	if !strings.Contains(body, `&lt;script&gt;`) {
		t.Error("expected escaped script tag")
	}
	if strings.Contains(body, `<img src=x>`) {
		t.Error("malicious input path was not escaped")
	}
}

// TestWriteHTMLDiagnosticsRender verifies that the diagnostics section appears when diagnostics are present.
func TestWriteHTMLDiagnosticsRender(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:    "/repo",
		Inputs:  []string{"."},
		Format:  "html",
		FailOn:  finding.SeverityMedium,
		Scanned: []string{"a.go"},
		Diagnostics: []analysis.Diagnostic{{
			Stage:    "parse",
			Message:  "syntax error",
			File:     "broken.go",
			Severity: finding.SeverityHigh,
		}},
		Definitions: defaultDefinitions(),
	})
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, `<section class="diagnostics">`) {
		t.Error("diagnostics section should render when diagnostics are present")
	}
	if !strings.Contains(body, "syntax error") {
		t.Error("diagnostic message should be visible")
	}
}

// TestWriteHTMLDiffScopeLabel checks the masthead scope label reflects diff-scope runs.
func TestWriteHTMLDiffScopeLabel(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "html",
		FailOn:      finding.SeverityMedium,
		Scanned:     []string{"a.go"},
		Definitions: defaultDefinitions(),
		Diff:        analysis.DiffSummary{Enabled: true, Base: "main", ChangedFiles: []string{"a.go", "b.go"}},
	})
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	if !strings.Contains(out.String(), "diff · 2 changed files") {
		t.Errorf("expected diff scope label with changed-files count; got: %s", out.String())
	}
}

// buildHTMLFixture returns a synthetic report covering each severity tier and histogram bin used by the HTML tests.
func buildHTMLFixture() analysis.Report {
	findings := []finding.Finding{
		{
			RuleID:     "complexity.cyclomatic",
			Message:    "function exceeds cyclomatic threshold",
			File:       "hot.go",
			Location:   &finding.Location{Line: 42},
			Severity:   finding.SeverityHigh,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarComplexity,
			Metadata:   map[string]any{"complexity": 24},
		},
		{
			RuleID:     "complexity.cyclomatic",
			Message:    "function exceeds cyclomatic threshold",
			File:       "hot.go",
			Location:   &finding.Location{Line: 90},
			Severity:   finding.SeverityCritical,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarComplexity,
			Metadata:   map[string]any{"complexity": 45},
		},
		{
			RuleID:     "size.file-length",
			Message:    "file is long",
			File:       "warm.go",
			Location:   &finding.Location{Line: 1},
			Severity:   finding.SeverityMedium,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarSize,
		},
		{
			RuleID:     "naming.local-short",
			Message:    "identifier is short",
			File:       "warm.go",
			Location:   &finding.Location{Line: 10},
			Severity:   finding.SeverityLow,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarNaming,
		},
	}
	// Need to also forge an 11-15 bin entry so we test warn tier on the histogram.
	findings = append(findings, finding.Finding{
		RuleID:     "complexity.cyclomatic",
		Message:    "function exceeds cyclomatic threshold",
		File:       "medium.go",
		Location:   &finding.Location{Line: 5},
		Severity:   finding.SeverityMedium,
		Confidence: finding.ConfidenceMedium,
		Pillar:     finding.PillarComplexity,
		Metadata:   map[string]any{"complexity": 12},
	})
	return analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "html",
		FailOn:      finding.SeverityMedium,
		Scanned:     []string{"hot.go", "warm.go", "medium.go"},
		Findings:    findings,
		Definitions: defaultDefinitions(),
	})
}
