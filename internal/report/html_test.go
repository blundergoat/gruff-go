package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

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

func TestWriteHTMLCelebrationSubtitle(t *testing.T) {
	report := analysis.NewReport(
		"/repo",
		[]string{"."},
		"html",
		finding.SeverityMedium,
		false,
		[]string{"main.go"},
		nil, nil, nil,
		nil,
		rule.Defaults().Definitions(),
		analysis.BaselineSummary{},
		analysis.DiffSummary{},
	)
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	if !strings.Contains(out.String(), "No medium or higher severity findings flagged.") {
		t.Errorf("expected celebration subtitle, got: %s", out.String())
	}
}

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

func TestWriteHTMLEscapesMaliciousInput(t *testing.T) {
	malicious := finding.Finding{
		RuleID:     "test.rule",
		Message:    `<script>alert("xss")</script>`,
		File:       `evil.go"`,
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceHigh,
		Pillar:     finding.PillarSize,
	}
	report := analysis.NewReport(
		"/repo",
		[]string{`<img src=x>`},
		"html",
		finding.SeverityMedium,
		false,
		[]string{"evil.go"},
		nil, nil, nil,
		[]finding.Finding{malicious},
		rule.Defaults().Definitions(),
		analysis.BaselineSummary{},
		analysis.DiffSummary{},
	)
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

func TestWriteHTMLDiagnosticsRender(t *testing.T) {
	report := analysis.NewReport(
		"/repo",
		[]string{"."},
		"html",
		finding.SeverityMedium,
		false,
		[]string{"a.go"},
		nil, nil,
		[]analysis.Diagnostic{{
			Stage:    "parse",
			Message:  "syntax error",
			File:     "broken.go",
			Severity: finding.SeverityHigh,
		}},
		nil,
		rule.Defaults().Definitions(),
		analysis.BaselineSummary{},
		analysis.DiffSummary{},
	)
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

func TestWriteHTMLDiffScopeLabel(t *testing.T) {
	report := analysis.NewReport(
		"/repo",
		[]string{"."},
		"html",
		finding.SeverityMedium,
		false,
		[]string{"a.go"},
		nil, nil, nil,
		nil,
		rule.Defaults().Definitions(),
		analysis.BaselineSummary{},
		analysis.DiffSummary{Enabled: true, Base: "main", ChangedFiles: []string{"a.go", "b.go"}},
	)
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	if !strings.Contains(out.String(), "diff · 2 changed files") {
		t.Errorf("expected diff scope label with changed-files count; got: %s", out.String())
	}
}

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
	return analysis.NewReport(
		"/repo",
		[]string{"."},
		"html",
		finding.SeverityMedium,
		false,
		[]string{"hot.go", "warm.go", "medium.go"},
		nil, nil, nil,
		findings,
		rule.Defaults().Definitions(),
		analysis.BaselineSummary{},
		analysis.DiffSummary{},
	)
}
