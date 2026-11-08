// Package report renders gruff-go analysis results into output formats.
//
// This file holds the core tests for the HTML report renderer: required sections, self-containment, escaping, editor links and the pillars table.
// It also defines buildHTMLFixture, which the markdown and interactive tests reuse, so a fixture change moves their expected counts too.
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
// The result is the default registry's Definitions list, unfiltered, so fixture reports see the full built-in rule set.
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
		`<h2 class="section-head">pillars`,
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
// It rejects only the literal substrings <link , <script src=, http:// and https:// anywhere in the body, even in report text.
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
		FailOn:      finding.FailThresholdWarning,
		Scanned:     []string{"main.go"},
		Definitions: defaultDefinitions(),
	})
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	if !strings.Contains(out.String(), "No warning or higher severity findings flagged.") {
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
	if !strings.Contains(body, "at warning or higher severity across") {
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
		{`<div class="severity fail">error</div>`, "error severity uses fail tier"},
		{`<div class="severity warn">warning</div>`, "warning severity uses warn tier"},
		{`<div class="severity note">advisory</div>`, "advisory severity uses note tier"},
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
// With CC 12, 24 and 45 findings in the fixture, it expects at least one bar with the warn class and one with the fail class.
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
// It checks that a script tag in a finding message and an img tag in an input path never appear raw, and that the script tag appears escaped.
func TestWriteHTMLEscapesMaliciousInput(t *testing.T) {
	malicious := finding.Finding{
		RuleID:     "test.rule",
		Message:    `<script>alert("xss")</script>`,
		File:       `evil.go"`,
		Severity:   finding.SeverityError,
		Confidence: finding.ConfidenceHigh,
		Pillar:     finding.PillarSize,
	}
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{`<img src=x>`},
		Format:      "html",
		FailOn:      finding.FailThresholdWarning,
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
		FailOn:  finding.FailThresholdWarning,
		Scanned: []string{"a.go"},
		Diagnostics: []analysis.Diagnostic{{
			Stage:    "parse",
			Message:  "syntax error",
			File:     "broken.go",
			Severity: finding.SeverityError,
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

// TestWriteHTMLPillarsTableMatchesCanonicalShape checks the expected column headers and all ten canonical pillar name cells.
//
// It also checks for a 100.00 marker and the fixture's complexity-before-naming-before-size order.
func TestWriteHTMLPillarsTableMatchesCanonicalShape(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	for _, header := range []string{
		`<th scope="col">pillar</th>`,
		`<th scope="col" class="num">grade</th>`,
		`<th scope="col" class="num">score</th>`,
		`<th scope="col" class="num">findings</th>`,
		`<th scope="col" class="num">advisory</th>`,
		`<th scope="col" class="num">warning</th>`,
		`<th scope="col" class="num">error</th>`,
	} {
		if !strings.Contains(body, header) {
			t.Errorf("missing pillar table header %q", header)
		}
	}
	wantPillars := []string{
		"size", "complexity", "documentation", "sensitive-data", "security",
		"test-quality", "naming", "maintainability", "dead-code", "modernisation",
	}
	for _, pillar := range wantPillars {
		marker := `<td class="pillar-name">` + pillar + `</td>`
		if !strings.Contains(body, marker) {
			t.Errorf("pillar table missing row for %q", pillar)
		}
	}
	// Score must render with two decimal places (e.g. 100.00, not 100).
	if !strings.Contains(body, `>100.00<`) {
		t.Errorf("pillar score should render with 2 decimals; body did not contain 100.00")
	}
	// Sort order is findings DESC, then pillar ASC.
	//
	// The fixture has complexity (3), naming (1) and size (1); the other seven pillars have 0 findings.
	// complexity leads on count, and naming precedes size on the ASC tie-break.
	indexComplexity := strings.Index(body, `<td class="pillar-name">complexity</td>`)
	indexSize := strings.Index(body, `<td class="pillar-name">size</td>`)
	indexNaming := strings.Index(body, `<td class="pillar-name">naming</td>`)
	if indexComplexity < 0 || indexSize < 0 || indexNaming < 0 {
		t.Fatalf("expected complexity, size, naming rows; got indices %d/%d/%d", indexComplexity, indexSize, indexNaming)
	}
	if !(indexComplexity < indexNaming && indexNaming < indexSize) {
		t.Errorf("pillar rows not sorted findings DESC then pillar ASC: complexity=%d naming=%d size=%d", indexComplexity, indexNaming, indexSize)
	}
}

// TestWriteHTMLPillarsTableCleanScan checks that a zero-finding scan renders all ten canonical pillar name cells.
// It also requires at least ten grade A markers and at least ten 100.00 markers anywhere in the HTML.
func TestWriteHTMLPillarsTableCleanScan(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "html",
		FailOn:      finding.FailThresholdWarning,
		Scanned:     []string{"main.go"},
		Definitions: defaultDefinitions(),
	})
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	wantPillars := []string{
		"size", "complexity", "documentation", "sensitive-data", "security",
		"test-quality", "naming", "maintainability", "dead-code", "modernisation",
	}
	for _, pillar := range wantPillars {
		marker := `<td class="pillar-name">` + pillar + `</td>`
		if !strings.Contains(body, marker) {
			t.Errorf("clean-scan pillar table missing row for %q", pillar)
		}
	}
	if strings.Count(body, `<span class="grade-pill a">A</span>`) < len(wantPillars) {
		t.Errorf("clean-scan pillar table should render every row at grade A; got body:\n%s", body)
	}
	if strings.Count(body, `>100.00<`) < len(wantPillars) {
		t.Errorf("clean-scan pillar table should render every row at score 100.00")
	}
}

// TestWriteHTMLDiffScopeLabel checks the masthead scope label reflects diff-scope runs.
func TestWriteHTMLDiffScopeLabel(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "html",
		FailOn:      finding.FailThresholdWarning,
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
//
// The result is a report over hot.go, warm.go and medium.go holding five findings.
// The markdown and interactive tests reuse it, so a fixture change moves their hardcoded counts.
// hot.go has error findings at CC 24 and 45; medium.go has a warning at CC 12; warm.go has a size warning and a naming advisory.
func buildHTMLFixture() analysis.Report {
	findings := []finding.Finding{
		{
			RuleID:     "complexity.cyclomatic",
			Message:    "function exceeds cyclomatic threshold",
			File:       "hot.go",
			Location:   &finding.Location{Line: 42},
			Severity:   finding.SeverityError,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarComplexity,
			Metadata:   map[string]any{"complexity": 24},
		},
		{
			RuleID:     "complexity.cyclomatic",
			Message:    "function exceeds cyclomatic threshold",
			File:       "hot.go",
			Location:   &finding.Location{Line: 90},
			Severity:   finding.SeverityError,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarComplexity,
			Metadata:   map[string]any{"complexity": 45},
		},
		{
			RuleID:     "size.file-length",
			Message:    "file is long",
			File:       "warm.go",
			Location:   &finding.Location{Line: 1},
			Severity:   finding.SeverityWarning,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarSize,
		},
		{
			RuleID:     "naming.local-short",
			Message:    "identifier is short",
			File:       "warm.go",
			Location:   &finding.Location{Line: 10},
			Severity:   finding.SeverityAdvisory,
			Confidence: finding.ConfidenceHigh,
			Pillar:     finding.PillarNaming,
		},
	}
	// The CC 12 finding puts data in the 11-15 bin for the warn bar that TestWriteHTMLCyclomaticSummaryAndBins checks.
	findings = append(findings, finding.Finding{
		RuleID:     "complexity.cyclomatic",
		Message:    "function exceeds cyclomatic threshold",
		File:       "medium.go",
		Location:   &finding.Location{Line: 5},
		Severity:   finding.SeverityWarning,
		Confidence: finding.ConfidenceMedium,
		Pillar:     finding.PillarComplexity,
		Metadata:   map[string]any{"complexity": 12},
	})
	return analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "html",
		FailOn:      finding.FailThresholdWarning,
		Scanned:     []string{"hot.go", "warm.go", "medium.go"},
		Findings:    findings,
		Definitions: defaultDefinitions(),
	})
}
