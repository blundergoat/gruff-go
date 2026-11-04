// Package report renders gruff-go analysis results into output formats.
//
// This file holds tests for the markdown reporter: the summary lines, the canonical Pillars table, the optional Top rules table and pipe escaping.
package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestWriteMarkdownRendersCoreSections checks the markdown renderer emits its core sections when findings exist.
//
// It expects the title, composite and schema lines, severity counts, and the Pillars and Top rules tables for the five fixture findings.
func TestWriteMarkdownRendersCoreSections(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteMarkdown(&out, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	body := out.String()

	required := []string{
		"# gruff-go report",
		"Composite: **",
		"**Schema:** `gruff.analysis.v3`",
		"**Files:** 3 scanned, 0 skipped",
		"Findings: 5 total · 2 error · 2 warning · 1 advisory",
		"\n## Pillars\n",
		"| Pillar | Grade | Score | Findings | Advisory | Warning | Error |",
		"| --- | --- | ---: | ---: | ---: | ---: | ---: |",
		"\n## Top rules\n",
		"| Rule | Count |",
		"|---|---:|",
		"| `complexity.cyclomatic` | 3 |",
	}
	for _, fragment := range required {
		if !strings.Contains(body, fragment) {
			t.Errorf("markdown missing fragment %q; got:\n%s", fragment, body)
		}
	}
}

// TestWriteMarkdownPillarsTableShape checks the canonical pillar row names, a two-decimal score marker and the fixture's row order.
// Every canonical pillar needs a row, 100.00 must appear, and rows sort by findings DESC, then pillar ASC.
func TestWriteMarkdownPillarsTableShape(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteMarkdown(&out, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	body := out.String()

	wantPillars := []string{
		"size", "complexity", "documentation", "sensitive-data", "security",
		"test-quality", "naming", "maintainability", "dead-code", "modernisation",
	}
	for _, pillar := range wantPillars {
		marker := "| " + pillar + " | "
		if !strings.Contains(body, marker) {
			t.Errorf("pillars table missing row for %q; got:\n%s", pillar, body)
		}
	}
	// Score must render with two decimal places (clean pillars show 100.00).
	if !strings.Contains(body, "100.00") {
		t.Errorf("pillar score should render with 2 decimals; body missing 100.00:\n%s", body)
	}
	// Sort order is findings DESC, then pillar ASC.
	//
	// The fixture has complexity (3), naming (1) and size (1); the remaining seven canonical pillars are clean.
	// complexity comes first, and naming precedes size on the ASC tie-break.
	indexComplexity := strings.Index(body, "| complexity |")
	indexNaming := strings.Index(body, "| naming |")
	indexSize := strings.Index(body, "| size |")
	if indexComplexity < 0 || indexNaming < 0 || indexSize < 0 {
		t.Fatalf("expected rows; got complexity=%d naming=%d size=%d", indexComplexity, indexNaming, indexSize)
	}
	if !(indexComplexity < indexNaming && indexNaming < indexSize) {
		t.Errorf("rows not sorted findings DESC then pillar ASC: complexity=%d naming=%d size=%d", indexComplexity, indexNaming, indexSize)
	}
}

// TestWriteMarkdownCleanScan asserts a zero-finding scan still emits every canonical pillar row at grade A and score 100.00.
//
// It also expects all-zero severity totals and no Top rules section.
func TestWriteMarkdownCleanScan(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "markdown",
		FailOn:      finding.FailThresholdWarning,
		Scanned:     []string{"main.go"},
		Definitions: defaultDefinitions(),
	})
	var out bytes.Buffer
	if err := WriteMarkdown(&out, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	body := out.String()
	wantPillars := []string{
		"size", "complexity", "documentation", "sensitive-data", "security",
		"test-quality", "naming", "maintainability", "dead-code", "modernisation",
	}
	for _, pillar := range wantPillars {
		marker := "| " + pillar + " | A | 100.00 | 0 | 0 | 0 | 0 |"
		if !strings.Contains(body, marker) {
			t.Errorf("clean-scan markdown missing canonical row %q; got:\n%s", marker, body)
		}
	}
	if strings.Contains(body, "## Top rules") {
		t.Errorf("clean scan should omit the Top rules section; got:\n%s", body)
	}
	if !strings.Contains(body, "Findings: 0 total · 0 error · 0 warning · 0 advisory\n") {
		t.Errorf("clean scan severity totals incorrect; got:\n%s", body)
	}
}

// TestWriteMarkdownEscapesPipeInCells checks that a pipe in a table cell, here a pillar name, is escaped as \| so it cannot split the row.
func TestWriteMarkdownEscapesPipeInCells(t *testing.T) {
	row := PillarSummaryRow{Pillar: "a|b", Grade: "F", Score: 0, Findings: 1}
	var out bytes.Buffer
	if err := writeMarkdownPillarsTable(&out, []PillarSummaryRow{row}); err != nil {
		t.Fatalf("writeMarkdownPillarsTable: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, `| a\|b | F |`) {
		t.Errorf("pipe in pillar name should be escaped; got:\n%s", body)
	}
}

// TestWriteMarkdownEmptyPillarsBlock checks the Pillars section still prints its header and a _(none)_ placeholder when given no rows.
//
// BuildPillarSummaryRows always returns ten rows in production, so this guards only the renderer's fallback.
func TestWriteMarkdownEmptyPillarsBlock(t *testing.T) {
	var out bytes.Buffer
	if err := writeMarkdownPillarsTable(&out, nil); err != nil {
		t.Fatalf("writeMarkdownPillarsTable: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "## Pillars") {
		t.Errorf("empty pillars block should still emit header; got:\n%s", body)
	}
	if !strings.Contains(body, "_(none)_") {
		t.Errorf("empty pillars block should emit placeholder row; got:\n%s", body)
	}
}
