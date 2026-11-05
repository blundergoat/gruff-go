// Package report renders gruff-go analysis results into output formats.
//
// This file covers the cross-port canonical summary digest in text and v3 JSON.
// A failure can mean drift in the rendered text or JSON, or in pillar-row values such as Penalty that the text block does not print.
package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/scoring"
)

// TestSummarySchemaVersion locks down the cross-port summary digest schema string.
// A failure means the schema string moved off gruff.summary.v3, which the other ports publish too.
func TestSummarySchemaVersion(t *testing.T) {
	if SummarySchemaVersion != "gruff.summary.v3" {
		t.Fatalf("SummarySchemaVersion = %q, want %q", SummarySchemaVersion, "gruff.summary.v3")
	}
}

// TestBuildPillarSummaryRowsCleanScan asserts a clean scan yields all ten canonical pillars at grade A, score 100 and zero counts.
//
// That keeps the summary block's row set fixed; the test also checks Penalty 0 and Applicable true on every clean row.
// A failure means the clean row set, one of those row values, or the pillar-name tie-break is wrong.
func TestBuildPillarSummaryRowsCleanScan(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "json",
		FailOn:      finding.FailThresholdWarning,
		Scanned:     []string{"main.go"},
		Findings:    nil,
		Definitions: defaultDefinitions(),
	})
	rows := BuildPillarSummaryRows(report)
	if len(rows) != 10 {
		t.Fatalf("rows = %d, want 10", len(rows))
	}
	wantNames := map[string]bool{
		"size": true, "complexity": true, "documentation": true,
		"sensitive-data": true, "security": true, "test-quality": true,
		"naming": true, "maintainability": true, "dead-code": true,
		"modernisation": true,
	}
	for _, row := range rows {
		if !wantNames[row.Pillar] {
			t.Errorf("unexpected pillar %q", row.Pillar)
		}
		if row.Grade != "A" || row.Score != 100 || row.Findings != 0 || row.Advisory != 0 || row.Warning != 0 || row.Error != 0 {
			t.Errorf("clean pillar %q = %#v, want grade A, score 100, zero counts", row.Pillar, row)
		}
		if row.Penalty != 0 {
			t.Errorf("clean pillar %q penalty = %v, want 0", row.Pillar, row.Penalty)
		}
		if !row.Applicable {
			t.Errorf("clean pillar %q applicable = false, want true", row.Pillar)
		}
	}
	// With every count tied at zero, rows fall back to pillar name order, so test-quality sorts last.
	if row := rows[len(rows)-1]; row.Pillar != "test-quality" {
		t.Errorf("last clean row = %q, want test-quality (ASC tie-break)", row.Pillar)
	}
}

// pillarDetail fills in the nullable score and grade the ratified contract publishes for a pillar fixture.
//
// A fixture can then state its counts as a plain literal without repeating the address dance for two pointers.
//
// base carries the pillar name and counts; it is passed by value, so the caller's literal is left untouched.
// It returns that copy of base with Applicable set to true and Score and Grade pointing at score and grade, so neither pointer is nil.
func pillarDetail(base scoring.PillarDetail, score float64, grade string) scoring.PillarDetail {
	base.Applicable = true
	base.Score = &score
	base.Grade = &grade
	return base
}

// TestBuildPillarSummaryRowsMergesPillarDetails confirms PillarDetail entries override the default zero rows and that rows sort by findings DESC.
// A failure means a merged grade or raw penalty is wrong, rows are out of findings order, or a pillar without details is not clean.
func TestBuildPillarSummaryRowsMergesPillarDetails(t *testing.T) {
	report := analysis.Report{
		Score: scoring.Score{
			PillarDetails: []scoring.PillarDetail{
				pillarDetail(scoring.PillarDetail{Pillar: "complexity", Findings: 2, Warning: 2, Penalty: 30}, 70, "C"),
				pillarDetail(scoring.PillarDetail{Pillar: "documentation", Findings: 5, Advisory: 4, Warning: 1, Penalty: 200}, 51, "F"),
			},
		},
	}
	rows := BuildPillarSummaryRows(report)
	if len(rows) != 10 {
		t.Fatalf("rows = %d, want 10 (all canonical pillars)", len(rows))
	}
	if rows[0].Pillar != "documentation" || rows[0].Findings != 5 || rows[0].Grade != "F" {
		t.Errorf("first row = %#v, want documentation/findings=5/grade F", rows[0])
	}
	if rows[0].Penalty != 200 {
		t.Errorf("documentation penalty = %v, want 200 (raw unclamped value preserves worst-pillar ranking)", rows[0].Penalty)
	}
	if rows[1].Pillar != "complexity" || rows[1].Findings != 2 || rows[1].Grade != "C" {
		t.Errorf("second row = %#v, want complexity/findings=2/grade C", rows[1])
	}
	if rows[1].Penalty != 30 {
		t.Errorf("complexity penalty = %v, want 30", rows[1].Penalty)
	}
	for _, row := range rows[2:] {
		if row.Findings != 0 || row.Grade != "A" || row.Score != 100 {
			t.Errorf("zero-findings tail row %q = %#v, want grade A score 100", row.Pillar, row)
		}
		if row.Penalty != 0 {
			t.Errorf("clean pillar %q penalty = %v, want 0", row.Pillar, row.Penalty)
		}
	}
}

// TestWritePillarsBlockCanonicalShape locks down the byte-for-byte column alignment defined by the cross-port summary spec.
// A failure means the Pillars block a user reads in summary text has moved a column or changed how scores print.
func TestWritePillarsBlockCanonicalShape(t *testing.T) {
	rows := []PillarSummaryRow{
		{Pillar: "documentation", Grade: "F", Score: 0.0, Applicable: true, Findings: 376, Advisory: 309, Warning: 67, Error: 0},
		{Pillar: "test-quality", Grade: "F", Score: 0.0, Applicable: true, Findings: 306, Advisory: 231, Warning: 75, Error: 0},
		{Pillar: "naming", Grade: "F", Score: 0.0, Applicable: true, Findings: 192, Advisory: 192, Warning: 0, Error: 0},
		{Pillar: "modernisation", Grade: "F", Score: 0.0, Applicable: true, Findings: 124, Advisory: 119, Warning: 5, Error: 0},
		{Pillar: "dead-code", Grade: "F", Score: 0.0, Applicable: true, Findings: 18, Advisory: 4, Warning: 14, Error: 0},
		{Pillar: "maintainability", Grade: "C", Score: 79.0, Applicable: true, Findings: 7, Advisory: 7, Warning: 0, Error: 0},
		{Pillar: "sensitive-data", Grade: "D", Score: 64.0, Applicable: true, Findings: 3, Advisory: 0, Warning: 3, Error: 0},
		{Pillar: "security", Grade: "C", Score: 76.0, Applicable: true, Findings: 2, Advisory: 0, Warning: 2, Error: 0},
		{Pillar: "size", Grade: "A", Score: 100.0, Applicable: true, Findings: 0, Advisory: 0, Warning: 0, Error: 0},
		{Pillar: "complexity", Grade: "A", Score: 100.0, Applicable: true, Findings: 0, Advisory: 0, Warning: 0, Error: 0},
	}
	const want = "Pillars\n" +
		"  documentation   F   0.00 findings=376   advisory=309   warning=67    error=0\n" +
		"  test-quality    F   0.00 findings=306   advisory=231   warning=75    error=0\n" +
		"  naming          F   0.00 findings=192   advisory=192   warning=0     error=0\n" +
		"  modernisation   F   0.00 findings=124   advisory=119   warning=5     error=0\n" +
		"  dead-code       F   0.00 findings=18    advisory=4     warning=14    error=0\n" +
		"  maintainability C  79.00 findings=7     advisory=7     warning=0     error=0\n" +
		"  sensitive-data  D  64.00 findings=3     advisory=0     warning=3     error=0\n" +
		"  security        C  76.00 findings=2     advisory=0     warning=2     error=0\n" +
		"  size            A 100.00 findings=0     advisory=0     warning=0     error=0\n" +
		"  complexity      A 100.00 findings=0     advisory=0     warning=0     error=0\n"
	var buf bytes.Buffer
	if err := writePillarsBlock(&buf, rows); err != nil {
		t.Fatalf("writePillarsBlock: %v", err)
	}
	if got := buf.String(); got != want {
		t.Fatalf("canonical Pillars block mismatch\n--- want ---\n%s--- got ---\n%s", want, got)
	}
}

// TestWritePillarsBlockEmptyEmitsHeader keeps the Pillars section discoverable when no rows feed into it: the header still prints, then (none).
// This is defensive: BuildPillarSummaryRows always returns ten rows in production, but the renderer must still degrade gracefully.
func TestWritePillarsBlockEmptyEmitsHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := writePillarsBlock(&buf, nil); err != nil {
		t.Fatalf("writePillarsBlock: %v", err)
	}
	if got := buf.String(); got != "Pillars\n  (none)\n" {
		t.Fatalf("empty block = %q, want \"Pillars\\n  (none)\\n\"", got)
	}
}

// TestWriteSummaryV01JSONShape locks the canonical analysis projection used by the summary command.
//
// Despite V01 in the writer's name, the document must announce gruff.summary.v3.
// A failure means summary JSON changed its schema string, lost a top-level key such as run or score, or brought back the per-finding array.
func TestWriteSummaryV01JSONShape(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "json",
		FailOn:      finding.FailThresholdWarning,
		Scanned:     []string{"main.go"},
		Findings:    nil,
		Definitions: defaultDefinitions(),
	})
	var buf bytes.Buffer
	if err := WriteSummaryV01JSON(&buf, report); err != nil {
		t.Fatalf("WriteSummaryV01JSON: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if parsed["schemaVersion"] != "gruff.summary.v3" {
		t.Fatalf("schemaVersion = %q, want gruff.summary.v3", parsed["schemaVersion"])
	}
	if _, present := parsed["findings"]; present {
		t.Fatal("summary projection retained the per-finding array")
	}
	body := buf.String()
	for _, key := range []string{`"schemaVersion"`, `"tool"`, `"run"`, `"summary"`, `"score"`, `"diagnostics"`, `"paths"`, `"suppressions"`} {
		if !strings.Contains(body, key) {
			t.Errorf("JSON missing %s; got:\n%s", key, body)
		}
	}
	if strings.Contains(body, "\n  \"findings\": [") {
		t.Errorf("JSON unexpectedly contains analysis findings; got:\n%s", body)
	}
}

// TestWriteSummaryTextIncludesPillarsBlock confirms the canonical Pillars header reaches summary text and the old "pillars:" tag is gone.
// A failure means a clean scan's summary lost the Pillars header or the complexity row, or fell back to the legacy block.
func TestWriteSummaryTextIncludesPillarsBlock(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "text",
		FailOn:      finding.FailThresholdWarning,
		Scanned:     []string{"main.go"},
		Findings:    nil,
		Definitions: defaultDefinitions(),
	})
	var buf bytes.Buffer
	if err := WriteSummaryText(&buf, report, SummaryOptions{Top: 5, ScanDuration: time.Millisecond}); err != nil {
		t.Fatalf("WriteSummaryText: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "Pillars\n") {
		t.Fatalf("summary text missing canonical 'Pillars' header; got:\n%s", body)
	}
	if strings.Contains(body, "pillars:\n") {
		t.Fatalf("summary text still emits legacy 'pillars:' block; got:\n%s", body)
	}
	if !strings.Contains(body, "complexity      A 100.00 findings=0") {
		t.Fatalf("summary text missing canonical clean pillar row; got:\n%s", body)
	}
}

// TestWriteSummaryTextClassifiesScannedFiles verifies text inputs and failed Go files get distinct counts.
// A parse diagnostic on broken.go moves it from parsed to failed; a failure means the summary files line shows wrong totals.
func TestWriteSummaryTextClassifiesScannedFiles(t *testing.T) {
	analysisReport := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "text",
		FailOn:      finding.FailThresholdNone,
		Scanned:     []string{"main.go", "config.txt", "broken.go"},
		Diagnostics: []analysis.Diagnostic{{Stage: "parse", File: "broken.go", Message: "expected declaration"}},
		Definitions: defaultDefinitions(),
	})
	var summaryOutput bytes.Buffer
	if err := WriteSummaryText(&summaryOutput, analysisReport, SummaryOptions{}); err != nil {
		t.Fatalf("WriteSummaryText: %v", err)
	}
	const expectedLine = "files: 1 Go parsed, 1 text scanned, 1 failed, 0 skipped\n"
	if !strings.Contains(summaryOutput.String(), expectedLine) {
		t.Fatalf("summary text missing %q; got:\n%s", expectedLine, summaryOutput.String())
	}
}

// TestWriteSummaryTextCountsContextOnlyParseFailures checks that summary text counts a supporting package file that failed parsing.
// support.go was never an explicit scan target, yet its parse diagnostic must still show as 1 failed on the files line.
func TestWriteSummaryTextCountsContextOnlyParseFailures(t *testing.T) {
	analysisReport := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"main.go"},
		Format:      "text",
		FailOn:      finding.FailThresholdNone,
		Scanned:     []string{"main.go"},
		Diagnostics: []analysis.Diagnostic{{Stage: "parse", File: "support.go", Message: "expected declaration"}},
		Definitions: defaultDefinitions(),
	})
	var summaryOutput bytes.Buffer
	if err := WriteSummaryText(&summaryOutput, analysisReport, SummaryOptions{}); err != nil {
		t.Fatalf("WriteSummaryText: %v", err)
	}
	const expectedLine = "files: 1 Go parsed, 0 text scanned, 1 failed, 0 skipped\n"
	if !strings.Contains(summaryOutput.String(), expectedLine) {
		t.Fatalf("summary text missing %q; got:\n%s", expectedLine, summaryOutput.String())
	}
}
