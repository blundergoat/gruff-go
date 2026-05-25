// Package report renders gruff-go analysis results into output formats.
// This file covers the cross-port canonical summary digest (text + v0.1 JSON).
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
func TestSummarySchemaVersion(t *testing.T) {
	if SummarySchemaVersion != "gruff.summary.v2" {
		t.Fatalf("SummarySchemaVersion = %q, want %q", SummarySchemaVersion, "gruff.summary.v2")
	}
}

// TestBuildPillarSummaryRowsCleanScan asserts a clean scan yields every
// canonical pillar at grade A with zero counts so the summary block always
// renders the same row set.
func TestBuildPillarSummaryRowsCleanScan(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "json",
		FailOn:      finding.SeverityWarning,
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
	if row := rows[len(rows)-1]; row.Pillar != "test-quality" {
		t.Errorf("last clean row = %q, want test-quality (ASC tie-break)", row.Pillar)
	}
}

// TestBuildPillarSummaryRowsMergesPillarDetails confirms PillarDetail entries
// override the default zero rows and that rows sort by findings DESC.
func TestBuildPillarSummaryRowsMergesPillarDetails(t *testing.T) {
	report := analysis.Report{
		Score: scoring.Score{
			PillarDetails: []scoring.PillarDetail{
				{Pillar: "complexity", Score: 70, Grade: "C", Findings: 2, Advisory: 0, Warning: 2, Error: 0, Penalty: 30},
				{Pillar: "documentation", Score: 0, Grade: "F", Findings: 5, Advisory: 4, Warning: 1, Error: 0, Penalty: 200},
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

// TestWritePillarsBlockCanonicalShape locks down the byte-for-byte column
// alignment defined by the cross-port summary spec.
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

// TestWritePillarsBlockEmptyEmitsHeader keeps the section discoverable even
// when no rows feed into it (defensive: BuildPillarSummaryRows always returns
// ten rows in production, but the renderer must still degrade gracefully).
func TestWritePillarsBlockEmptyEmitsHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := writePillarsBlock(&buf, nil); err != nil {
		t.Fatalf("writePillarsBlock: %v", err)
	}
	if got := buf.String(); got != "Pillars\n  (none)\n" {
		t.Fatalf("empty block = %q, want \"Pillars\\n  (none)\\n\"", got)
	}
}

// TestWriteSummaryV01JSONShape locks the dedicated digest payload shape and
// confirms the schema version constant flows into the rendered JSON.
func TestWriteSummaryV01JSONShape(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "json",
		FailOn:      finding.SeverityWarning,
		Scanned:     []string{"main.go"},
		Findings:    nil,
		Definitions: defaultDefinitions(),
	})
	var buf bytes.Buffer
	if err := WriteSummaryV01JSON(&buf, report); err != nil {
		t.Fatalf("WriteSummaryV01JSON: %v", err)
	}
	var parsed struct {
		SchemaVersion string             `json:"schemaVersion"`
		Pillars       []PillarSummaryRow `json:"pillars"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if parsed.SchemaVersion != "gruff.summary.v2" {
		t.Fatalf("schemaVersion = %q, want gruff.summary.v2", parsed.SchemaVersion)
	}
	if len(parsed.Pillars) != 10 {
		t.Fatalf("pillars length = %d, want 10", len(parsed.Pillars))
	}
	body := buf.String()
	for _, key := range []string{`"schemaVersion"`, `"pillars"`, `"applicable"`, `"grade"`, `"score"`, `"findings"`, `"advisory"`, `"warning"`, `"error"`, `"penalty"`} {
		if !strings.Contains(body, key) {
			t.Errorf("JSON missing %s; got:\n%s", key, body)
		}
	}
	// The summary v0.1 digest must not leak the heavier analysis payload.
	// Top-level fields use 2-space indent ("  "); per-pillar fields use 6-space
	// indent ("      "), so we anchor the forbidden checks to the outer indent.
	for _, forbidden := range []string{
		"\n  \"tool\":",
		"\n  \"run\":",
		"\n  \"summary\":",
		"\n  \"baseline\":",
		"\n  \"diff\":",
		"\n  \"diagnostics\":",
		"\n  \"score\":",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("JSON unexpectedly contains analysis-schema field %s; got:\n%s", forbidden, body)
		}
	}
}

// TestWriteSummaryTextIncludesPillarsBlock confirms the canonical Pillars
// header reaches the summary text output and the old "pillars:" tag is gone.
func TestWriteSummaryTextIncludesPillarsBlock(t *testing.T) {
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "text",
		FailOn:      finding.SeverityWarning,
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
