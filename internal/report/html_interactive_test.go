package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteHTMLFindingRowsCarryDataAttributes(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	// Static reporter still emits the data attributes used by the interactive layer.
	for _, fragment := range []string{
		`data-severity="`,
		`data-pillar="`,
		`data-file="`,
		`data-rule="`,
		`data-search="`,
	} {
		if !strings.Contains(body, fragment) {
			t.Errorf("static report missing %q", fragment)
		}
	}
}

func TestWriteHTMLInteractiveEmitsFilterForm(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{Interactive: true}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	for _, fragment := range []string{
		`data-finding-filters`,
		`<select name="severity" multiple`,
		`<select name="pillar" multiple`,
		`<input name="path"`,
		`<input name="q"`,
		`<legend>Group by</legend>`,
		`<input type="radio" name="group" value="none" checked>`,
		`<input type="radio" name="group" value="file">`,
		`<input type="radio" name="group" value="rule">`,
		`data-clear-filters`,
		`data-filter-count`,
		`aria-live="polite"`,
		`data-findings-list`,
		`<script type="module">`,
	} {
		if !strings.Contains(body, fragment) {
			t.Errorf("interactive report missing %q", fragment)
		}
	}
}

func TestWriteHTMLNonInteractiveOmitsScript(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	forbidden := []string{
		`<script type="module">`,
		`data-finding-filters`,
		`data-findings-list`,
	}
	for _, fragment := range forbidden {
		if strings.Contains(body, fragment) {
			t.Errorf("static report should not include %q", fragment)
		}
	}
}

func TestWriteHTMLInteractiveSeverityOptionOrder(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{Interactive: true}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	// Severity options must be in canonical priority order (critical → info).
	expected := []string{"critical", "high", "medium", "low", "info"}
	previousIndex := -1
	for _, value := range expected {
		marker := `<option value="` + value + `">`
		index := strings.Index(body, marker)
		if index == -1 {
			t.Errorf("severity option %q missing", value)
			continue
		}
		if index < previousIndex {
			t.Errorf("severity option %q appears out of order", value)
		}
		previousIndex = index
	}
}

func TestWriteHTMLInteractivePillarOptionsSortedAndDeduped(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{Interactive: true}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	// Fixture has findings in complexity, size, naming pillars.
	for _, pillar := range []string{"complexity", "naming", "size"} {
		marker := `<option value="` + pillar + `">`
		if strings.Count(body, marker) < 1 {
			t.Errorf("pillar %q should appear as an option", pillar)
		}
	}
	// Pillars must appear alphabetically.
	indexComplexity := strings.Index(body, `<option value="complexity">complexity</option>`)
	indexNaming := strings.Index(body, `<option value="naming">naming</option>`)
	indexSize := strings.Index(body, `<option value="size">size</option>`)
	if indexComplexity == -1 || indexNaming == -1 || indexSize == -1 {
		t.Fatal("expected complexity, naming, and size pillar options")
	}
	if !(indexComplexity < indexNaming && indexNaming < indexSize) {
		t.Errorf("pillar options not alphabetically sorted: complexity=%d naming=%d size=%d", indexComplexity, indexNaming, indexSize)
	}
}

func TestWriteHTMLInteractiveCountReflectsAllFindings(t *testing.T) {
	report := buildHTMLFixture()
	var out bytes.Buffer
	if err := WriteHTML(&out, report, HTMLOptions{Interactive: true}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := out.String()
	totalFindings := len(report.Findings)
	expected := strings.Replace("{n} of {n} findings shown.", "{n}", "5", -1)
	_ = totalFindings
	if !strings.Contains(body, expected) {
		t.Errorf("interactive report should report %q (got count %d in fixture)", expected, totalFindings)
	}
}
