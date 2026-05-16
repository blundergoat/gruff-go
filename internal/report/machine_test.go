package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

func TestMachineReportFormats(t *testing.T) {
	item := finding.Finding{
		RuleID:      "size.file-length",
		Message:     "too long",
		File:        "main.go",
		Location:    &finding.Location{Line: 12},
		Severity:    finding.SeverityMedium,
		Confidence:  finding.ConfidenceHigh,
		Pillar:      finding.PillarSize,
		Fingerprint: "abc123",
	}
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "sarif",
		FailOn:      finding.SeverityMedium,
		Scanned:     []string{"main.go"},
		Findings:    []finding.Finding{item},
		Definitions: rule.Defaults().Definitions(),
	})

	var sarif bytes.Buffer
	if err := WriteSARIF(&sarif, report); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(sarif.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid sarif json: %v\n%s", err, sarif.String())
	}
	if parsed["version"] != "2.1.0" || !strings.Contains(sarif.String(), `"ruleId": "size.file-length"`) {
		t.Fatalf("sarif output = %s", sarif.String())
	}
	if !strings.Contains(sarif.String(), `"gruffFingerprint": "abc123"`) ||
		!strings.Contains(sarif.String(), `"ruleIndex":`) ||
		!strings.Contains(sarif.String(), `"gruffSchemaVersion": "gruff-go.analysis.v0.1"`) {
		t.Fatalf("sarif output missing contract fields = %s", sarif.String())
	}

	var summary bytes.Buffer
	if err := WriteSummaryJSON(&summary, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.String(), `"findingsCount": 1`) || strings.Contains(summary.String(), `"findings": [`) {
		t.Fatalf("summary output = %s", summary.String())
	}

	var github bytes.Buffer
	if err := WriteGitHub(&github, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(github.String(), "::warning file=main.go,line=12,title=size.file-length::too long") {
		t.Fatalf("github output = %s", github.String())
	}
}

func TestWriteSARIFContract(t *testing.T) {
	definitions := rule.Defaults().Definitions()
	for left, right := 0, len(definitions)-1; left < right; left, right = left+1, right-1 {
		definitions[left], definitions[right] = definitions[right], definitions[left]
	}
	item := finding.Finding{
		RuleID:           "size.file-length",
		Message:          "file has 401 lines, above threshold 400",
		File:             `./pkg\main.go`,
		Location:         &finding.Location{Line: 12, Column: 3, EndLine: 14},
		Symbol:           "main",
		Severity:         finding.SeverityHigh,
		Confidence:       finding.ConfidenceHigh,
		Pillar:           finding.PillarSize,
		SecondaryPillars: []finding.Pillar{finding.PillarMaintain},
		Remediation:      "Split cohesive package responsibilities across smaller files.",
		Metadata: map[string]any{
			"lines":     401,
			"threshold": 400,
		},
		Fingerprint: "fp-size",
	}
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "sarif",
		FailOn:      finding.SeverityCritical,
		Scanned:     []string{"pkg/main.go"},
		Findings:    []finding.Finding{item},
		Definitions: definitions,
	})

	var out bytes.Buffer
	if err := WriteSARIF(&out, report); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name            string `json:"name"`
					SemanticVersion string `json:"semanticVersion"`
					Rules           []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex *int   `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
							EndLine     int `json:"endLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Properties          map[string]any    `json:"properties"`
			} `json:"results"`
			Properties map[string]any `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("invalid sarif json: %v\n%s", err, out.String())
	}
	if payload.Version != "2.1.0" || len(payload.Runs) != 1 {
		t.Fatalf("unexpected sarif envelope: %#v", payload)
	}
	run := payload.Runs[0]
	if run.Tool.Driver.Name != "gruff-go" || run.Tool.Driver.SemanticVersion != "0.1.0-dev" {
		t.Fatalf("unexpected driver identity: %#v", run.Tool.Driver)
	}
	for index := 1; index < len(run.Tool.Driver.Rules); index++ {
		if run.Tool.Driver.Rules[index-1].ID > run.Tool.Driver.Rules[index].ID {
			t.Fatalf("driver rules are not sorted: %q before %q", run.Tool.Driver.Rules[index-1].ID, run.Tool.Driver.Rules[index].ID)
		}
	}
	if len(run.Results) != 1 {
		t.Fatalf("results length = %d, want 1", len(run.Results))
	}
	result := run.Results[0]
	if result.RuleID != item.RuleID || result.Level != "error" {
		t.Fatalf("unexpected result identity/level: %#v", result)
	}
	if result.RuleIndex == nil || run.Tool.Driver.Rules[*result.RuleIndex].ID != result.RuleID {
		t.Fatalf("ruleIndex does not point to matching driver rule: %#v", result)
	}
	rawResult := rawSARIFResult(t, out.Bytes(), 0)
	for _, key := range []string{"codeFlows", "threadFlows", "fixes"} {
		if _, exists := rawResult[key]; exists {
			t.Fatalf("unexpected SARIF %s in result: %#v", key, rawResult[key])
		}
	}
	if got := result.PartialFingerprints["gruffFingerprint"]; got != item.Fingerprint {
		t.Fatalf("gruffFingerprint = %q, want %q", got, item.Fingerprint)
	}
	if _, exists := result.PartialFingerprints["primary"]; exists {
		t.Fatalf("stale primary fingerprint key present: %#v", result.PartialFingerprints)
	}
	if len(result.Locations) != 1 {
		t.Fatalf("locations length = %d, want 1", len(result.Locations))
	}
	location := result.Locations[0].PhysicalLocation
	if location.ArtifactLocation.URI != "pkg/main.go" {
		t.Fatalf("artifact uri = %q, want normalized pkg/main.go", location.ArtifactLocation.URI)
	}
	if location.Region.StartLine != 12 || location.Region.StartColumn != 3 || location.Region.EndLine != 14 {
		t.Fatalf("region not preserved: %#v", location.Region)
	}
	metadata, ok := result.Properties["metadata"].(map[string]any)
	if !ok || metadata["lines"] != float64(401) || metadata["threshold"] != float64(400) {
		t.Fatalf("metadata not preserved: %#v", result.Properties["metadata"])
	}
	if result.Properties["pillar"] != string(item.Pillar) ||
		result.Properties["severity"] != string(item.Severity) ||
		result.Properties["confidence"] != string(item.Confidence) {
		t.Fatalf("core result properties not preserved: %#v", result.Properties)
	}
	secondaryPillars, ok := result.Properties["secondaryPillars"].([]any)
	if !ok || len(secondaryPillars) != 1 || secondaryPillars[0] != string(finding.PillarMaintain) {
		t.Fatalf("secondary pillars not preserved: %#v", result.Properties["secondaryPillars"])
	}
	if result.Properties["remediation"] != item.Remediation || result.Properties["symbol"] != item.Symbol {
		t.Fatalf("result properties not preserved: %#v", result.Properties)
	}
	grade, gradeOK := run.Properties["grade"].(string)
	if run.Properties["gruffSchemaVersion"] != analysis.SchemaVersion || !gradeOK || grade == "" {
		t.Fatalf("run properties not preserved: %#v", run.Properties)
	}
	if _, ok := run.Properties["score"].(float64); !ok {
		t.Fatalf("run score missing or not numeric: %#v", run.Properties)
	}
}

func TestWriteSARIFOmitRuleIndexWhenRuleMissing(t *testing.T) {
	item := finding.Finding{
		RuleID:      "custom.missing-rule",
		Message:     "custom finding",
		File:        `./custom\missing.go`,
		Location:    &finding.Location{Line: 1},
		Severity:    finding.SeverityLow,
		Confidence:  finding.ConfidenceMedium,
		Pillar:      finding.PillarMaintain,
		Fingerprint: "fp-missing",
	}
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "sarif",
		FailOn:      finding.SeverityCritical,
		Scanned:     []string{"custom/missing.go"},
		Findings:    []finding.Finding{item},
		Definitions: rule.Defaults().Definitions(),
	})

	var out bytes.Buffer
	if err := WriteSARIF(&out, report); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Runs []struct {
			Results []struct {
				RuleID              string            `json:"ruleId"`
				RuleIndex           *int              `json:"ruleIndex"`
				Locations           []sarifLocation   `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("invalid sarif json: %v\n%s", err, out.String())
	}
	if len(payload.Runs) != 1 || len(payload.Runs[0].Results) != 1 {
		t.Fatalf("unexpected sarif results: %#v", payload)
	}
	result := payload.Runs[0].Results[0]
	if result.RuleID != item.RuleID {
		t.Fatalf("ruleId = %q, want %q", result.RuleID, item.RuleID)
	}
	if result.RuleIndex != nil {
		t.Fatalf("ruleIndex = %d, want omitted", *result.RuleIndex)
	}
	rawResult := rawSARIFResult(t, out.Bytes(), 0)
	if _, exists := rawResult["ruleIndex"]; exists {
		t.Fatalf("raw ruleIndex key present for missing rule: %#v", rawResult["ruleIndex"])
	}
	if got := result.PartialFingerprints["gruffFingerprint"]; got != item.Fingerprint {
		t.Fatalf("gruffFingerprint = %q, want %q", got, item.Fingerprint)
	}
	if len(result.Locations) != 1 || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "custom/missing.go" {
		t.Fatalf("location not well-formed: %#v", result.Locations)
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	cases := map[finding.Severity]string{
		finding.SeverityCritical: "error",
		finding.SeverityHigh:     "error",
		finding.SeverityMedium:   "warning",
		finding.SeverityLow:      "note",
		finding.SeverityInfo:     "note",
	}
	for severity, want := range cases {
		if got := sarifLevel(severity); got != want {
			t.Fatalf("sarifLevel(%q) = %q, want %q", severity, got, want)
		}
	}
}

func rawSARIFResult(t *testing.T, data []byte, index int) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid sarif json: %v", err)
	}
	runs, ok := payload["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs not found: %#v", payload["runs"])
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("run is not an object: %#v", runs[0])
	}
	results, ok := run["results"].([]any)
	if !ok || index >= len(results) {
		t.Fatalf("result %d not found: %#v", index, run["results"])
	}
	result, ok := results[index].(map[string]any)
	if !ok {
		t.Fatalf("result is not an object: %#v", results[index])
	}
	return result
}
