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
		Definitions: defaultDefinitions(),
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
	definitions := reversedDefinitions(defaultDefinitions())
	item := sarifContractFinding()
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "sarif",
		FailOn:      finding.SeverityCritical,
		Scanned:     []string{"pkg/main.go"},
		Findings:    []finding.Finding{item},
		Definitions: definitions,
	})

	out := writeSARIFBytes(t, report)
	if len(out) == 0 {
		t.Fatal("sarif output is empty")
	}
	payload := decodeSARIFLog(t, out)
	run := requireSingleSARIFRun(t, payload)
	result := requireSingleSARIFResult(t, run.Results)

	requireSARIFDriver(t, run.Tool.Driver)
	requireSARIFRulesSorted(t, run.Tool.Driver.Rules)
	requireSARIFRulesCapability(t, run.Tool.Driver.Rules)
	requireSARIFResultIdentity(t, result, item)
	requireSARIFRuleIndex(t, result, run.Tool.Driver.Rules)
	requireNoRawSARIFResultKeys(t, rawSARIFResult(t, out, 0), "codeFlows", "threadFlows", "fixes")
	requireSARIFFingerprints(t, result.PartialFingerprints, item.Fingerprint)
	requireSARIFLocation(t, result.Locations, "pkg/main.go", *item.Location)
	requireSARIFResultProperties(t, result.Properties, item)
	requireSARIFRunProperties(t, run.Properties, report.Score.Composite)
}

func reversedDefinitions(definitions []rule.Definition) []rule.Definition {
	for left, right := 0, len(definitions)-1; left < right; left, right = left+1, right-1 {
		definitions[left], definitions[right] = definitions[right], definitions[left]
	}
	return definitions
}

func sarifContractFinding() finding.Finding {
	return finding.Finding{
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
}

func writeSARIFBytes(t *testing.T, report analysis.Report) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := WriteSARIF(&out, report); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func decodeSARIFLog(t *testing.T, data []byte) sarifLog {
	t.Helper()
	var payload sarifLog
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid sarif json: %v\n%s", err, string(data))
	}
	return payload
}

func requireSingleSARIFRun(t *testing.T, payload sarifLog) sarifRun {
	t.Helper()
	if payload.Version != "2.1.0" || len(payload.Runs) != 1 {
		t.Fatalf("unexpected sarif envelope: %#v", payload)
	}
	return payload.Runs[0]
}

func requireSARIFDriver(t *testing.T, driver sarifDriver) {
	t.Helper()
	if driver.Name != "gruff-go" || driver.SemanticVersion != "0.1.0-dev" {
		t.Fatalf("unexpected driver identity: %#v", driver)
	}
}

func requireSARIFRulesSorted(t *testing.T, rules []sarifRule) {
	t.Helper()
	for index := 1; index < len(rules); index++ {
		if rules[index-1].ID > rules[index].ID {
			t.Fatalf("driver rules are not sorted: %q before %q", rules[index-1].ID, rules[index].ID)
		}
	}
}

func requireSARIFRulesCapability(t *testing.T, rules []sarifRule) {
	t.Helper()
	if len(rules) == 0 {
		t.Fatal("expected SARIF driver rules")
	}
	for _, item := range rules {
		if item.Properties.Capability != rule.CapabilityParser {
			t.Fatalf("rule %s capability = %q, want %q", item.ID, item.Properties.Capability, rule.CapabilityParser)
		}
	}
}

func requireSingleSARIFResult(t *testing.T, results []sarifResult) sarifResult {
	t.Helper()
	if len(results) != 1 {
		t.Fatalf("results length = %d, want 1", len(results))
	}
	return results[0]
}

func requireSARIFResultIdentity(t *testing.T, result sarifResult, item finding.Finding) {
	t.Helper()
	if result.RuleID != item.RuleID || result.Level != "error" {
		t.Fatalf("unexpected result identity/level: %#v", result)
	}
}

func requireSARIFRuleIndex(t *testing.T, result sarifResult, rules []sarifRule) {
	t.Helper()
	if result.RuleIndex == nil {
		t.Fatalf("ruleIndex missing: %#v", result)
	}
	if *result.RuleIndex < 0 || *result.RuleIndex >= len(rules) {
		t.Fatalf("ruleIndex out of range: %#v", result)
	}
	if rules[*result.RuleIndex].ID != result.RuleID {
		t.Fatalf("ruleIndex does not point to matching driver rule: %#v", result)
	}
}

func requireNoRawSARIFResultKeys(t *testing.T, result map[string]any, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if _, exists := result[key]; exists {
			t.Fatalf("unexpected SARIF %s in result: %#v", key, result[key])
		}
	}
}

func requireSARIFFingerprints(t *testing.T, fingerprints map[string]string, want string) {
	t.Helper()
	if got := fingerprints["gruffFingerprint"]; got != want {
		t.Fatalf("gruffFingerprint = %q, want %q", got, want)
	}
	if _, exists := fingerprints["primary"]; exists {
		t.Fatalf("stale primary fingerprint key present: %#v", fingerprints)
	}
}

func requireSARIFLocation(t *testing.T, locations []sarifLocation, wantURI string, want finding.Location) {
	t.Helper()
	if len(locations) != 1 {
		t.Fatalf("locations length = %d, want 1", len(locations))
	}
	location := locations[0].PhysicalLocation
	if location.ArtifactLocation.URI != wantURI {
		t.Fatalf("artifact uri = %q, want normalized %s", location.ArtifactLocation.URI, wantURI)
	}
	if location.Region == nil {
		t.Fatalf("region missing: %#v", location)
	}
	if location.Region.StartLine != want.Line || location.Region.StartColumn != want.Column || location.Region.EndLine != want.EndLine {
		t.Fatalf("region not preserved: %#v", location.Region)
	}
}

func requireSARIFResultProperties(t *testing.T, properties map[string]any, item finding.Finding) {
	t.Helper()
	requireSARIFMetadata(t, properties)
	requireCoreSARIFResultProperties(t, properties, item)
	requireSARIFSecondaryPillars(t, properties)
	if properties["remediation"] != item.Remediation || properties["symbol"] != item.Symbol {
		t.Fatalf("result properties not preserved: %#v", properties)
	}
}

func requireSARIFMetadata(t *testing.T, properties map[string]any) {
	t.Helper()
	metadata, ok := properties["metadata"].(map[string]any)
	if !ok || metadata["lines"] != float64(401) || metadata["threshold"] != float64(400) {
		t.Fatalf("metadata not preserved: %#v", properties["metadata"])
	}
}

func requireCoreSARIFResultProperties(t *testing.T, properties map[string]any, item finding.Finding) {
	t.Helper()
	if properties["pillar"] != string(item.Pillar) ||
		properties["severity"] != string(item.Severity) ||
		properties["confidence"] != string(item.Confidence) {
		t.Fatalf("core result properties not preserved: %#v", properties)
	}
}

func requireSARIFSecondaryPillars(t *testing.T, properties map[string]any) {
	t.Helper()
	secondaryPillars, ok := properties["secondaryPillars"].([]any)
	if !ok || len(secondaryPillars) != 1 || secondaryPillars[0] != string(finding.PillarMaintain) {
		t.Fatalf("secondary pillars not preserved: %#v", properties["secondaryPillars"])
	}
}

func requireSARIFRunProperties(t *testing.T, properties sarifRunProperties, wantScore int) {
	t.Helper()
	if properties.GruffSchemaVersion != analysis.SchemaVersion || properties.Grade == "" {
		t.Fatalf("run properties not preserved: %#v", properties)
	}
	if properties.Score != wantScore {
		t.Fatalf("run score = %d, want %d", properties.Score, wantScore)
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
		Definitions: defaultDefinitions(),
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
