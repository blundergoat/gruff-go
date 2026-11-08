// Package report renders gruff-go analysis results into output formats.
//
// This file holds tests for the machine-readable reporters: SARIF, summary JSON, and GitHub annotations.
// A failure here means a CI consumer such as code scanning or GitHub annotations would read a changed or broken payload.
package report

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestMachineReportFormats end-to-end checks the SARIF, summary JSON, and GitHub annotation outputs together for one warning finding.
// A failure means one machine-readable format lost a contract field, such as the SARIF durable identity or the GitHub annotation line.
func TestMachineReportFormats(t *testing.T) {
	item := finding.Finding{
		RuleID:      "size.file-length",
		Message:     "too long",
		File:        "main.go",
		Location:    &finding.Location{Line: 12},
		Severity:    finding.SeverityWarning,
		Confidence:  finding.ConfidenceHigh,
		Pillar:      finding.PillarSize,
		Fingerprint: "abc123",
	}
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "sarif",
		FailOn:      finding.FailThresholdWarning,
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
	// Code scanning groups alerts by the ratified durable identity, not by the line-bearing fingerprint.
	identity, err := item.ComputeBaselineIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sarif.String(), `"gruffFingerprint": "`+identity+`"`) ||
		!strings.Contains(sarif.String(), `"ruleIndex":`) ||
		!strings.Contains(sarif.String(), `"gruffSchemaVersion": "gruff.analysis.v3"`) {
		t.Fatalf("sarif output missing contract fields = %s", sarif.String())
	}

	var summary bytes.Buffer
	if err := WriteSummaryJSON(&summary, report); err != nil {
		t.Fatal(err)
	}
	var summaryPayload map[string]any
	if err := json.Unmarshal(summary.Bytes(), &summaryPayload); err != nil {
		t.Fatalf("invalid summary json: %v\n%s", err, summary.String())
	}
	// A wrong summary schema or a non-null findings value fails here; the compact summary JSON must leave the findings list out.
	if summaryPayload["schemaVersion"] != analysis.SummarySchemaVersion || summaryPayload["findings"] != nil {
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

// TestBoundedDeepScanDiagnosticReachesEveryRenderer protects the visible degradation contract for a file over the deep-scan budget.
//
// Every output format must show the bounded-deep-scan diagnostic and its override=cli detail, so the user learns the scan was bounded.
// A failing subtest names the renderer that would hide it.
func TestBoundedDeepScanDiagnosticReachesEveryRenderer(t *testing.T) {
	nonFatal := false
	diagnostic := analysis.Diagnostic{
		DiagnosticType: "bounded-deep-scan",
		Stage:          "analysis",
		File:           "main.go",
		Location:       &finding.Location{Line: 1},
		Message:        "path=main.go; lines=2; bytes=30; maxLines=1; maxBytes=20; override=cli",
		Severity:       finding.SeverityAdvisory,
		InvalidatesRun: &nonFatal,
	}
	reportData := analysis.NewReport(analysis.ReportInput{
		Root: "/repo", Inputs: []string{"main.go"}, Format: "json", FailOn: finding.FailThresholdNone,
		Scanned: []string{"main.go"}, Diagnostics: []analysis.Diagnostic{diagnostic}, Definitions: defaultDefinitions(),
	})
	renderers := []struct {
		name   string
		render func(io.Writer) error
	}{
		{name: "json", render: func(writer io.Writer) error { return WriteJSON(writer, reportData) }},
		{name: "summary-json", render: func(writer io.Writer) error { return WriteSummaryJSON(writer, reportData) }},
		{name: "summary-v3", render: func(writer io.Writer) error { return WriteSummaryV01JSON(writer, reportData) }},
		{name: "text", render: func(writer io.Writer) error { return WriteText(writer, reportData) }},
		{name: "summary-text", render: func(writer io.Writer) error { return WriteSummaryText(writer, reportData, SummaryOptions{}) }},
		{name: "html", render: func(writer io.Writer) error { return WriteHTML(writer, reportData, HTMLOptions{}) }},
		{name: "markdown", render: func(writer io.Writer) error { return WriteMarkdown(writer, reportData) }},
		{name: "github", render: func(writer io.Writer) error { return WriteGitHub(writer, reportData) }},
		{name: "sarif", render: func(writer io.Writer) error { return WriteSARIF(writer, reportData) }},
	}
	for _, renderer := range renderers {
		t.Run(renderer.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := renderer.render(&output); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "bounded-deep-scan") || !strings.Contains(output.String(), "override=cli") {
				t.Fatalf("%s omitted the diagnostic: %s", renderer.name, output.String())
			}
		})
	}
}

// TestWriteSARIFContract checks the SARIF output against the schema contract, one require helper per field group.
//
// It feeds rule definitions in reverse order and a finding path with a dot-slash and a backslash, so sorting and normalising are exercised.
// A failure names the field that drifted, such as rule order, ruleIndex, partialFingerprints or the run score.
func TestWriteSARIFContract(t *testing.T) {
	definitions := reversedDefinitions(defaultDefinitions())
	item := sarifContractFinding()
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "sarif",
		FailOn:      finding.FailThresholdError,
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
	requireSARIFFingerprints(t, result.PartialFingerprints, baselineIdentityOf(t, item))
	requireSARIFLocation(t, result.Locations, "pkg/main.go", *item.Location)
	requireSARIFResultProperties(t, result.Properties, item)
	requireSARIFRunProperties(t, run.Properties, report.Score.Composite)
}

// TestWriteSARIFWithholdsIdentityFromUnnameableFindings covers the two findings the family refuses to name.
//
// A sensitive result carries no partialFingerprints or fingerprint property, which code scanning would keep as a durable name for a secret.
// A separator-bearing symbol keeps only its port-local property; the ordinary result keeps both, so the writer still emits identities.
func TestWriteSARIFWithholdsIdentityFromUnnameableFindings(t *testing.T) {
	ordinary := sarifContractFinding()
	sensitive := finding.Finding{
		RuleID:     "sensitive-data.aws-access-key",
		Message:    "Possible AWS access key [redacted:aws-access-key]",
		File:       "config/app.env",
		Location:   &finding.Location{Line: 3},
		Severity:   finding.SeverityError,
		Confidence: finding.ConfidenceHigh,
		Pillar:     finding.PillarSensitiveData,
	}.WithFingerprint()
	separated := ordinary
	separated.Symbol = "main#2"
	separated = separated.WithFingerprint()
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "sarif",
		FailOn:      finding.FailThresholdError,
		Scanned:     []string{"pkg/main.go", "config/app.env"},
		Findings:    []finding.Finding{ordinary, sensitive, separated},
		Definitions: defaultDefinitions(),
	})

	run := requireSingleSARIFRun(t, decodeSARIFLog(t, writeSARIFBytes(t, report)))
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}
	for _, result := range run.Results {
		_, hasProperty := result.Properties["fingerprint"]
		switch {
		case result.RuleID == sensitive.RuleID:
			if result.PartialFingerprints != nil || hasProperty {
				t.Fatalf("sensitive result carries an identity: fingerprints %#v, fingerprint property %v", result.PartialFingerprints, hasProperty)
			}
		case result.Properties["symbol"] == "main#2":
			if result.PartialFingerprints != nil || !hasProperty {
				t.Fatalf("separator-bearing result: fingerprints %#v, fingerprint property %v; want none and present", result.PartialFingerprints, hasProperty)
			}
		default:
			requireSARIFFingerprints(t, result.PartialFingerprints, baselineIdentityOf(t, ordinary))
			if !hasProperty {
				t.Fatal("ordinary result lost its fingerprint property")
			}
		}
	}
}

// reversedDefinitions flips the rule definitions slice in place so the SARIF contract test hands NewReport the rules in reverse order.
//
// NewReport sorts them by ID before WriteSARIF runs, and that order is what requireSARIFRulesSorted then observes.
// It returns the same definitions slice, now reversed, so an empty or single-entry slice comes back unchanged.
func reversedDefinitions(definitions []rule.Definition) []rule.Definition {
	for left, right := 0, len(definitions)-1; left < right; left, right = left+1, right-1 {
		definitions[left], definitions[right] = definitions[right], definitions[left]
	}
	return definitions
}

// sarifContractFinding builds the canonical finding used to exercise SARIF contract fields.
//
// It returns a size.file-length finding at error severity with location, symbol, secondary pillar, remediation, metadata and fingerprint set.
// Its File carries a leading dot-slash and a backslash separator, which the contract test expects the writer to normalise to pkg/main.go.
func sarifContractFinding() finding.Finding {
	return finding.Finding{
		RuleID:           "size.file-length",
		Message:          "file has 401 lines, above threshold 400",
		File:             `./pkg\main.go`,
		Location:         &finding.Location{Line: 12, Column: 3, EndLine: 14},
		Symbol:           "main",
		Severity:         finding.SeverityError,
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

// writeSARIFBytes invokes WriteSARIF and returns the produced bytes, failing the test on error.
// The report is passed to WriteSARIF unchanged and rendered into an in-memory buffer.
func writeSARIFBytes(t *testing.T, report analysis.Report) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := WriteSARIF(&out, report); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// decodeSARIFLog parses SARIF bytes into the typed sarifLog model used in test assertions.
//
// It unmarshals data with encoding/json and returns the decoded sarifLog, leaving fields absent from data at their zero values.
// Invalid JSON fails the test with the error and the raw data in the message.
func decodeSARIFLog(t *testing.T, data []byte) sarifLog {
	t.Helper()
	var payload sarifLog
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid sarif json: %v\n%s", err, string(data))
	}
	return payload
}

// requireSingleSARIFRun fails the test when the SARIF payload does not contain exactly one run at version 2.1.0.
// It returns the only run in payload when the check passes; on failure the test stops and nothing is returned.
func requireSingleSARIFRun(t *testing.T, payload sarifLog) sarifRun {
	t.Helper()
	if payload.Version != "2.1.0" || len(payload.Runs) != 1 {
		t.Fatalf("unexpected sarif envelope: %#v", payload)
	}
	return payload.Runs[0]
}

// requireSARIFDriver asserts the driver identity matches the gruff-go tool and pinned semantic version.
// The driver must name gruff-go at 0.6.0, so a release version bump must update this literal too.
func requireSARIFDriver(t *testing.T, driver sarifDriver) {
	t.Helper()
	if driver.Name != "gruff-go" || driver.SemanticVersion != "0.6.0" {
		t.Fatalf("unexpected driver identity: %#v", driver)
	}
}

// requireSARIFRulesSorted asserts the driver rules appear in ID-sorted order.
// A failure names the first out-of-order pair in rules, which means the reversed definitions from TestWriteSARIFContract were not re-sorted.
func requireSARIFRulesSorted(t *testing.T, rules []sarifRule) {
	t.Helper()
	for index := 1; index < len(rules); index++ {
		if rules[index-1].ID > rules[index].ID {
			t.Fatalf("driver rules are not sorted: %q before %q", rules[index-1].ID, rules[index].ID)
		}
	}
}

// requireSARIFRulesCapability asserts every driver rule advertises the parser capability.
// The rules are the driver rule entries; an empty list fails the test, as does any entry whose Properties.Capability is not rule.CapabilityParser.
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

// requireSingleSARIFResult fails the test when the SARIF run does not contain exactly one result.
// The results are the run's result entries, and it returns the single entry once the length check passes.
func requireSingleSARIFResult(t *testing.T, results []sarifResult) sarifResult {
	t.Helper()
	if len(results) != 1 {
		t.Fatalf("results length = %d, want 1", len(results))
	}
	return results[0]
}

// requireSARIFResultIdentity checks the finding's rule ID and requires the SARIF level error.
// The result must carry item.RuleID; the level is fixed rather than derived from item.Severity, so callers pass an error-severity item.
func requireSARIFResultIdentity(t *testing.T, result sarifResult, item finding.Finding) {
	t.Helper()
	if result.RuleID != item.RuleID || result.Level != "error" {
		t.Fatalf("unexpected result identity/level: %#v", result)
	}
}

// requireSARIFRuleIndex asserts the result.ruleIndex points to the matching driver rule entry.
//
// It fails the test when result has no RuleIndex or the index falls outside rules.
// It also fails when the entry at that index in rules has an ID other than result.RuleID.
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

// requireNoRawSARIFResultKeys fails the test when forbidden SARIF result keys are present in the raw JSON.
// The result is one decoded raw result object, and keys lists names it must lack, such as codeFlows, threadFlows and fixes.
func requireNoRawSARIFResultKeys(t *testing.T, result map[string]any, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if _, exists := result[key]; exists {
			t.Fatalf("unexpected SARIF %s in result: %#v", key, result[key])
		}
	}
}

// baselineIdentityOf returns the ratified durable identity a SARIF result must publish for one finding.
//
// Code scanning groups alerts by this identity; an unranked symbol-bearing item gets ordinal 1 without a declaration inventory.
// The item is ranked alone through finding.EnsureSymbolOrdinals, and a failed identity computation fails the test.
func baselineIdentityOf(t *testing.T, item finding.Finding) string {
	t.Helper()
	ranked := finding.EnsureSymbolOrdinals([]finding.Finding{item})
	identity, err := ranked[0].ComputeBaselineIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return identity
}

// requireSARIFFingerprints checks the expected durable identity under gruffFingerprint and rejects the legacy primary key.
//
// The want value is the expected durable identity, which callers take from baselineIdentityOf rather than the finding's Fingerprint field.
// Other keys in fingerprints are not checked, and a nil map fails unless want is empty.
func requireSARIFFingerprints(t *testing.T, fingerprints map[string]string, want string) {
	t.Helper()
	if got := fingerprints["gruffFingerprint"]; got != want {
		t.Fatalf("gruffFingerprint = %q, want %q", got, want)
	}
	if _, exists := fingerprints["primary"]; exists {
		t.Fatalf("stale primary fingerprint key present: %#v", fingerprints)
	}
}

// requireSARIFLocation asserts the SARIF location's artefact URI and region match the expected values.
//
// It fails the test unless locations holds exactly one entry whose artifact URI equals wantURI.
// The region must be present, and its start line, start column and end line must match the Line, Column and EndLine of want.
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

// requireSARIFResultProperties asserts result.properties keeps the core fields, remediation, symbol, metadata and secondary pillars.
//
// The properties map goes through requireSARIFMetadata, requireCoreSARIFResultProperties and requireSARIFSecondaryPillars.
// Remediation and symbol must equal those of item; metadata and secondary pillars are compared with the sarifContractFinding values, not item.
func requireSARIFResultProperties(t *testing.T, properties map[string]any, item finding.Finding) {
	t.Helper()
	requireSARIFMetadata(t, properties)
	requireCoreSARIFResultProperties(t, properties, item)
	requireSARIFSecondaryPillars(t, properties)
	if properties["remediation"] != item.Remediation || properties["symbol"] != item.Symbol {
		t.Fatalf("result properties not preserved: %#v", properties)
	}
}

// requireSARIFMetadata asserts the metadata sub-block of result.properties survives JSON round-trip.
// The properties map must hold the lines 401 and threshold 400 that sarifContractFinding sets, which JSON decoding turns into float64.
func requireSARIFMetadata(t *testing.T, properties map[string]any) {
	t.Helper()
	metadata, ok := properties["metadata"].(map[string]any)
	if !ok || metadata["lines"] != float64(401) || metadata["threshold"] != float64(400) {
		t.Fatalf("metadata not preserved: %#v", properties["metadata"])
	}
}

// requireCoreSARIFResultProperties asserts pillar, severity, and confidence are preserved in result.properties.
// The pillar, severity and confidence entries in properties must equal the string forms of the Pillar, Severity and Confidence of item.
func requireCoreSARIFResultProperties(t *testing.T, properties map[string]any, item finding.Finding) {
	t.Helper()
	if properties["pillar"] != string(item.Pillar) ||
		properties["severity"] != string(item.Severity) ||
		properties["confidence"] != string(item.Confidence) {
		t.Fatalf("core result properties not preserved: %#v", properties)
	}
}

// requireSARIFSecondaryPillars asserts the secondary pillar list survives serialisation.
// It fails unless the secondaryPillars entry in properties is a list holding only finding.PillarMaintain, the value sarifContractFinding sets.
func requireSARIFSecondaryPillars(t *testing.T, properties map[string]any) {
	t.Helper()
	secondaryPillars, ok := properties["secondaryPillars"].([]any)
	if !ok || len(secondaryPillars) != 1 || secondaryPillars[0] != string(finding.PillarMaintain) {
		t.Fatalf("secondary pillars not preserved: %#v", properties["secondaryPillars"])
	}
}

// requireSARIFRunProperties asserts run-level properties carry the schema version, grade, and score.
//
// The properties must carry analysis.SchemaVersion and a non-empty grade, even when wantScore is nil, so a run with a null grade fails here.
// The caller passes the report's composite as wantScore: nil requires a null score, otherwise the score must equal the value it points to.
func requireSARIFRunProperties(t *testing.T, properties sarifRunProperties, wantScore *float64) {
	t.Helper()
	if properties.GruffSchemaVersion != analysis.SchemaVersion || properties.Grade == nil || *properties.Grade == "" {
		t.Fatalf("run properties not preserved: %#v", properties)
	}
	// A run that evaluated nothing has a nil composite, and its SARIF run must then publish a null score rather than a number.
	if wantScore == nil {
		if properties.Score != nil {
			t.Fatalf("run score = %v, want null when nothing was evaluated", *properties.Score)
		}
		return
	}
	if properties.Score == nil || *properties.Score != *wantScore {
		t.Fatalf("run score = %v, want %v", properties.Score, *wantScore)
	}
}

// TestWriteSARIFOmitRuleIndexWhenRuleMissing asserts ruleIndex is omitted when no driver rule matches the finding.
// A finding whose rule the registry lacks, such as custom.missing-rule, must still get its durable identity and a normalised location.
func TestWriteSARIFOmitRuleIndexWhenRuleMissing(t *testing.T) {
	item := finding.Finding{
		RuleID:      "custom.missing-rule",
		Message:     "custom finding",
		File:        `./custom\missing.go`,
		Location:    &finding.Location{Line: 1},
		Severity:    finding.SeverityAdvisory,
		Confidence:  finding.ConfidenceMedium,
		Pillar:      finding.PillarMaintain,
		Fingerprint: "fp-missing",
	}
	report := analysis.NewReport(analysis.ReportInput{
		Root:        "/repo",
		Inputs:      []string{"."},
		Format:      "sarif",
		FailOn:      finding.FailThresholdError,
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
	if got, want := result.PartialFingerprints["gruffFingerprint"], baselineIdentityOf(t, item); got != want {
		t.Fatalf("gruffFingerprint = %q, want %q", got, want)
	}
	if len(result.Locations) != 1 || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "custom/missing.go" {
		t.Fatalf("location not well-formed: %#v", result.Locations)
	}
}

// TestSARIFLevelMapping checks each gruff severity maps to the documented SARIF level.
// A failure means a SARIF consumer such as code scanning would show findings at the wrong level, for example an advisory as a warning.
func TestSARIFLevelMapping(t *testing.T) {
	cases := map[finding.Severity]string{
		finding.SeverityError:    "error",
		finding.SeverityWarning:  "warning",
		finding.SeverityAdvisory: "note",
	}
	for severity, want := range cases {
		if got := sarifLevel(severity); got != want {
			t.Fatalf("sarifLevel(%q) = %q, want %q", severity, got, want)
		}
	}
}

// rawSARIFResult returns the index-th SARIF result as a generic map for raw-key assertions.
//
// It decodes data as JSON and fails the test when it is invalid, holds other than one run, or has no result at index.
// A run, or the result at index, that is not a JSON object also fails the test; a negative index panics.
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

// TestWriteSARIFKeepsInlineSuppressedFindingsAsSuppressedResults proves section 13c's SARIF rule for inline-suppressed findings.
//
// A finding another tool's comment suppressed stays a result with an inSource suppression carrying the audit reason, after the open results.
// A code-scanning tool then shows it as suppressed rather than fixed.
func TestWriteSARIFKeepsInlineSuppressedFindingsAsSuppressedResults(t *testing.T) {
	open := finding.Finding{RuleID: "security.shell-command", Message: "shell", File: "main.go", Location: &finding.Location{Line: 9},
		Severity: finding.SeverityWarning, Confidence: finding.ConfidenceHigh, Pillar: finding.PillarSecurity}
	quiet := open
	quiet.Location = &finding.Location{Line: 4}
	report := analysis.NewReport(analysis.ReportInput{
		Root: "/repo", Inputs: []string{"."}, Format: "sarif", FailOn: finding.FailThresholdError, Scanned: []string{"main.go"},
		Findings: []finding.Finding{open}, Definitions: defaultDefinitions(),
		Suppressed: []analysis.SuppressedFinding{{Finding: quiet, Justification: analysis.InlineSuppressionReason}},
	})

	var out bytes.Buffer
	if err := WriteSARIF(&out, report); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Runs []struct {
			Results []struct {
				Locations    []sarifLocation `json:"locations"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("invalid sarif json: %v\n%s", err, out.String())
	}
	results := payload.Runs[0].Results
	if len(results) != 2 || len(results[0].Suppressions) != 0 {
		t.Fatalf("results = %#v, want the open result unsuppressed and then the suppressed one", results)
	}
	suppression := results[1].Suppressions
	if len(suppression) != 1 || suppression[0].Kind != "inSource" || suppression[0].Justification != analysis.InlineSuppressionReason ||
		results[1].Locations[0].PhysicalLocation.Region.StartLine != 4 {
		t.Fatalf("suppressed result = %#v, want one inSource suppression with the audit reason on line 4", results[1])
	}
	if _, exists := rawSARIFResult(t, out.Bytes(), 0)["suppressions"]; exists {
		t.Fatal("an open result must not carry a suppressions key")
	}
}
