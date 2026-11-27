// rules_docs_contract_fixtures_test.go tests the narrow rules-doc parser and the registry comparator on isolated Markdown fixtures.
//
// Missing required metadata and duplicate or malformed markers must fail, while ordinary author prose stays free to edit.
// It also checks docs/rules.md against the default registry; repository lookup, the file read, parsing or metadata drift can fail it.
package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestRulesDocsStructuredParserFixtures checks the rules-doc marker grammar on small edits of the one-rule fixture.
//
// Missing required metadata and duplicate or malformed markers fail with the expected error; reordered bullets and two thresholds must parse.
// Rewriting the free prose must leave the parsed contract identical; a difference means the parser is reading prose as metadata.
func TestRulesDocsStructuredParserFixtures(t *testing.T) {
	base := rulesDocsFixture()
	tests := []struct {
		name    string
		body    string
		wantErr string
		wantTwo bool
	}{
		{name: "missing metadata", body: strings.Replace(base, "- **Confidence:** high\n", "", 1), wantErr: "missing Confidence metadata"},
		{name: "duplicate metadata", body: strings.Replace(base, "- **Pillar:** test-quality\n", "- **Pillar:** test-quality\n- **Pillar:** test-quality\n", 1), wantErr: "duplicate Pillar metadata"},
		{name: "malformed metadata", body: strings.Replace(base, "`limit` (default `2`)", "`limit` (default `many`)", 1), wantErr: "malformed Threshold metadata"},
		{name: "malformed marker", body: strings.Replace(base, "- **Tags:**", "- **Tags**:", 1), wantErr: "malformed Tags metadata marker"},
		{name: "reordered metadata", body: rulesDocsReorderedFixture()},
		{name: "multiple thresholds", body: rulesDocsMultiThresholdFixture(), wantTwo: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := parseRulesDocsContract(test.body)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parse error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// Only the two-threshold case checks parsed content; the reordered case passes as soon as it parses.
			if test.wantTwo && len(parsed.Sections["test.sample"].Thresholds) != 2 {
				t.Fatalf("thresholds = %#v, want two", parsed.Sections["test.sample"].Thresholds)
			}
		})
	}
	original, err := parseRulesDocsContract(base)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := parseRulesDocsContract(strings.Replace(base, "Harmless prose.", "Entirely different harmless prose with **Markdown**.", 1))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, changed) {
		t.Fatalf("harmless prose changed parsed contract:\noriginal=%#v\nchanged=%#v", original, changed)
	}
}

// TestRulesDocsStructuredMetadataMatchesRegistry checks docs/rules.md against rule.Defaults, then breaks one fixture field per subtest.
//
// Before the subtests, the repository lookup, file read, parse or comparison can fail; a comparison error names the first mismatch.
// A subtest failure reports a fixture parse error, or a comparison that did not return its field's expected error text.
func TestRulesDocsStructuredMetadataMatchesRegistry(t *testing.T) {
	root := repoRootForTest(t)
	data, err := os.ReadFile(filepath.Join(root, "docs", "rules.md"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseRulesDocsContract(string(data))
	if err != nil {
		t.Fatal(err)
	}
	registry := rule.Defaults()
	if err := compareRulesDocsWithRegistry(parsed, registry.Definitions()); err != nil {
		t.Fatal(err)
	}

	expected := rulesDocsExpectedFixtureDefinition()
	for _, test := range rulesDocsMismatchCases() {
		t.Run(test.name, func(t *testing.T) {
			// Each subtest parses a fresh fixture, so one case's mutation cannot leak into the next.
			fixture, err := parseRulesDocsContract(rulesDocsFixture())
			if err != nil {
				t.Fatal(err)
			}
			applyRulesDocsMismatch(&fixture, test.name)
			err = compareRulesDocsWithRegistry(fixture, []rule.Definition{expected})
			// A nil error means the drift went unnoticed; unexpected text can come from another check or from changed error wording.
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("comparison error = %v, want substring %q", err, test.want)
			}
		})
	}
}

// rulesDocsMismatchCase pairs one field mutation with the error substring that proves the intended comparator rejected the drift.
type rulesDocsMismatchCase struct {
	name string
	want string
}

// rulesDocsMismatchCases lists every summary, catalog and section field that must reject drift on its own.
//
// It returns one case per field, pairing a mutation name applyRulesDocsMismatch handles with the error substring the comparison must report.
func rulesDocsMismatchCases() []rulesDocsMismatchCase {
	return []rulesDocsMismatchCase{
		{name: "summary rule count", want: "summary rule count"},
		{name: "summary pillar count", want: "summary pillar count"},
		{name: "summary default count", want: "summary default count"},
		{name: "summary opt-in count", want: "summary opt-in count"},
		{name: "summary opt-in IDs", want: "summary opt-in IDs"},
		{name: "catalog pillar", want: "catalog test.sample pillar"},
		{name: "catalog severity", want: "catalog test.sample severity"},
		{name: "catalog capability", want: "catalog test.sample capability"},
		{name: "catalog threshold", want: "catalog test.sample thresholds"},
		{name: "section pillar", want: "section test.sample pillar"},
		{name: "section severity", want: "section test.sample severity"},
		{name: "section confidence", want: "section test.sample confidence"},
		{name: "section enablement", want: "section test.sample default-enabled"},
		{name: "section capability", want: "section test.sample capability"},
		{name: "section threshold", want: "section test.sample thresholds"},
		{name: "section tag", want: "section test.sample tags"},
	}
}

// applyRulesDocsMismatch changes exactly one fixture field, so each negative subtest proves its own comparison and not a neighbouring check.
//
// The parsed contract is changed in place, in its summary header or its test.sample catalog row or section.
// The name argument is a case name from rulesDocsMismatchCases and selects the single field to change.
func applyRulesDocsMismatch(parsed *rulesDocsContract, name string) {
	catalog := parsed.Catalog["test.sample"]
	section := parsed.Sections["test.sample"]
	// A case name missing from this switch changes nothing, so its subtest fails because the comparison returns nil.
	switch name {
	case "summary rule count":
		parsed.Header.RuleCount++
	case "summary pillar count":
		parsed.Header.PillarCount++
	case "summary default count":
		parsed.Header.DefaultCount++
	case "summary opt-in count":
		parsed.Header.OptInCount++
	case "summary opt-in IDs":
		parsed.Header.OptInIDs = []string{"test.other"}
	case "catalog pillar":
		catalog.Pillar = "security"
	case "catalog severity":
		catalog.Severity = "warning"
	case "catalog capability":
		catalog.Capability = "ssa"
	case "catalog threshold":
		catalog.Thresholds = map[string]float64{"limit": 3}
	case "section pillar":
		section.Pillar = "security"
	case "section severity":
		section.Severity = "warning"
	case "section confidence":
		section.Confidence = "medium"
	case "section enablement":
		section.DefaultEnabled = true
	case "section capability":
		section.Capability = "ssa"
	case "section threshold":
		section.Thresholds = map[string]float64{"limit": 3}
	case "section tag":
		section.Tags = []string{"other"}
	}
	// The maps hold copies, so both records are stored back; without this the field change would never reach the comparator.
	parsed.Catalog["test.sample"] = catalog
	parsed.Sections["test.sample"] = section
}

// rulesDocsExpectedFixtureDefinition is the registry side of the one-rule fixture that every negative field subtest compares against.
//
// It returns the opt-in test.sample definition whose pillar, severity, confidence, capability, limit threshold and tags match rulesDocsFixture.
func rulesDocsExpectedFixtureDefinition() rule.Definition {
	return rule.Definition{
		ID:             "test.sample",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		Capability:     rule.CapabilityParser,
		DefaultEnabled: false,
		Thresholds:     map[string]float64{"limit": 2},
		Tags:           []string{"sample", "tests"},
	}
}

// rulesDocsFixture returns a complete one-rule docs page for test.sample, plus prose that the parser must ignore.
//
// Other fixtures edit this text by exact string replacement, so rewording a bullet here can turn their edits into no-ops.
func rulesDocsFixture() string {
	return strings.Join([]string{
		"# Rule Catalog", "",
		"`gruff-go` ships **1 rules** across **1 pillars**. **0 rules are enabled by default** and 1 rules are opt-in.", "",
		"Opt-in rules: `test.sample`.", "",
		"| Rule ID | Pillar | Severity | Capability | Default threshold | Description |",
		"|---|---|---|---|---|---|",
		"| [`test.sample`](#testsample) | test-quality | advisory | parser | `limit: 2` | Fixture description. |", "",
		"### `test.sample`", "",
		"- **Pillar:** test-quality",
		"- **Default severity:** advisory",
		"- **Default-enabled:** no (opt-in)",
		"- **Threshold:** `limit` (default `2`)",
		"- **Confidence:** high",
		"- **Capability:** parser",
		"- **Tags:** `sample`, `tests`", "",
		"Harmless prose.", "", "## Configuring rules",
	}, "\n")
}

// rulesDocsReorderedFixture supplies reordered metadata for a test that checks parsing succeeds.
//
// It returns rulesDocsFixture with the test.sample metadata bullets in reverse order and every other line unchanged.
// If those bullets in rulesDocsFixture are reworded, the replacement misses and this returns the fixture in its original order.
func rulesDocsReorderedFixture() string {
	return strings.Replace(rulesDocsFixture(), strings.Join([]string{
		"- **Pillar:** test-quality", "- **Default severity:** advisory",
		"- **Default-enabled:** no (opt-in)", "- **Threshold:** `limit` (default `2`)",
		"- **Confidence:** high", "- **Capability:** parser", "- **Tags:** `sample`, `tests`",
	}, "\n"), strings.Join([]string{
		"- **Tags:** `sample`, `tests`", "- **Capability:** parser", "- **Confidence:** high",
		"- **Threshold:** `limit` (default `2`)", "- **Default-enabled:** no (opt-in)",
		"- **Default severity:** advisory", "- **Pillar:** test-quality",
	}, "\n"), 1)
}

// rulesDocsMultiThresholdFixture supplies a parser fixture with two numeric thresholds in both the catalog row and the section metadata.
//
// Its caller checks only that parsing succeeds and that the test.sample section holds two thresholds.
// It returns rulesDocsFixture with a minimum threshold of 1.5 added beside limit in both the catalog row and the section Threshold bullet.
func rulesDocsMultiThresholdFixture() string {
	body := strings.Replace(rulesDocsFixture(), "`limit: 2`", "`limit: 2`, `minimum: 1.5`", 1)
	return strings.Replace(body, "`limit` (default `2`)", "`minimum` (default `1.5` units), `limit` (default `2`)", 1)
}
