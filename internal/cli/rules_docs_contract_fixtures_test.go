// rules_docs_contract_fixtures_test.go exercises the narrow rules-doc parser
// and registry comparator with isolated Markdown records. These fixtures prove
// malformed markers fail while ordinary author prose stays freely editable.
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

// TestRulesDocsStructuredParserFixtures covers the narrow marker grammar,
// including errors and prose changes that must not affect parsed metadata.
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

// TestRulesDocsStructuredMetadataMatchesRegistry compares every declared docs
// field to the no-config registry and exercises each comparator field in an
// isolated in-memory fixture.
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
			fixture, err := parseRulesDocsContract(rulesDocsFixture())
			if err != nil {
				t.Fatal(err)
			}
			applyRulesDocsMismatch(&fixture, test.name)
			err = compareRulesDocsWithRegistry(fixture, []rule.Definition{expected})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("comparison error = %v, want substring %q", err, test.want)
			}
		})
	}
}

// rulesDocsMismatchCase names one isolated field mutation and the error text
// that proves its intended comparator rejected the drift.
type rulesDocsMismatchCase struct {
	name string
	want string
}

// rulesDocsMismatchCases names every summary, catalog, and section field that
// must independently reject drift.
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

// applyRulesDocsMismatch changes exactly one fixture field so each negative
// subtest proves the intended comparison rather than a neighbouring check.
func applyRulesDocsMismatch(parsed *rulesDocsContract, name string) {
	catalog := parsed.Catalog["test.sample"]
	section := parsed.Sections["test.sample"]
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
	parsed.Catalog["test.sample"] = catalog
	parsed.Sections["test.sample"] = section
}

// rulesDocsExpectedFixtureDefinition is the registry side of the isolated
// comparator fixture used by every negative field test.
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

// rulesDocsFixture returns a complete one-rule contract plus prose that the
// parser must ignore.
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

// rulesDocsReorderedFixture proves metadata bullet display order is not part
// of the structured contract.
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

// rulesDocsMultiThresholdFixture proves both table and section representations
// preserve more than one numeric knob without map-order dependence.
func rulesDocsMultiThresholdFixture() string {
	body := strings.Replace(rulesDocsFixture(), "`limit: 2`", "`limit: 2`, `minimum: 1.5`", 1)
	return strings.Replace(body, "`limit` (default `2`)", "`minimum` (default `1.5` units), `limit` (default `2`)", 1)
}
