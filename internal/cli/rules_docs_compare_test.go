// rules_docs_compare_test.go compares the rule metadata parsed from the rules Markdown with the registry's rule definitions.
//
// Thresholds, tags and opt-in IDs are sorted first, so map and display order never change the result.
// Catalog rows and rule sections are checked separately, so drift in one cannot be hidden by the other.
package cli

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// compareRulesDocsWithRegistry checks the summary, catalog and per-rule sections parsed from the rules Markdown against registry definitions.
//
// The parsed contract holds the summary, catalog rows and rule sections read from the Markdown; definitions is the rule list they must match.
// It returns nil when the summary counts, sorted opt-in IDs, catalog and section sizes, and each rule's row and section agree with definitions.
// Otherwise it returns an error naming the first mismatch, such as a differing count or a rule ID missing from the catalog or sections.
func compareRulesDocsWithRegistry(parsed rulesDocsContract, definitions []rule.Definition) error {
	pillars := map[finding.Pillar]struct{}{}
	defaultCount := 0
	optInIDs := []string{}
	for _, definition := range definitions {
		pillars[definition.Pillar] = struct{}{}
		if definition.DefaultEnabled {
			defaultCount++
		} else {
			optInIDs = append(optInIDs, definition.ID)
		}
	}
	if got, want := parsed.Header.RuleCount, len(definitions); got != want {
		return fmt.Errorf("summary rule count = %d, want %d", got, want)
	}
	if got, want := parsed.Header.PillarCount, len(pillars); got != want {
		return fmt.Errorf("summary pillar count = %d, want %d", got, want)
	}
	if got, want := parsed.Header.DefaultCount, defaultCount; got != want {
		return fmt.Errorf("summary default count = %d, want %d", got, want)
	}
	if got, want := parsed.Header.OptInCount, len(optInIDs); got != want {
		return fmt.Errorf("summary opt-in count = %d, want %d", got, want)
	}
	// The Markdown may list opt-in IDs in any order, so both lists are sorted; the docs list is sorted on a copy so parsed is not changed.
	documentedOptIns := append([]string(nil), parsed.Header.OptInIDs...)
	slices.Sort(documentedOptIns)
	slices.Sort(optInIDs)
	if !slices.Equal(documentedOptIns, optInIDs) {
		return fmt.Errorf("summary opt-in IDs = %q, want %q", documentedOptIns, optInIDs)
	}
	// Only these counts can catch a leftover row or section for a rule the registry no longer has; the loop below walks registry rules.
	if len(parsed.Catalog) != len(definitions) {
		return fmt.Errorf("catalog row count = %d, want %d", len(parsed.Catalog), len(definitions))
	}
	if len(parsed.Sections) != len(definitions) {
		return fmt.Errorf("rule section count = %d, want %d", len(parsed.Sections), len(definitions))
	}
	for _, definition := range definitions {
		catalog, ok := parsed.Catalog[definition.ID]
		if !ok {
			return fmt.Errorf("catalog missing rule %q", definition.ID)
		}
		if err := compareRulesDocsCatalog(catalog, definition); err != nil {
			return err
		}
		section, ok := parsed.Sections[definition.ID]
		if !ok {
			return fmt.Errorf("sections missing rule %q", definition.ID)
		}
		if err := compareRulesDocsSection(section, definition); err != nil {
			return err
		}
	}
	return nil
}

// compareRulesDocsCatalog checks the fields a compact catalog row declares against one registry definition.
//
// The got record is the parsed catalog row and want is the registry definition it must match on pillar, severity, capability and thresholds.
// It returns nil when all four agree, and otherwise an error naming the rule ID, the first differing field, and both values.
func compareRulesDocsCatalog(got rulesDocsCatalogRecord, want rule.Definition) error {
	fields := [][3]string{
		{"pillar", got.Pillar, string(want.Pillar)},
		{"severity", got.Severity, string(want.Severity)},
		{"capability", got.Capability, string(want.Capability)},
		{"thresholds", rulesDocsThresholdSignature(got.Thresholds), rulesDocsThresholdSignature(want.Thresholds)},
	}
	for _, field := range fields {
		if field[1] != field[2] {
			return fmt.Errorf("catalog %s %s = %q, want %q", want.ID, field[0], field[1], field[2])
		}
	}
	return nil
}

// compareRulesDocsSection checks the richer metadata listed under one rule heading, sorting threshold and tag values before comparison.
//
// The got record is the parsed rule section and want is the registry definition it must match, default-enabled flag included.
// It returns nil when every field agrees, and otherwise an error naming the rule ID, the first differing field, and both values.
func compareRulesDocsSection(got rulesDocsSectionRecord, want rule.Definition) error {
	fields := [][3]string{
		{"pillar", got.Pillar, string(want.Pillar)},
		{"severity", got.Severity, string(want.Severity)},
		{"confidence", got.Confidence, string(want.Confidence)},
		{"capability", got.Capability, string(want.Capability)},
		{"thresholds", rulesDocsThresholdSignature(got.Thresholds), rulesDocsThresholdSignature(want.Thresholds)},
		{"tags", rulesDocsListSignature(got.Tags), rulesDocsListSignature(want.Tags)},
	}
	for _, field := range fields {
		if field[1] != field[2] {
			return fmt.Errorf("section %s %s = %q, want %q", want.ID, field[0], field[1], field[2])
		}
	}
	if got.DefaultEnabled != want.DefaultEnabled {
		return fmt.Errorf("section %s default-enabled = %t, want %t", want.ID, got.DefaultEnabled, want.DefaultEnabled)
	}
	return nil
}

// rulesDocsThresholdSignature turns a threshold map into one stable string, so comparisons and failure messages never depend on map order.
//
// The values map holds threshold names and numbers; the result lists them as key=value pairs sorted by key, joined by commas.
// Each number uses the fewest digits that round-trip, never an exponent, and a nil or empty values map gives an empty string.
func rulesDocsThresholdSignature(values map[string]float64) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strconv.FormatFloat(values[key], 'f', -1, 64))
	}
	return strings.Join(parts, ",")
}

// rulesDocsListSignature turns a list such as a rule's tags into one sorted string, so Markdown and registry order never affect a comparison.
//
// The values slice is copied before sorting, so the caller's order is left unchanged.
// It returns the values sorted and joined by commas, duplicates kept, and an empty string when values is nil or empty.
func rulesDocsListSignature(values []string) string {
	sorted := append([]string(nil), values...)
	slices.Sort(sorted)
	return strings.Join(sorted, ",")
}
