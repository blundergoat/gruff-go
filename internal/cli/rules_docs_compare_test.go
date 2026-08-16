// rules_docs_compare_test.go owns deterministic comparison between parsed
// documentation markers and the built-in registry. Catalog and section
// surfaces remain independent so drift in one cannot be hidden by the other.
package cli

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// compareRulesDocsWithRegistry checks summary, catalog, and per-rule sections
// against definitions returned by the no-config registry.
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
	documentedOptIns := append([]string(nil), parsed.Header.OptInIDs...)
	slices.Sort(documentedOptIns)
	slices.Sort(optInIDs)
	if !slices.Equal(documentedOptIns, optInIDs) {
		return fmt.Errorf("summary opt-in IDs = %q, want %q", documentedOptIns, optInIDs)
	}
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

// compareRulesDocsCatalog checks fields declared by the compact catalog row.
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

// compareRulesDocsSection checks the richer metadata declared below each rule
// heading, sorting map and tag values before comparison.
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

// rulesDocsThresholdSignature provides deterministic map-order-independent
// output for comparisons and field-specific test failures.
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

// rulesDocsListSignature compares tag and ID sets without depending on their
// display order in Markdown or registry construction.
func rulesDocsListSignature(values []string) string {
	sorted := append([]string(nil), values...)
	slices.Sort(sorted)
	return strings.Join(sorted, ",")
}
