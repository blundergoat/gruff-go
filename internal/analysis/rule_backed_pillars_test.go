// Package analysis tests that the composite denominator is derived from the rule registry.
//
// A hand-written pillar list could miss a pillar a new rule introduces and change the composite score; these tests catch that.
package analysis

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestRuleBackedPillarsCoversEveryRegisteredPillar fails when a registered rule can emit a pillar the composite denominator does not count.
//
// Primary and secondary pillars must both appear in the catalogue-derived set, so the denominator counts them before any finding exists.
func TestRuleBackedPillarsCoversEveryRegisteredPillar(t *testing.T) {
	registry := rule.Defaults()
	definitions := registry.Definitions()
	// An empty registry would let the pillar coverage check pass without checking a single rule.
	if len(definitions) == 0 {
		t.Fatal("registry published no definitions")
	}

	counted := map[finding.Pillar]bool{}
	for _, pillar := range ruleBackedPillars(definitions) {
		counted[pillar] = true
	}

	for _, definition := range definitions {
		if !counted[definition.Pillar] {
			t.Errorf("rule %s declares primary pillar %q, which the composite denominator omits", definition.ID, definition.Pillar)
		}
		for _, secondary := range definition.SecondaryPillars {
			if !counted[secondary] {
				t.Errorf("rule %s declares secondary pillar %q, which the composite denominator omits", definition.ID, secondary)
			}
		}
	}
}

// TestRuleBackedPillarsIsDerivedNotHandWritten fails if the set stops tracking the registry.
//
// Adding a rule under a new pillar must widen the denominator on its own. A hand-written list
// would return the same set for both registries, so these assertions check that a new pillar widens it.
func TestRuleBackedPillarsIsDerivedNotHandWritten(t *testing.T) {
	base := []rule.Definition{{ID: "a.one", Pillar: finding.PillarDesign}}
	// A rule under a new pillar must enter the scoring denominator even before it produces a finding.
	widened := append(append([]rule.Definition{}, base...), rule.Definition{ID: "b.one", Pillar: finding.PillarSecurity})

	if got := len(ruleBackedPillars(base)); got != 1 {
		t.Fatalf("one rule yielded %d pillars, want 1", got)
	}
	if got := len(ruleBackedPillars(widened)); got != 2 {
		t.Fatalf("two rules under different pillars yielded %d pillars, want 2", got)
	}
}
