// Package analysis tests that the composite denominator is derived from the rule registry.
//
// Routed from M06's fresh-context review of the composite-denominator candidate on 2026-09-05:
// a hand-written pillar list silently changes every score when a rule introduces a pillar nobody
// added to it, and no test would notice.
package analysis

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestRuleBackedPillarsCoversEveryRegisteredPillar fails when a registered rule can emit a pillar
// the composite denominator does not count.
//
// Both halves of a rule's declaration are checked. A secondary pillar is still a pillar the rule
// emits findings under, so a pillar reachable only that way would divide the composite by a
// denominator that never counted it.
func TestRuleBackedPillarsCoversEveryRegisteredPillar(t *testing.T) {
	registry := rule.Defaults()
	definitions := registry.Definitions()
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
// would return the same set for both registries below and pass every other test in this package.
func TestRuleBackedPillarsIsDerivedNotHandWritten(t *testing.T) {
	base := []rule.Definition{{ID: "a.one", Pillar: finding.PillarDesign}}
	widened := append(append([]rule.Definition{}, base...), rule.Definition{ID: "b.one", Pillar: finding.PillarSecurity})

	if got := len(ruleBackedPillars(base)); got != 1 {
		t.Fatalf("one rule yielded %d pillars, want 1", got)
	}
	if got := len(ruleBackedPillars(widened)); got != 2 {
		t.Fatalf("two rules under different pillars yielded %d pillars, want 2", got)
	}
}
