// Package rule guards the security severity distribution that published CI guidance depends on.
//
// docs/ci-integration.md tells readers an error-only gate ignores every built-in security.* finding.
// That is a claim about this registry, so it is asserted here rather than left to go stale silently.
package rule

import (
	"slices"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// securityRuleIDPrefix scopes the guard to the application-security family of rule IDs.
//
// sensitive-data.* is deliberately outside this prefix: it is not the subject of the published gate claim.
const securityRuleIDPrefix = "security."

// TestDefaultSecurityRulesStayBelowError pins the docs/ci-integration.md claim that no default-enabled security.* rule is at error severity.
//
// It asserts the invariant rather than a rule count, so adding an advisory security rule stays green.
// It reads Defaults(), not the effective registry, because this project's .gruff-go.yaml raises security.shell-command to error.
func TestDefaultSecurityRulesStayBelowError(t *testing.T) {
	severityCounts := map[finding.Severity]int{}
	errorTierRuleIDs := []string{}

	// Definitions is a pointer method, so the registry needs a name before it can be queried.
	defaultRegistry := Defaults()
	for _, definition := range defaultRegistry.Definitions() {
		// Default-off rules never run on a default scan, so they cannot break the published gate claim.
		if !definition.DefaultEnabled || !strings.HasPrefix(definition.ID, securityRuleIDPrefix) {
			continue
		}
		severityCounts[definition.Severity]++
		if definition.Severity == finding.SeverityError {
			errorTierRuleIDs = append(errorTierRuleIDs, definition.ID)
		}
	}

	// Reached when no default-enabled rule carries the security. prefix, so the guard fails instead of passing without checking any rule.
	if len(severityCounts) == 0 {
		t.Fatalf("no default-enabled %s* rules found; the guard is not measuring anything", securityRuleIDPrefix)
	}

	if len(errorTierRuleIDs) > 0 {
		slices.Sort(errorTierRuleIDs)
		t.Fatalf("default-enabled %s* rules at error severity: %v\n"+
			"distribution now advisory=%d warning=%d error=%d\n"+
			"docs/ci-integration.md states an error-only gate ignores every built-in %s* finding; "+
			"update that section in the same change that raises a rule to error",
			securityRuleIDPrefix, errorTierRuleIDs,
			severityCounts[finding.SeverityAdvisory],
			severityCounts[finding.SeverityWarning],
			severityCounts[finding.SeverityError],
			securityRuleIDPrefix)
	}
}
