// Package rule tests debt-marker wording shown through skipped-test findings.
// Prose examples stay quiet while an introduced marker keeps the skip actionable.
// The matrix models users waiting on an unavailable external dependency.
package rule

import (
	"fmt"
	"testing"
)

// TestSkippedTestRuleRequiresIntroducedDebtMarkers checks every user-visible
// boundary around explanatory prose and a real marker-led skip reason.
func TestSkippedTestRuleRequiresIntroducedDebtMarkers(t *testing.T) {
	markerCases := []struct {
		name         string
		skipMessage  string
		wantFindings int
	}{
		{name: "mid sentence prose", skipMessage: "The author parked the answer with a TODO/TBD marker, so name it back to them.", wantFindings: 0},
		{name: "quoted prose", skipMessage: `"TODO": the documented marker word`, wantFindings: 0},
		{name: "backticked prose", skipMessage: "`TODO`: the documented marker word", wantFindings: 0},
		{name: "plural word continuation", skipMessage: "TODOs are vocabulary examples", wantFindings: 0},
		{name: "hyphenated name", skipMessage: "todo-without-tracking is a vocabulary example", wantFindings: 0},
		{name: "plural marker prose", skipMessage: "These TODO markers are documented for readiness authors", wantFindings: 0},
		{name: "colon marker", skipMessage: "TODO: restore the backend test", wantFindings: 1},
		{name: "owner marker", skipMessage: "TODO(owner) restore the backend test", wantFindings: 1},
		{name: "go owner marker", skipMessage: "TODO(username): restore the backend test", wantFindings: 1},
		{name: "dashed marker", skipMessage: "FIXME - restore the backend test", wantFindings: 1},
		{name: "bare marker", skipMessage: "TODO", wantFindings: 1},
		{name: "lowercase marker", skipMessage: "todo: restore the backend test", wantFindings: 1},
		{name: "space marker", skipMessage: "TODO add the missing owner", wantFindings: 1},
		{name: "bullet marker", skipMessage: "- TODO: restore the backend test", wantFindings: 1},
		{name: "later physical line", skipMessage: "backend unavailable\nTODO: restore the backend test", wantFindings: 1},
	}

	// Run each message as the reason a user sees when an external dependency is unavailable.
	for _, markerCase := range markerCases {
		t.Run(markerCase.name, func(t *testing.T) {
			scanSource := fmt.Sprintf(`package sample
import "testing"
func unavailable() bool { return true }
func TestConditional(t *testing.T) {
	// The user reaches this skip while the external dependency is unavailable.
	if unavailable() {
		t.Skip(%q)
	}
}`, markerCase.skipMessage)
			unit := parseOne(t, "pkg/marker_test.go", scanSource)
			markerFindings := SkippedTestRule{}.AnalyzeUnit(unit, Context{})
			// A count mismatch means the CLI either hid real debt or mislabeled explanatory prose.
			if len(markerFindings) != markerCase.wantFindings {
				t.Fatalf("message %q produced %d findings, want %d: %#v", markerCase.skipMessage, len(markerFindings), markerCase.wantFindings, markerFindings)
			}
		})
	}
}

// TestSkippedTestRuleRemediationClearsFinding proves both fixes named in the
// catalogue remove the finding users see for an intentionally deferred test.
func TestSkippedTestRuleRemediationClearsFinding(t *testing.T) {
	debtSource := conditionalSkipSource("TODO: restore the backend test")
	// Start from a real finding so a quiet fixed fixture cannot pass vacuously.
	if findings := (SkippedTestRule{}).AnalyzeUnit(parseOne(t, "pkg/debt_test.go", debtSource), Context{}); len(findings) != 1 {
		t.Fatalf("debt fixture produced %d findings, want 1: %#v", len(findings), findings)
	}

	remediatedSources := []struct {
		name   string
		source string
	}{
		{name: "remove skip", source: `package sample
import "testing"
func unavailable() bool { return true }
func TestConditional(t *testing.T) { _ = unavailable() }
`},
		{name: "track outside body", source: `package sample
import "testing"
// Backend restoration is tracked in ISSUE-123.
func unavailable() bool { return true }
func TestConditional(t *testing.T) {
	if unavailable() {
		t.Skip("integration backend unavailable")
	}
}
`},
	}

	// Each catalogue remedy should leave the user with no skipped-test finding.
	for _, remediatedSource := range remediatedSources {
		t.Run(remediatedSource.name, func(t *testing.T) {
			findings := (SkippedTestRule{}).AnalyzeUnit(parseOne(t, "pkg/remediated_test.go", remediatedSource.source), Context{})
			// A remaining finding would make the documented remediation unactionable.
			if len(findings) != 0 {
				t.Fatalf("remediated source produced findings: %#v", findings)
			}
		})
	}
}

// conditionalSkipSource models the guarded integration skip shown to users.
// The caller supplies the exact message whose debt boundary is under test.
func conditionalSkipSource(skipMessage string) string {
	return fmt.Sprintf(`package sample
import "testing"
func unavailable() bool { return true }
func TestConditional(t *testing.T) {
	if unavailable() {
		t.Skip(%q)
	}
}`, skipMessage)
}
