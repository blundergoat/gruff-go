package rule

import "testing"

// TestNoFailurePathRuleAcceptsSameFileFailureHelpers covers local helpers that
// do not use assertion-style names but do fail through the active testing
// receiver.
func TestNoFailurePathRuleAcceptsSameFileFailureHelpers(t *testing.T) {
	unit := parseOne(t, "pkg/local_helper_test.go", `package pkg

import "testing"

func runCompatibilityCheck(t *testing.T, dialect string) {
	t.Helper()
	if dialect == "" {
		t.Fatalf("missing dialect")
	}
}

func helperChain(t *testing.T) {
	runCompatibilityCheck(t, "sqlite")
}

func observeOnly(t *testing.T) {
	t.Log("no failure")
}

func TestDelegatesToFailureHelper(t *testing.T) {
	runCompatibilityCheck(t, "sqlite")
}

func TestDelegatesThroughHelperChain(t *testing.T) {
	helperChain(t)
}

func TestDelegatesToAssertionlessHelperStillFires(t *testing.T) {
	observeOnly(t)
}

func TestSelectorHelperStillFires(t *testing.T) {
	helpers.runCompatibilityCheck(t, "sqlite")
}
`)
	findings := NoFailurePathTestRule{}.AnalyzeUnit(unit, Context{})
	got := map[string]bool{}
	for _, item := range findings {
		got[item.Symbol] = true
	}
	for _, accepted := range []string{"TestDelegatesToFailureHelper", "TestDelegatesThroughHelperChain"} {
		if got[accepted] {
			t.Errorf("%s should be accepted as delegating to a same-file failure helper", accepted)
		}
	}
	for _, rejected := range []string{"TestDelegatesToAssertionlessHelperStillFires", "TestSelectorHelperStillFires"} {
		if !got[rejected] {
			t.Errorf("%s should still produce no-failure-path; got %#v", rejected, findings)
		}
	}
}
