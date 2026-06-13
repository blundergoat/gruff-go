package rule

import "testing"

// TestNoFailurePathRuleAcceptsCapturedHelperObjects covers helpers that capture
// testing.TB in a local object and later expose assertion-prefixed methods.
func TestNoFailurePathRuleAcceptsCapturedHelperObjects(t *testing.T) {
	unit := parseOne(t, "pkg/captured_test.go", `package pkg

import "testing"

type Harness struct{}

func NewHarness(t *testing.T) Harness { return Harness{} }
func NewHarnessNoReceiver() Harness { return Harness{} }

func TestCapturedAssert(t *testing.T) {
	h := NewHarness(t)
	h.AssertReady()
}

func TestCapturedRequireFromSelector(t *testing.T) {
	h := helpers.NewHarness(t)
	h.RequireReady()
}

func TestCapturedNoReceiver(t *testing.T) {
	h := NewHarnessNoReceiver()
	h.AssertReady()
}

func TestCapturedNonAssertMethod(t *testing.T) {
	h := NewHarness(t)
	h.Ready()
}

func TestCapturedCallBeforeInitialization(t *testing.T) {
	h.AssertReady()
	h := NewHarness(t)
	_ = h
}
`)
	findings := NoFailurePathTestRule{}.AnalyzeUnit(unit, Context{})
	got := map[string]bool{}
	for _, item := range findings {
		got[item.Symbol] = true
	}
	for _, accepted := range []string{"TestCapturedAssert", "TestCapturedRequireFromSelector"} {
		if got[accepted] {
			t.Errorf("%s should be accepted as a captured helper assertion", accepted)
		}
	}
	for _, rejected := range []string{"TestCapturedNoReceiver", "TestCapturedNonAssertMethod", "TestCapturedCallBeforeInitialization"} {
		if !got[rejected] {
			t.Errorf("%s should still produce no-failure-path; got %#v", rejected, findings)
		}
	}
}
