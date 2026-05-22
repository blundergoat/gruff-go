// Package rule defines gruff-go's rule registry and analysers.
// This file exercises the identifier-quality, empty-test, and no-failure-path rules.
package rule

import "testing"

// TestIdentifierQualityFlagsPlaceholders verifies short-variable declarations matching the placeholder list are flagged.
func TestIdentifierQualityFlagsPlaceholders(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func Run() {
	foo := compute()
	tmp := lookup()
	user := load()
	_ = foo
	_ = tmp
	_ = user
}

func compute() int { return 1 }
func lookup() int  { return 2 }
func load() int    { return 3 }
`)
	findings := IdentifierQualityRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (foo, tmp); got %#v", len(findings), findings)
	}
	names := map[string]bool{}
	for _, f := range findings {
		names[f.Symbol] = true
	}
	if !names["foo"] || !names["tmp"] {
		t.Errorf("expected foo + tmp flagged, got %#v", names)
	}
	if names["user"] {
		t.Errorf("user should not be flagged")
	}
}

// TestIdentifierQualityAllowsRemovedDefaultPlaceholders confirms data, info, and qux are no longer default placeholders.
func TestIdentifierQualityAllowsRemovedDefaultPlaceholders(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func Run() {
	data := compute()
	info := lookup()
	qux := load()
	_ = data
	_ = info
	_ = qux
}

func compute() int { return 1 }
func lookup() int  { return 2 }
func load() int    { return 3 }
`)
	findings := IdentifierQualityRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("data, info, and qux should no longer be default placeholders, got %#v", findings)
	}
}

// TestIdentifierQualityIgnoresTestFiles ensures test files are skipped to avoid noisy fixture identifiers.
func TestIdentifierQualityIgnoresTestFiles(t *testing.T) {
	unit := parseOne(t, "pkg/file_test.go", `package pkg

import "testing"

func TestSomething(t *testing.T) {
	data := 1
	_ = data
}
`)
	findings := IdentifierQualityRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("test file should be ignored, got %#v", findings)
	}
}

// TestIdentifierQualityHonoursConfiguredPlaceholders verifies user-supplied placeholder lists replace the defaults.
func TestIdentifierQualityHonoursConfiguredPlaceholders(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func Run() {
	data := compute()
	info := lookup()
	qux := load()
	tmp := 4
	_ = data
	_ = info
	_ = qux
	_ = tmp
}

func compute() int { return 1 }
func lookup() int  { return 2 }
func load() int    { return 3 }
`)
	// Override default list - should flag the configured names but NOT `tmp`.
	rule := IdentifierQualityRule{PlaceholderNames: []string{"data", "info", "qux"}}
	findings := rule.AnalyzeUnit(unit, Context{})
	names := map[string]bool{}
	for _, f := range findings {
		names[f.Symbol] = true
	}
	if len(findings) != 3 || !names["data"] || !names["info"] || !names["qux"] {
		t.Fatalf("expected findings for configured data/info/qux placeholders; got %#v", findings)
	}
	if names["tmp"] {
		t.Fatalf("tmp should not be flagged when it is not configured; got %#v", findings)
	}
}

// TestIdentifierQualityIsDefaultEnabled asserts the rule ships enabled by default.
func TestIdentifierQualityIsDefaultEnabled(t *testing.T) {
	if !(IdentifierQualityRule{}).Definition().DefaultEnabled {
		t.Error("naming.identifier-quality must be default-enabled")
	}
}

// TestEmptyTestRuleFlagsEmptyBody checks the empty-test rule emits a single finding for an empty test body.
func TestEmptyTestRuleFlagsEmptyBody(t *testing.T) {
	unit := parseOne(t, "pkg/sample_test.go", `package pkg

import "testing"

func TestEmpty(t *testing.T) {
}

func TestPopulated(t *testing.T) {
	if 1+1 != 2 {
		t.Fatal("math broken")
	}
}
`)
	findings := EmptyTestRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "TestEmpty" {
		t.Fatalf("expected single finding for TestEmpty; got %#v", findings)
	}
}

// TestEmptyTestRuleIgnoresNonTestFiles confirms non-test files do not trigger empty-test findings.
func TestEmptyTestRuleIgnoresNonTestFiles(t *testing.T) {
	unit := parseOne(t, "pkg/sample.go", `package pkg

func TestEmpty() {
}
`)
	if got := (EmptyTestRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("non-test file should be ignored, got %#v", got)
	}
}

// TestNoFailurePathRuleFlagsAssertionlessTests verifies the no-failure-path rule identifies tests without t.Fatal-style assertions.
func TestNoFailurePathRuleFlagsAssertionlessTests(t *testing.T) {
	unit := parseOne(t, "pkg/sample_test.go", `package pkg

import "testing"

type customErr struct{}

func (customErr) Error() string { return "nope" }

func TestNoAssertion(t *testing.T) {
	t.Log("running")
	value := 1 + 1
	_ = value
}

func TestOnlyErrorString(t *testing.T) {
	err := customErr{}
	_ = err.Error()
}

func TestWithFatal(t *testing.T) {
	if 1+1 != 2 {
		t.Fatalf("broken")
	}
}

func TestWithError(t *testing.T) {
	t.Error("nope")
}

func BenchmarkWithFatal(b *testing.B) {
	b.Fatal("broken")
}

func FuzzWithFatal(f *testing.F) {
	f.Fatal("broken")
}

func TestEmpty(t *testing.T) {
}
`)
	findings := NoFailurePathTestRule{}.AnalyzeUnit(unit, Context{})
	got := map[string]bool{}
	for _, finding := range findings {
		got[finding.Symbol] = true
	}
	if len(got) != 2 || !got["TestNoAssertion"] || !got["TestOnlyErrorString"] {
		t.Fatalf("expected findings for assertionless tests; got %#v", findings)
	}
}

// TestNoFailurePathRuleAcceptsAssertionHelpers ensures tests that delegate
// assertions to helpers (`testutil.AssertStatus(t, ...)`, `require.NoError(t, err)`, etc.)
// are not flagged. The helper-recognition heuristic keys on the prefix and on
// the receiver being passed as an argument, so unrelated `MustX` calls don't
// accidentally suppress the rule.
func TestNoFailurePathRuleAcceptsAssertionHelpers(t *testing.T) {
	unit := parseOne(t, "pkg/sample_test.go", `package pkg

import "testing"

type fakeT struct{}

func MustParse(s string) int { return 0 }
func AssertStatus(t *testing.T, got, want int) {}
func RequireNoError(t *testing.T, err error) {}
func ExpectEqual(t *testing.T, a, b int) {}
func MustEqual(t *testing.T, a, b int) {}
func CheckLen(t *testing.T, s string, n int) {}
func helperWithoutT(s string) {}

func TestAssertHelper(t *testing.T) {
	AssertStatus(t, 200, 200)
}

func TestRequireHelper(t *testing.T) {
	RequireNoError(t, nil)
}

func TestExpectHelper(t *testing.T) {
	ExpectEqual(t, 1, 1)
}

func TestMustHelper(t *testing.T) {
	MustEqual(t, 1, 1)
}

func TestCheckHelper(t *testing.T) {
	CheckLen(t, "abc", 3)
}

func TestQualifiedAssertion(t *testing.T) {
	helpers.AssertStatus(t, 200, 200)
}

// Should still be flagged: MustParse takes no testing receiver,
// so the heuristic must not treat it as an assertion helper.
func TestMustWithoutReceiver(t *testing.T) {
	_ = MustParse("x")
}

// Should still be flagged: helper without an assertion prefix.
func TestUnrelatedHelper(t *testing.T) {
	helperWithoutT("x")
}
`)
	findings := NoFailurePathTestRule{}.AnalyzeUnit(unit, Context{})
	got := map[string]bool{}
	for _, item := range findings {
		got[item.Symbol] = true
	}
	if !got["TestMustWithoutReceiver"] || !got["TestUnrelatedHelper"] {
		t.Fatalf("expected only MustWithoutReceiver + UnrelatedHelper to fire; got %#v", got)
	}
	for _, suppressed := range []string{
		"TestAssertHelper", "TestRequireHelper", "TestExpectHelper",
		"TestMustHelper", "TestCheckHelper", "TestQualifiedAssertion",
	} {
		if got[suppressed] {
			t.Errorf("%s should be accepted as having a failure path", suppressed)
		}
	}
}

// TestNoFailurePathRuleAcceptsTestifyStyleSelectorHelpers confirms calls of
// the form `require.NoError(t, err)`, `assert.Equal(t, ...)`, etc. are
// recognised as a failure path even though the function name itself does not
// carry an Assert/Require/Expect/Must/Check prefix. The recogniser keys on
// the package qualifier (assert/require/expect/must/check) AND on the call
// passing a known testing receiver so unrelated `assert.Something(value)`
// helpers in non-test contexts are not mistaken for assertions.
func TestNoFailurePathRuleAcceptsTestifyStyleSelectorHelpers(t *testing.T) {
	unit := parseOne(t, "pkg/sample_test.go", `package pkg

import "testing"

func TestRequireNoError(t *testing.T) {
	require.NoError(t, nil)
}

func TestAssertEqual(t *testing.T) {
	assert.Equal(t, 1, 1)
}

func TestExpectMatch(t *testing.T) {
	expect.Match(t, "abc")
}

func TestMustOK(t *testing.T) {
	must.OK(t, nil)
}

func TestCheckLen(t *testing.T) {
	check.Len(t, []int{1, 2})
}

// Should still fire: assert.Something but no testing receiver argument.
func TestNonTestingAssertCallStillFires(t *testing.T) {
	_ = 1
	assert.Something("not a t value")
}
`)
	findings := NoFailurePathTestRule{}.AnalyzeUnit(unit, Context{})
	got := map[string]bool{}
	for _, item := range findings {
		got[item.Symbol] = true
	}
	if !got["TestNonTestingAssertCallStillFires"] {
		t.Fatalf("non-testing assert call should still fire, got %#v", got)
	}
	for _, accepted := range []string{
		"TestRequireNoError", "TestAssertEqual", "TestExpectMatch", "TestMustOK", "TestCheckLen",
	} {
		if got[accepted] {
			t.Errorf("%s should be accepted as having a failure path via the assertion-library selector", accepted)
		}
	}
}

// TestNoFailurePathRuleAcceptsAssertionHelperSelfTests covers tests for local
// assertion helpers, where the helper is intentionally called with a locally
// allocated *testing.T instead of the outer test's receiver.
func TestNoFailurePathRuleAcceptsAssertionHelperSelfTests(t *testing.T) {
	unit := parseOne(t, "pkg/helpers_test.go", `package pkg

import "testing"

func AssertStatus(t *testing.T, got, want int) {}
func AssertHeader(t *testing.T, name string) {}

func TestAssertStatusPassesOnMatch(t *testing.T) {
	mockT := &testing.T{}
	AssertStatus(mockT, 200, 200)
}

func TestAssertHeaderPassesWithNew(t *testing.T) {
	mockT := new(testing.T)
	AssertHeader(mockT, "X-Request-ID")
}

func TestMockReceiverAloneStillFires(t *testing.T) {
	mockT := &testing.T{}
	_ = mockT
}
`)
	findings := NoFailurePathTestRule{}.AnalyzeUnit(unit, Context{})
	got := map[string]bool{}
	for _, item := range findings {
		got[item.Symbol] = true
	}
	for _, accepted := range []string{"TestAssertStatusPassesOnMatch", "TestAssertHeaderPassesWithNew"} {
		if got[accepted] {
			t.Errorf("%s should be accepted as an assertion-helper self-test", accepted)
		}
	}
	if !got["TestMockReceiverAloneStillFires"] {
		t.Fatalf("allocating a mock testing receiver alone should not count as a failure path; got %#v", findings)
	}
}

// TestNoFailurePathRuleHandlesFuzzCallbackBodies confirms the rule does not
// misfire on idiomatic fuzz tests, which put their assertions inside the
// callback passed to f.Fuzz. The inner *testing.T parameter is the only handle
// that calls failure methods, so the rule has to walk nested function literals
// when collecting testing receivers.
func TestNoFailurePathRuleHandlesFuzzCallbackBodies(t *testing.T) {
	unit := parseOne(t, "pkg/fuzz_test.go", `package pkg

import "testing"

func FuzzInnerAssertion(f *testing.F) {
	f.Add([]byte("seed"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if data == nil {
			t.Fatal("nope")
		}
	})
}

func FuzzWithSubFunc(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		t.Errorf("got %q", s)
	})
}

func FuzzNoAssertion(f *testing.F) {
	f.Fuzz(func(t *testing.T, n int) {
		_ = n
	})
}
`)
	findings := NoFailurePathTestRule{}.AnalyzeUnit(unit, Context{})
	got := map[string]bool{}
	for _, item := range findings {
		got[item.Symbol] = true
	}
	if !got["FuzzNoAssertion"] {
		t.Fatalf("FuzzNoAssertion should fire (callback never reaches a failure method); got %#v", got)
	}
	for _, accepted := range []string{"FuzzInnerAssertion", "FuzzWithSubFunc"} {
		if got[accepted] {
			t.Errorf("%s should be accepted as having a failure path via the inner callback", accepted)
		}
	}
}

// TestTestQualityRulesDefaultEnabled asserts all test-quality rules ship enabled by default.
func TestTestQualityRulesDefaultEnabled(t *testing.T) {
	for _, definition := range []Definition{
		EmptyTestRule{}.Definition(),
		NoFailurePathTestRule{}.Definition(),
		IdentifierQualityRule{}.Definition(),
	} {
		if !definition.DefaultEnabled {
			t.Errorf("rule %q must be default-enabled", definition.ID)
		}
	}
}
