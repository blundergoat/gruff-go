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
