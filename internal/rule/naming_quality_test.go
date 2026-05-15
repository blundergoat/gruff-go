package rule

import "testing"

func TestIdentifierQualityFlagsPlaceholders(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func Run() {
	data := compute()
	info := lookup()
	user := load()
	_ = data
	_ = info
	_ = user
}

func compute() int { return 1 }
func lookup() int  { return 2 }
func load() int    { return 3 }
`)
	findings := IdentifierQualityRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (data, info); got %#v", len(findings), findings)
	}
	names := map[string]bool{}
	for _, f := range findings {
		names[f.Symbol] = true
	}
	if !names["data"] || !names["info"] {
		t.Errorf("expected data + info flagged, got %#v", names)
	}
	if names["user"] {
		t.Errorf("user should not be flagged")
	}
}

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

func TestIdentifierQualityHonoursConfiguredPlaceholders(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func Run() {
	customPlaceholder := 1
	tmp := 2
	_ = customPlaceholder
	_ = tmp
}
`)
	// Override default list — should flag `customPlaceholder` but NOT `tmp`.
	rule := IdentifierQualityRule{PlaceholderNames: []string{"customPlaceholder"}}
	findings := rule.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "customPlaceholder" {
		t.Fatalf("expected single finding for customPlaceholder; got %#v", findings)
	}
}

func TestIdentifierQualityIsDefaultDisabled(t *testing.T) {
	if (IdentifierQualityRule{}).Definition().DefaultEnabled {
		t.Error("naming.identifier-quality must be default-disabled in v0.1")
	}
}

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

func TestEmptyTestRuleIgnoresNonTestFiles(t *testing.T) {
	unit := parseOne(t, "pkg/sample.go", `package pkg

func TestEmpty() {
}
`)
	if got := (EmptyTestRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("non-test file should be ignored, got %#v", got)
	}
}

func TestNoFailurePathRuleFlagsAssertionlessTests(t *testing.T) {
	unit := parseOne(t, "pkg/sample_test.go", `package pkg

import "testing"

func TestNoAssertion(t *testing.T) {
	t.Log("running")
	value := 1 + 1
	_ = value
}

func TestWithFatal(t *testing.T) {
	if 1+1 != 2 {
		t.Fatalf("broken")
	}
}

func TestWithError(t *testing.T) {
	t.Error("nope")
}

func TestEmpty(t *testing.T) {
}
`)
	findings := NoFailurePathTestRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "TestNoAssertion" {
		t.Fatalf("expected single finding for TestNoAssertion; got %#v", findings)
	}
}

func TestTestQualityRulesDefaultDisabled(t *testing.T) {
	for _, definition := range []Definition{
		EmptyTestRule{}.Definition(),
		NoFailurePathTestRule{}.Definition(),
		IdentifierQualityRule{}.Definition(),
	} {
		if definition.DefaultEnabled {
			t.Errorf("rule %q must be default-disabled in v0.1", definition.ID)
		}
	}
}
