// Package rule tests scoped receiver handling for test-quality rules.
package rule

import "testing"

// TestQualityRulesRequireRunnableSignatures confirms Test-prefixed helpers that
// do not match go test entrypoint signatures are ignored.
func TestQualityRulesRequireRunnableSignatures(t *testing.T) {
	unit := parseOne(t, "pkg/sample_test.go", `package pkg

import "testing"

func TestDataBuilder() string {
	return "fixture"
}

func TestEmptyHelper() {
}

func TestRealEmpty(t *testing.T) {
}

func TestNoAssertion(t *testing.T) {
	t.Log("running")
}
`)
	emptyFindings := (EmptyTestRule{}).AnalyzeUnit(unit, Context{})
	if len(emptyFindings) != 1 || emptyFindings[0].Symbol != "TestRealEmpty" {
		t.Fatalf("empty findings = %#v, want TestRealEmpty only", emptyFindings)
	}
	noFailureFindings := (NoFailurePathTestRule{}).AnalyzeUnit(unit, Context{})
	if len(noFailureFindings) != 1 || noFailureFindings[0].Symbol != "TestNoAssertion" {
		t.Fatalf("no-failure findings = %#v, want TestNoAssertion only", noFailureFindings)
	}
}

// TestQualityRulesRecognizeDotImportedTestingHandles covers *T receivers from a
// dot-imported standard testing package.
func TestQualityRulesRecognizeDotImportedTestingHandles(t *testing.T) {
	unit := parseOne(t, "pkg/sample_test.go", `package pkg

import . "testing"

func TestDotFatal(t *T) {
	t.Fatal("broken")
}

func TestDotEmpty(t *T) {
}

func TestDotSkip(t *T) {
	t.Skip("later")
}
`)
	if got := (NoFailurePathTestRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 || got[0].Symbol != "TestDotSkip" {
		t.Fatalf("no-failure findings = %#v, want TestDotSkip only", got)
	}
	if got := (EmptyTestRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 || got[0].Symbol != "TestDotEmpty" {
		t.Fatalf("empty findings = %#v, want TestDotEmpty only", got)
	}
	if got := (SkippedTestRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
		t.Fatalf("skip findings = %#v, want one dot-import skip", got)
	}
}

// TestNoFailurePathRuleRequiresKnownAssertionImport verifies selector-style
// assertions depend on actual assertion-library imports, not local names.
func TestNoFailurePathRuleRequiresKnownAssertionImport(t *testing.T) {
	accepted := parseOne(t, "pkg/assertions_test.go", `package pkg

import (
	"testing"

	assert "github.com/stretchr/testify/assert"
	req "github.com/stretchr/testify/require"
)

func TestImportedAssert(t *testing.T) {
	assert.Equal(t, 1, 1)
}

func TestImportedRequire(t *testing.T) {
	req.NoError(t, nil)
}
`)
	if got := (NoFailurePathTestRule{}).AnalyzeUnit(accepted, Context{}); len(got) != 0 {
		t.Fatalf("known assertion imports should be accepted, got %#v", got)
	}

	rejected := parseOne(t, "pkg/fake_assert_test.go", `package pkg

import "testing"

type fakeAssert struct{}

func (fakeAssert) Equal(t *testing.T, got, want int) {}

var assert fakeAssert

func TestFakeAssertStillFires(t *testing.T) {
	assert.Equal(t, 1, 1)
}
`)
	if got := (NoFailurePathTestRule{}).AnalyzeUnit(rejected, Context{}); len(got) != 1 || got[0].Symbol != "TestFakeAssertStillFires" {
		t.Fatalf("local assert value should not suppress no-failure-path, got %#v", got)
	}
}

// TestNoFailurePathRuleScopesNestedReceivers ensures nested non-testing
// parameters shadow outer testing handles without hiding real closure failures.
func TestNoFailurePathRuleScopesNestedReceivers(t *testing.T) {
	unit := parseOne(t, "pkg/scope_test.go", `package pkg

import "testing"

type fakeT struct{}

func (fakeT) Fatal(args ...any) {}

func TestShadowedReceiverStillFires(t *testing.T) {
	func(t fakeT) {
		t.Fatal("not testing")
	}(fakeT{})
}

func TestClosureUsesOuterReceiver(t *testing.T) {
	func() {
		t.Fatal("testing receiver")
	}()
}
`)
	got := map[string]bool{}
	for _, item := range (NoFailurePathTestRule{}).AnalyzeUnit(unit, Context{}) {
		got[item.Symbol] = true
	}
	if len(got) != 1 || !got["TestShadowedReceiverStillFires"] {
		t.Fatalf("findings = %#v, want only shadowed receiver test", got)
	}
}

// TestSkippedTestRuleScopesReceiversPerFunction verifies testing receiver names
// from one function do not make same-named helpers look like test skips.
func TestSkippedTestRuleScopesReceiversPerFunction(t *testing.T) {
	unit := parseOne(t, "pkg/skips_test.go", `package pkg

import "testing"

type fakeT struct{}

func (fakeT) Skip(args ...any) {}

func helper() {
	var t fakeT
	t.Skip("not testing")
}

func TestNestedShadow(t *testing.T) {
	func(t fakeT) {
		t.Skip("not testing")
	}(fakeT{})
}

func TestClosureSkip(t *testing.T) {
	func() {
		t.Skip("later")
	}()
}

func TestSubtestSkip(t *testing.T) {
	t.Run("x", func(t *testing.T) {
		t.Skip("later")
	})
}
`)
	if got := (SkippedTestRule{}).AnalyzeUnit(unit, Context{}); len(got) != 2 {
		t.Fatalf("skip findings = %#v, want only closure and subtest skips", got)
	}
}
