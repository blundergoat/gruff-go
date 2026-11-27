// Package rule tests scoped receiver handling for test-quality rules.
//
// These tests pin which functions the empty-test rule treats as real go test entrypoints.
// They check that helpers, empty tests and tests that do work through their testing handle are told apart.
package rule

import (
	"testing"
)

// TestQualityRulesRequireRunnableSignatures confirms Test-prefixed helpers that do not match go test entrypoint signatures are ignored.
//
// It expects exactly one finding, on TestRealEmpty, from two helpers, one empty test and one test that only logs.
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
	// TestNoAssertion logs through t, so it is not empty, and the two helpers are not entrypoints; only TestRealEmpty may be reported.
	if len(emptyFindings) != 1 || emptyFindings[0].Symbol != "TestRealEmpty" {
		t.Fatalf("empty findings = %#v, want TestRealEmpty only", emptyFindings)
	}
}

// TestQualityRulesRecognizeDotImportedTestingHandles covers *T receivers from a dot-imported standard testing package.
//
// It expects exactly one finding, on TestDotEmpty, from three tests that take t *T: one fails, one is empty and one skips.
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
	// TestDotFatal and TestDotSkip do work through t, so only the body-less TestDotEmpty may be reported.
	if got := (EmptyTestRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 || got[0].Symbol != "TestDotEmpty" {
		t.Fatalf("empty findings = %#v, want TestDotEmpty only", got)
	}
}

// TestEmptyTestParallelOnly checks that a test whose body only calls Parallel on its own testing handle counts as empty.
//
// Renamed receivers and aliased or dot imports still count; a foreign receiver, a shadowed t in a closure, or any extra work does not.
// Each case builds one TestEntry function and expects either one empty-test finding or none.
func TestEmptyTestParallelOnly(t *testing.T) {
	cases := []struct {
		name    string
		imports string
		param   string
		body    string
		want    int
	}{
		{"parallel only", `import "testing"`, "t *testing.T", "t.Parallel()", 1},
		{"renamed receiver", `import "testing"`, "ctx *testing.T", "ctx.Parallel()", 1},
		{"aliased import", `import check "testing"`, "t *check.T", "t.Parallel()", 1},
		{"dot import", `import . "testing"`, "t *T", "t.Parallel()", 1},
		{"foreign receiver", `import "testing"`, "t *testing.T", "other.Parallel()", 0},
		{"assertion after parallel", `import "testing"`, "t *testing.T", `t.Parallel(); if run() != 1 { t.Fatal("wrong result") }`, 0},
		{"action after parallel", `import "testing"`, "t *testing.T", "t.Parallel(); run()", 0},
		{"nested shadow receiver", `import "testing"`, "t *testing.T", "func(t *Other) { t.Parallel() }(other)", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unit := parseOne(t, "pkg/parallel_test.go", "package pkg\n"+tc.imports+"\nfunc TestEntry("+tc.param+") { "+tc.body+" }")
			findings := (EmptyTestRule{}).AnalyzeUnit(unit, Context{})
			if len(findings) != tc.want {
				t.Fatalf("empty-test findings = %#v, want %d", findings, tc.want)
			}
		})
	}
}
