// Package rule tests scoped receiver handling for test-quality rules.
package rule

import (
	"testing"
)

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
	if got := (EmptyTestRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 || got[0].Symbol != "TestDotEmpty" {
		t.Fatalf("empty findings = %#v, want TestDotEmpty only", got)
	}
}

// TestEmptyTestParallelOnly binds scheduling-only bodies to the real testing handle.
// Other receivers, nested scopes and additional work must retain their ordinary classification.
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
