// Package rule tests additional parser-only test-quality rules.
package rule

import "testing"

// TestHelperMissingTHelperRule covers helpers that fail tests without t.Helper.
func TestHelperMissingTHelperRule(t *testing.T) {
	unit := parseOne(t, "helpers_test.go", `package sample

import "testing"

func requireNoError(t testing.TB, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func requireEqual(t *testing.T, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("got %d", got)
	}
}

func TestReal(t *testing.T) {
	t.Fatal("not a helper")
}
`)
	findings := HelperMissingTHelperRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "requireNoError" {
		t.Fatalf("findings = %#v, want only requireNoError", findings)
	}
}

// TestParallelRangeCaptureRule covers unsafe table-test captures and explicit shadow copies.
func TestParallelRangeCaptureRule(t *testing.T) {
	captured := parseOne(t, "parallel_test.go", `package sample

import "testing"

func TestTable(t *testing.T) {
	tests := []struct {
		name string
		value int
	}{{name: "one", value: 1}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_ = tc.value
		})
	}
}
`)
	if findings := (ParallelRangeCaptureRule{}).AnalyzeUnit(captured, Context{}); len(findings) != 1 {
		t.Fatalf("captured findings = %#v, want one", findings)
	}

	shadowed := parseOne(t, "parallel_test.go", `package sample

import "testing"

func TestTable(t *testing.T) {
	tests := []struct {
		name string
		value int
	}{{name: "one", value: 1}}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_ = tc.value
		})
	}
}
`)
	if findings := (ParallelRangeCaptureRule{}).AnalyzeUnit(shadowed, Context{}); len(findings) != 0 {
		t.Fatalf("shadowed findings = %#v, want none", findings)
	}
}
