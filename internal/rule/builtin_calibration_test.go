// Package rule defines gruff-go's rule registry and analysers.
// This file holds calibration tests for the builtin pack: false-positive
// guards added after spot-checking the rubric on a real Go codebase.
package rule

import (
	"testing"
)

// TestFunctionLengthCountsCodeLinesOnly verifies the rule's length measurement
// strips blank lines and comment-only lines so heavily documented functions
// aren't flagged for documentation density alone.
func TestFunctionLengthCountsCodeLinesOnly(t *testing.T) {
	rule := FunctionLengthRule{MaxLines: 5}
	// docHeavy spans 21 raw lines but only 4 code lines - should not fire.
	unit := parseOne(t, "doc_heavy.go", `// Package sample is a test package.
package sample

// docHeavy is heavily commented but trivial.
//
// Step 1: explain what we'll do.
// Step 2: explain why.
// Step 3: hand-wave the implementation.
// Step 4: warn future readers about edge cases.
// Step 5: link to the related ADR.
func docHeavy() int {
	// gather the answer
	a := 1

	// adjust by one
	b := 2

	// combine
	return a + b
}
`)
	if got := rule.AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("doc-heavy function should not fire on code-line counting, got %#v", got)
	}
}

// TestFunctionLengthLeavesNolintToTheInlineFilter confirms the rule reports a generic method `Stack.Wired` on its
// `func` line even under `//nolint:funlen`, so analysis.ApplyInlineSuppressions can suppress it there and count it
// (FAMILY-CONTRACT.md section 13c); the filter's own tests cover which comments suppress it.
func TestFunctionLengthLeavesNolintToTheInlineFilter(t *testing.T) {
	rule := FunctionLengthRule{MaxLines: 3}
	body := `
	a := 1
	b := 2
	c := 3
	d := 4
	_ = a
	_ = b
	_ = c
	_ = d
}
`
	commented := parseOne(t, "generic_nolint.go", "// Package sample is a test package.\npackage sample\n\n//nolint:funlen // setup needs to stay linear\nfunc (s *Stack[T]) Wired() {"+body)
	got := rule.AnalyzeUnit(commented, Context{})
	if len(got) != 1 || got[0].Symbol != "Stack.Wired" || got[0].Location.Line != 5 {
		t.Fatalf("findings = %#v, want one finding on Stack.Wired at its func line 5", got)
	}
}

// TestFunctionLengthStillFiresOnRealCode confirms that a function which
// exceeds the threshold on real code (not just comments) still fires.
func TestFunctionLengthStillFiresOnRealCode(t *testing.T) {
	rule := FunctionLengthRule{MaxLines: 3}
	unit := parseOne(t, "real.go", `// Package sample is a test package.
package sample

func wired() {
	a := 1
	b := 2
	c := 3
	d := 4
	_ = a + b + c + d
}
`)
	got := rule.AnalyzeUnit(unit, Context{})
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %#v", got)
	}
	if symbol := got[0].Symbol; symbol != "wired" {
		t.Fatalf("expected wired, got %q", symbol)
	}
}

// TestFunctionLengthDiscountsTableDrivenTestFixtures verifies large case
// matrices in table-driven tests are treated as fixture data instead of
// executable test logic.
func TestFunctionLengthDiscountsTableDrivenTestFixtures(t *testing.T) {
	rule := FunctionLengthRule{MaxLines: 8}
	unit := parseOne(t, "table_test.go", `package sample

import "testing"

func TestTable(t *testing.T) {
	tests := []struct{ name string; want int }{
		{name: "a", want: 1},
		{name: "b", want: 2},
		{name: "c", want: 3},
		{name: "d", want: 4},
		{name: "e", want: 5},
		{name: "f", want: 6},
		{name: "g", want: 7},
		{name: "h", want: 8},
		{name: "i", want: 9},
	}
	for _, tt := range tests {
		if got := tt.want; got != tt.want {
			t.Fatalf("%s: got %d", tt.name, got)
		}
	}
}
`)
	if got := rule.AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("table fixture rows should not make the test look too long, got %#v", got)
	}
}

// TestFunctionLengthStillFiresOnLongTestLogic keeps the table-fixture
// discount from hiding tests whose executable logic is itself too long.
func TestFunctionLengthStillFiresOnLongTestLogic(t *testing.T) {
	rule := FunctionLengthRule{MaxLines: 5}
	unit := parseOne(t, "logic_test.go", `package sample

import "testing"

func TestLongLogic(t *testing.T) {
	tests := []struct{ name string }{
		{name: "a"},
		{name: "b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := 1
			b := 2
			c := 3
			d := 4
			e := 5
			if got := a + b + c + d + e; got == 0 {
				t.Fatal(got)
			}
		})
	}
}
`)
	got := rule.AnalyzeUnit(unit, Context{})
	if len(got) != 1 || got[0].Symbol != "TestLongLogic" {
		t.Fatalf("long executable test logic should still fire, got %#v", got)
	}
	if got[0].Metadata["tableFixtureLines"] == nil {
		t.Fatalf("expected table fixture metadata on adjusted finding, got %#v", got[0].Metadata)
	}
}
