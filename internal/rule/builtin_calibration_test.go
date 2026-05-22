// Package rule defines gruff-go's rule registry and analysers.
// This file holds calibration tests for the builtin pack: false-positive
// guards added after spot-checking the rubric on a real Go codebase.
package rule

import (
	"go/ast"
	"testing"
)

// TestFunctionLengthCountsCodeLinesOnly verifies the rule's length measurement
// strips blank lines and comment-only lines so heavily documented functions
// aren't flagged for documentation density alone.
func TestFunctionLengthCountsCodeLinesOnly(t *testing.T) {
	rule := FunctionLengthRule{MaxLines: 5}
	// docHeavy spans 21 raw lines but only 4 code lines — should not fire.
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

// TestFunctionLengthHonoursNolintFunlen ensures a `//nolint:funlen` directly
// on a function's doc comment suppresses the finding.
func TestFunctionLengthHonoursNolintFunlen(t *testing.T) {
	rule := FunctionLengthRule{MaxLines: 3}
	unit := parseOne(t, "nolint.go", `// Package sample is a test package.
package sample

//nolint:funlen // setup needs to stay linear
func wired() {
	a := 1
	b := 2
	c := 3
	d := 4
	_ = a
	_ = b
	_ = c
	_ = d
}
`)
	if got := rule.AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("nolint:funlen should suppress finding, got %#v", got)
	}
}

// TestFunctionLengthNolintAcceptsAllShape confirms `//nolint:all` (golangci-lint's
// "suppress every linter" form) also suppresses the function-length rule.
func TestFunctionLengthNolintAcceptsAllShape(t *testing.T) {
	rule := FunctionLengthRule{MaxLines: 3}
	unit := parseOne(t, "nolintall.go", `// Package sample is a test package.
package sample

//nolint:all
func wired() {
	a := 1
	b := 2
	c := 3
	d := 4
	_ = a
	_ = b
	_ = c
	_ = d
}
`)
	if got := rule.AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("nolint:all should suppress finding, got %#v", got)
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

// TestSkippedTestRuleAcceptsConditionalSkips asserts the skipped-test rule no
// longer fires on the common integration-test "guard on missing infrastructure"
// pattern (`if !available { t.Skip(...) }`), but still flags unconditional
// skips and conditional skips that read like TODO debt.
func TestSkippedTestRuleAcceptsConditionalSkips(t *testing.T) {
	unit := parseOne(t, "guard_test.go", `// Package sample is a test package.
package sample

import "testing"

func resourceAvailable() bool { return false }

func TestUnconditional(t *testing.T) {
	t.Skip("manual triage required")
}

func TestConditionalGuard(t *testing.T) {
	if !resourceAvailable() {
		t.Skip("integration backend not available")
	}
}

func TestConditionalWithTodo(t *testing.T) {
	if !resourceAvailable() {
		t.Skip("TODO: re-enable once backend stabilises")
	}
}

func TestConditionalFixmeFmt(t *testing.T) {
	if !resourceAvailable() {
		t.Skipf("FIXME: flaky under load (issue %d)", 42)
	}
}

func TestRangeGuard(t *testing.T) {
	for _, ok := range []bool{true} {
		if !ok {
			t.Skip("disabled row")
		}
	}
}
`)
	findings := SkippedTestRule{}.AnalyzeUnit(unit, Context{})
	gotLines := map[int]bool{}
	for _, item := range findings {
		gotLines[item.Location.Line] = true
	}
	wantSymbols := []string{"TestUnconditional", "TestConditionalWithTodo", "TestConditionalFixmeFmt"}
	for _, sym := range wantSymbols {
		fn := findFuncDecl(unit.AST, sym)
		if fn == nil {
			t.Fatalf("test fixture missing %s", sym)
		}
		testingPackages := testingPackageNames(unit.AST)
		testingReceivers := collectFileTestingReceivers(unit.AST, testingPackages)
		var skipPos int
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && isTestingSkipCall(call, testingReceivers) {
				skipPos = unit.FileSet.Position(call.Pos()).Line
				return false
			}
			return true
		})
		if !gotLines[skipPos] {
			t.Errorf("expected finding for %s at line %d; got %#v", sym, skipPos, findings)
		}
	}
	if len(findings) != len(wantSymbols) {
		t.Fatalf("expected %d findings, got %d: %#v", len(wantSymbols), len(findings), findings)
	}
}

// findFuncDecl returns the top-level function declaration with the given name,
// or nil if absent. Used by skip-test fixtures to locate skip-call lines
// without hard-coding them and rebreaking the test whenever fixtures shift.
func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}
