// Package rule tests scoped receiver handling for test-quality rules.
package rule

import (
	"go/ast"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// analyseNoFailurePathUnit runs the package-scoped rule over a single file.
//
// The rule became a project rule so it can credit a failure helper declared in a sibling
// _test.go. Analysing one file is the one-unit case of that, so these tests keep asserting
// exactly what they asserted before, on the same inputs.
func analyseNoFailurePathUnit(unit parser.Unit) []finding.Finding {
	return NoFailurePathTestRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
}

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
	noFailureFindings := analyseNoFailurePathUnit(unit)
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
	if got := analyseNoFailurePathUnit(unit); len(got) != 0 {
		t.Fatalf("exact skip-only test should be owned by skipped-test, got no-failure findings %#v", got)
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
	if got := analyseNoFailurePathUnit(accepted); len(got) != 0 {
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
	if got := analyseNoFailurePathUnit(rejected); len(got) != 1 || got[0].Symbol != "TestFakeAssertStillFires" {
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
	for _, item := range analyseNoFailurePathUnit(unit) {
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

// TestSkipOnlyDeduplicationMatrix pins the sole overlap that no-failure-path
// yields to skipped-test while preserving each rule's independent scope.
func TestSkipOnlyDeduplicationMatrix(t *testing.T) {
	tests := []struct {
		name          string
		code          string
		function      string
		wantSkipped   int
		wantNoFailure int
	}{
		{
			name: "exact test skip",
			code: `package sample
import "testing"
func TestSkip(t *testing.T) {
	t.Skip("later")
}`,
			function: "TestSkip", wantSkipped: 1, wantNoFailure: 0,
		},
		{
			name: "exact test skipf",
			code: `package sample
import "testing"
func TestSkipf(t *testing.T) {
	t.Skipf("later %d", 1)
}`,
			function: "TestSkipf", wantSkipped: 1, wantNoFailure: 0,
		},
		{
			name: "exact test skip now",
			code: `package sample
import "testing"
func TestSkipNow(t *testing.T) {
	t.SkipNow()
}`,
			function: "TestSkipNow", wantSkipped: 1, wantNoFailure: 0,
		},
		{
			name: "testing import alias",
			code: `package sample
import testpkg "testing"
func TestAlias(t *testpkg.T) {
	t.Skip("later")
}`,
			function: "TestAlias", wantSkipped: 1, wantNoFailure: 0,
		},
		{
			name: "comment does not add a statement",
			code: `package sample
import "testing"
func TestComment(t *testing.T) {
	// Explain the tracked skip.
	t.Skip("later")
}`,
			function: "TestComment", wantSkipped: 1, wantNoFailure: 0,
		},
		{
			name: "exact fuzz skip",
			code: `package sample
import "testing"
func FuzzSkip(f *testing.F) {
	f.Skip("later")
}`,
			function: "FuzzSkip", wantSkipped: 1, wantNoFailure: 0,
		},
		{
			name: "benchmark already excluded from no failure",
			code: `package sample
import "testing"
func BenchmarkSkip(b *testing.B) {
	b.Skip("later")
}`,
			function: "BenchmarkSkip", wantSkipped: 1, wantNoFailure: 0,
		},
		{
			name: "helper remains skipped test scope",
			code: `package sample
import "testing"
func helper(t *testing.T) {
	t.Skip("later")
}`,
			function: "helper", wantSkipped: 1, wantNoFailure: 0,
		},
		{
			name: "conditional non debt skip",
			code: `package sample
import "testing"
func unavailable() bool { return true }
func TestConditional(t *testing.T) {
	if unavailable() {
		t.Skip("backend unavailable")
	}
}`,
			function: "TestConditional", wantSkipped: 0, wantNoFailure: 1,
		},
		{
			name: "conditional debt skip",
			code: `package sample
import "testing"
func unavailable() bool { return true }
func TestConditionalDebt(t *testing.T) {
	if unavailable() {
		t.Skip("TODO: restore")
	}
}`,
			function: "TestConditionalDebt", wantSkipped: 1, wantNoFailure: 1,
		},
		{
			name: "nested subtest skip",
			code: `package sample
import "testing"
func TestNested(t *testing.T) {
	t.Run("nested", func(t *testing.T) {
		t.Skip("later")
	})
}`,
			function: "TestNested", wantSkipped: 1, wantNoFailure: 1,
		},
		{
			name: "nested fuzz callback skip",
			code: `package sample
import "testing"
func FuzzNested(f *testing.F) {
	f.Fuzz(func(t *testing.T, value []byte) {
		t.Skip("later")
	})
}`,
			function: "FuzzNested", wantSkipped: 1, wantNoFailure: 1,
		},
		{
			name: "setup then skip",
			code: `package sample
import "testing"
func setup() {}
func TestSetupThenSkip(t *testing.T) {
	setup()
	t.Skip("later")
}`,
			function: "TestSetupThenSkip", wantSkipped: 1, wantNoFailure: 1,
		},
		{
			name: "skip then ordinary code",
			code: `package sample
import "testing"
func setup() {}
func TestSkipThenCode(t *testing.T) {
	t.Skip("later")
	setup()
}`,
			function: "TestSkipThenCode", wantSkipped: 1, wantNoFailure: 1,
		},
		{
			name: "explicit empty statement prevents exact body",
			code: `package sample
import "testing"
func TestEmptyThenSkip(t *testing.T) {
	;
	t.Skip("later")
}`,
			function: "TestEmptyThenSkip", wantSkipped: 1, wantNoFailure: 1,
		},
		{
			name: "non testing receiver skip",
			code: `package sample
import "testing"
type fakeT struct{}
func (fakeT) Skip(...any) {}
func TestFakeReceiver(t *testing.T) {
	var fake fakeT
	fake.Skip("not testing")
}`,
			function: "TestFakeReceiver", wantSkipped: 0, wantNoFailure: 1,
		},
		{
			name: "wrong test signature remains skipped test scope",
			code: `package sample
import "testing"
func TestWrongSignature(t *testing.T, extra int) {
	t.Skip("later")
}`,
			function: "TestWrongSignature", wantSkipped: 1, wantNoFailure: 0,
		},
		{
			name: "fake test parameter belongs to neither rule",
			code: `package sample
type fakeT struct{}
func (fakeT) Skip(...any) {}
func TestFake(t *fakeT) {
	t.Skip("not testing")
}`,
			function: "TestFake", wantSkipped: 0, wantNoFailure: 0,
		},
	}

	registry := Defaults()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			unit := parseOne(t, "pkg/matrix_test.go", test.code)
			findings := skipDedupFindings(registry.Analyze([]parser.Unit{unit}, Context{}))
			assertSkipDedupCounts(t, findings, test.wantSkipped, test.wantNoFailure)
			assertSkipDedupLocations(t, unit, test.function, findings)
		})
	}
}

// skipDedupFindings keeps only the two independently dispatched rules whose
// overlap M12 is testing through the default registry.
func skipDedupFindings(items []finding.Finding) map[string][]finding.Finding {
	out := map[string][]finding.Finding{}
	for _, item := range items {
		switch item.RuleID {
		case "test-quality.skipped-test", "test-quality.no-failure-path":
			out[item.RuleID] = append(out[item.RuleID], item)
		}
	}
	return out
}

// assertSkipDedupCounts requires exact rule IDs and counts for one matrix row.
func assertSkipDedupCounts(t *testing.T, got map[string][]finding.Finding, wantSkipped, wantNoFailure int) {
	t.Helper()
	if len(got["test-quality.skipped-test"]) != wantSkipped ||
		len(got["test-quality.no-failure-path"]) != wantNoFailure {
		t.Errorf("findings = %#v, want skipped-test=%d no-failure-path=%d", got, wantSkipped, wantNoFailure)
	}
}

// assertSkipDedupLocations pins skip findings to the direct call and
// no-failure findings to the runnable function declaration.
func assertSkipDedupLocations(t *testing.T, unit parser.Unit, function string, got map[string][]finding.Finding) {
	t.Helper()
	fn := findFuncDecl(unit.AST, function)
	if fn == nil {
		t.Fatalf("fixture missing function %q", function)
	}
	if len(got["test-quality.skipped-test"]) == 1 {
		wantLine := firstTestingSkipLine(unit, fn)
		if wantLine == 0 || got["test-quality.skipped-test"][0].Location.Line != wantLine {
			t.Errorf("skipped-test location = %#v, want line %d", got["test-quality.skipped-test"], wantLine)
		}
	}
	if len(got["test-quality.no-failure-path"]) == 1 {
		wantLine := unit.FileSet.Position(fn.Name.NamePos).Line
		item := got["test-quality.no-failure-path"][0]
		if item.Location.Line != wantLine || item.Symbol != function {
			t.Errorf("no-failure-path location/symbol = %#v, want line %d symbol %q", item, wantLine, function)
		}
	}
}

// firstTestingSkipLine returns the first receiver-aware skip-call line in fn.
func firstTestingSkipLine(unit parser.Unit, fn *ast.FuncDecl) int {
	receivers := collectFileTestingReceivers(unit.AST, testingPackageNames(unit.AST))
	line := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !isTestingSkipCall(call, receivers) {
			return true
		}
		line = unit.FileSet.Position(call.Pos()).Line
		return false
	})
	return line
}
