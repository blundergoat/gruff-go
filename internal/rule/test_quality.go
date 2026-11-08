// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds the test-quality.empty-test rule and helpers that spot testing receivers, assertion helpers and failure calls in Go tests.
// A user sees test-quality.empty-test when a scan covers a _test.go file with an empty or Parallel-only test.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// EmptyTestRule flags Go tests with no work beyond scheduling themselves in parallel.
//
// It backs test-quality.empty-test: a runnable test with a missing or empty body, or a TestX whose only statement is a Parallel call.
// Such a body checks nothing; an empty FuzzX also fails go test because it never calls F.Fuzz, F.Fail or F.Skip.
type EmptyTestRule struct{}

// Definition describes empty runnable tests, including a sole testing.T.Parallel call.
// It returns the fixed test-quality.empty-test metadata: advisory severity, high confidence, enabled by default, with a remediation hint.
func (EmptyTestRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.empty-test",
		Title:          "Empty test",
		Description:    "Flags Go test functions with no statements or only a testing.T.Parallel() call.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"tests"},
		Remediation:    "Add an assertion that exercises the behaviour the test name claims, or remove the empty test.",
	}
}

// AnalyzeUnit reports empty runnable tests and tests whose only action schedules parallel execution.
//
// Each finding sits on the test's name and reads "test NAME has an empty body", even for a Parallel-only test.
//
// unit is the parsed file to check; it gives nil unless its path ends in _test.go and its AST and file set are present.
// Otherwise the result is a non-nil slice of one finding per runnable test with a missing, empty or Parallel-only body, empty when there is none.
func (EmptyTestRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") {
		return nil
	}
	findings := []finding.Finding{}
	testingPackages := testingPackageNames(unit.AST)
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !isRunnableTestFunction(fn, testingPackages) {
			continue
		}
		if fn.Body == nil || len(fn.Body.List) == 0 || isParallelOnlyTest(fn, testingPackages) {
			position := unit.FileSet.Position(fn.Name.NamePos)
			findings = append(findings, finding.Finding{
				Message:  fmt.Sprintf("test %s has an empty body", fn.Name.Name),
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   fn.Name.Name,
			})
		}
	}
	return findings
}

// isParallelOnlyTest spots a test whose whole body only schedules it to run in parallel, which AnalyzeUnit reports as empty.
//
// The sole call binds to the test's declared testing handle; a one-statement body cannot rebind or shadow that handle before the call.
//
// It reports true when fn's name starts with Test and its whole body is one no-argument Parallel call on a testing receiver parameter of fn.
// testingPackages holds the testing package's import names that identify those parameters; any other shape reports false.
func isParallelOnlyTest(fn *ast.FuncDecl, testingPackages map[string]bool) bool {
	if !strings.HasPrefix(fn.Name.Name, "Test") || fn.Body == nil || len(fn.Body.List) != 1 {
		return false
	}
	statement, ok := fn.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := statement.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Parallel" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && testingReceiverNames(fn, testingPackages)[receiver.Name]
}

// isReceiverFailureCall reports whether call is Error, Errorf, Fatal, Fatalf, Fail or FailNow on a known testing receiver.
//
// receivers holds the testing receiver names in scope; the qualifier must be one of them as a plain identifier, as in t.Fatal(err).
// It reports false for any other method name, an unknown or non-identifier qualifier, or a call that is not a selector.
func isReceiverFailureCall(call *ast.CallExpr, receivers map[string]bool) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !receivers[receiver.Name] {
		return false
	}
	switch selector.Sel.Name {
	case "Error", "Errorf", "Fatal", "Fatalf", "Fail", "FailNow":
		return true
	}
	return false
}

// isAssertionHelperCall reports whether call looks like a third-party assertion helper that fails the test on its own.
//
// A bare or selector call counts when its name starts with Assert, Require, Expect, Must or Check followed by an uppercase ASCII letter.
// A selector call also counts when its qualifier is in assertionPackages, which covers testify-style require.NoError(t, err) and assert.Equal.
//
// Either way a known testing receiver must be an argument, so json.MustDecode(data) or an assert call with no testing handle does not count.
// receivers holds the testing receiver names in scope, and assertionPackages holds the qualifiers that count as assertion libraries.
// It reports false when no receiver is passed or neither shape matches.
func isAssertionHelperCall(call *ast.CallExpr, receivers map[string]bool, assertionPackages map[string]bool) bool {
	if !callPassesTestingReceiver(call, receivers) {
		return false
	}
	if hasAssertionHelperPrefix(callFunctionName(call)) {
		return true
	}
	if hasAssertionLibrarySelector(call, assertionPackages) {
		return true
	}
	return false
}

// isCapturedAssertionHelperCall reports whether call is an assertion-prefixed method on a helper made by a call passing a testing receiver.
//
// helperObjects maps each helper name to the positions where it captured a testing receiver; call counts only after one of those positions.
// It reports false for a non-selector call, a method name without an assertion prefix, or a helper with no capture before call.
func isCapturedAssertionHelperCall(call *ast.CallExpr, helperObjects map[string][]token.Pos) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !hasAssertionHelperPrefix(selector.Sel.Name) {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && capturedHelperObjectAvailableBefore(helperObjects[receiver.Name], call.Pos())
}

// capturedHelperObjectAvailableBefore reports whether a helper object captured a testing receiver before an assertion-looking method call.
//
// positions lists where the object captured a testing receiver, and before is the call's position.
// It reports false when no position is earlier than before, which includes an empty positions list.
func capturedHelperObjectAvailableBefore(positions []token.Pos, before token.Pos) bool {
	for _, pos := range positions {
		if pos < before {
			return true
		}
	}
	return false
}

// methodHelperKey prefixes the names of failing helpers that are methods, so bare calls and selector calls look up separate keys in one map.
//
// A method never matches a bare call, but selector qualifiers are not resolved, so an imported function can match a recorded method name.
// One map carries both kinds without widening every signature that passes it.
const methodHelperKey = "\x00method:"

// isLocalFailureHelperCall reports whether call invokes a helper that was proven to fail the test through a testing receiver.
//
// Both spellings count: checkBuild(t, ...) as a free function, and h.verify(t, ...) as the same helper declared as a method on a harness type.
// Either way the call must pass a testing receiver, and a selector call is looked up only among method helpers.
//
// receivers holds the testing receiver names, one of which must appear as a plain identifier argument.
// failureHelpers holds the proven failing helper names, methods keyed with the methodHelperKey prefix; an empty map always reports false.
// Selector calls match failureHelpers by method name alone, so helpers.checkBuild(t, ...) counts if a failing method is named checkBuild.
func isLocalFailureHelperCall(call *ast.CallExpr, receivers map[string]bool, failureHelpers map[string]bool) bool {
	if len(failureHelpers) == 0 || !callPassesTestingReceiver(call, receivers) {
		return false
	}
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return failureHelpers[fn.Name]
	case *ast.SelectorExpr:
		// The qualifier is not resolved: any selector call named like a failing method counts, even one into an imported package.
		return failureHelpers[methodHelperKey+fn.Sel.Name]
	}
	return false
}

// collectTestingReceiverVariables records local variables initialised as *testing.T, *testing.B or *testing.F values.
//
// A local mock such as mockT := &testing.T{} then counts as a testing handle when callers look for assertions or failure calls.
//
// It walks body, skipping nested function literals, and adds each non-blank name assigned or declared from a receiver allocation to receivers.
// testingPackages holds the names the standard testing package is imported under; a nil body leaves receivers unchanged.
func collectTestingReceiverVariables(body *ast.BlockStmt, testingPackages map[string]bool, receivers map[string]bool) {
	if body == nil {
		return
	}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch stmt := node.(type) {
		case *ast.AssignStmt:
			for i, rhs := range stmt.Rhs {
				if i >= len(stmt.Lhs) || !isTestingReceiverAllocation(rhs, testingPackages) {
					continue
				}
				if ident, ok := stmt.Lhs[i].(*ast.Ident); ok && ident.Name != "_" {
					receivers[ident.Name] = true
				}
			}
		case *ast.ValueSpec:
			for i, value := range stmt.Values {
				if i >= len(stmt.Names) || !isTestingReceiverAllocation(value, testingPackages) {
					continue
				}
				name := stmt.Names[i]
				if name.Name != "_" {
					receivers[name.Name] = true
				}
			}
		}
		return true
	})
}

// isTestingReceiverAllocation recognises local mock receiver construction such as &testing.T{} and new(testing.T).
// It reports true when expr is such a form for testing.T, B or F, with testingPackages giving the testing import names, and false otherwise.
func isTestingReceiverAllocation(expr ast.Expr, testingPackages map[string]bool) bool {
	switch value := expr.(type) {
	case *ast.UnaryExpr:
		if value.Op != token.AND {
			return false
		}
		lit, ok := value.X.(*ast.CompositeLit)
		return ok && isTestingTBFSelector(lit.Type, testingPackages)
	case *ast.CallExpr:
		ident, ok := value.Fun.(*ast.Ident)
		return ok && ident.Name == "new" && len(value.Args) == 1 && isTestingTBFSelector(value.Args[0], testingPackages)
	default:
		return false
	}
}

// isTestingTBFSelector reports whether expr names testing.T, testing.B or testing.F through an imported standard testing package selector.
//
// testingPackages holds the names the standard testing package is imported under; a bare T, B or F also counts when it includes the dot import.
// Any other expression, or a qualifier that is not a testing import name, reports false.
func isTestingTBFSelector(expr ast.Expr, testingPackages map[string]bool) bool {
	switch value := expr.(type) {
	case *ast.SelectorExpr:
		pkg, ok := value.X.(*ast.Ident)
		if !ok || !testingPackages[pkg.Name] {
			return false
		}
		_, ok = testingReceiverKind(value.Sel.Name)
		return ok
	case *ast.Ident:
		if !testingPackages["."] {
			return false
		}
		_, ok := testingReceiverKind(value.Name)
		return ok
	default:
		return false
	}
}

// callPassesTestingReceiver reports whether any argument of call is a known testing receiver identifier.
// receivers holds those known names; only plain identifier arguments are compared, and a call with no match reports false.
func callPassesTestingReceiver(call *ast.CallExpr, receivers map[string]bool) bool {
	for _, arg := range call.Args {
		ident, ok := arg.(*ast.Ident)
		if !ok {
			continue
		}
		if receivers[ident.Name] {
			return true
		}
	}
	return false
}

// hasAssertionLibrarySelector recognises assertion-library calls such as assert.Equal or require.NoError by their package qualifier.
//
// This covers testify and similar libraries whose qualifier, such as assert, require, expect, must or check, carries the assertion.
// It reports true when call is a selector call whose qualifier is a plain identifier listed in assertionPackages, and false for any other call.
func hasAssertionLibrarySelector(call *ast.CallExpr, assertionPackages map[string]bool) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	return assertionPackages[ident.Name]
}

// callFunctionName returns the final name of a call's function, whether the call is Foo() or pkg.Foo().
//
// A selector call gives its last name even when its receiver is another call, so factory().Check() yields Check.
// Any other callee, such as a function literal called in place or a generic instantiation, gives an empty string.
func callFunctionName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// hasAssertionHelperPrefix recognizes common assertion-helper name shapes across Go testing libraries.
//
// These prefixes are naming heuristics, as in AssertEqual or MustParse; a match does not prove the helper can fail a test.
// The prefix must be followed by an uppercase ASCII letter, so names like Asserts or Mustache do not trigger.
//
// It returns true when name starts with Assert, Require, Expect, Must or Check followed by an uppercase ASCII letter, and false otherwise.
func hasAssertionHelperPrefix(name string) bool {
	for _, prefix := range []string{"Assert", "Require", "Expect", "Must", "Check"} {
		if len(name) <= len(prefix) || !strings.HasPrefix(name, prefix) {
			continue
		}
		next := name[len(prefix)]
		if next >= 'A' && next <= 'Z' {
			return true
		}
	}
	return false
}

// testingPackageNames returns the import names under which the standard "testing" package is reachable.
//
// It reads the imports of file whose path is spelled exactly "testing" in double quotes; a raw-string spelling of the same path is ignored.
// No alias yields testing, an alias yields itself, a dot import yields ".", a blank import is skipped, and no match gives an empty, non-nil map.
func testingPackageNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, imported := range file.Imports {
		if imported.Path == nil || imported.Path.Value != `"testing"` {
			continue
		}
		if imported.Name == nil {
			names["testing"] = true
			continue
		}
		switch imported.Name.Name {
		case "_":
			continue
		case ".":
			names["."] = true
		default:
			names[imported.Name.Name] = true
		}
	}
	return names
}

// testingReceiverNames returns the parameter names in fn whose type is *testing.T, *testing.B, or *testing.F.
// testingPackages holds the names the standard testing package is imported under; a function with no such parameter gives an empty map.
func testingReceiverNames(fn *ast.FuncDecl, testingPackages map[string]bool) map[string]bool {
	receivers := map[string]bool{}
	if fn.Type == nil || fn.Type.Params == nil {
		return receivers
	}
	collectTestingFieldNames(fn.Type.Params.List, testingPackages, receivers)
	return receivers
}

// collectTestingFieldNames adds every non-blank field name whose declared type is *testing.T, *testing.B or *testing.F into receivers.
// fields is the list to scan, such as a parameter list; testingPackages holds the names the standard testing package is imported under.
func collectTestingFieldNames(fields []*ast.Field, testingPackages map[string]bool, receivers map[string]bool) {
	for _, field := range fields {
		if !isTestingTBFType(field.Type, testingPackages) {
			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" {
				receivers[name.Name] = true
			}
		}
	}
}

// isTestingTBFType reports whether expr names *testing.T, *testing.B, or *testing.F.
// testingPackages holds the names the standard testing package is imported under; the check is delegated to testingReceiverTypeName.
func isTestingTBFType(expr ast.Expr, testingPackages map[string]bool) bool {
	_, ok := testingReceiverTypeName(expr, testingPackages)
	return ok
}
