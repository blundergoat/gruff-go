// Package rule defines gruff-go's rule registry and analysers.
// This file implements the test-quality.* rules that grade Go test files.
package rule

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// EmptyTestRule flags Go test functions whose body contains no executable statements.
type EmptyTestRule struct{}

// Definition declares the test-quality.empty-test rule that fires on Test/Benchmark/Fuzz functions whose body holds zero statements.
func (EmptyTestRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.empty-test",
		Title:          "Empty test",
		Description:    "Flags Go test functions whose body contains no executable statements.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"opt-in", "tests"},
		Remediation:    "Add an assertion that exercises the behaviour the test name claims, or remove the empty test.",
	}
}

// AnalyzeUnit reports each Test/Benchmark/Fuzz function in the unit that has an empty body.
func (EmptyTestRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !isTestFunction(fn) {
			continue
		}
		if fn.Body == nil || len(fn.Body.List) == 0 {
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

// NoFailurePathTestRule flags Go test functions whose bodies cannot reach a failure call.
type NoFailurePathTestRule struct{}

// Definition declares the test-quality.no-failure-path rule that fires when a Go test body never reaches t.Error/Errorf/Fatal/Fatalf/Fail/FailNow.
func (NoFailurePathTestRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.no-failure-path",
		Title:          "Test cannot fail",
		Description:    "Flags Go test functions that contain executable statements but never reach a failure call (t.Error, t.Fatal, t.Fail, etc.).",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"opt-in", "tests"},
		Remediation:    "Add an assertion or document why the test cannot fail.",
	}
}

// AnalyzeUnit reports each test function whose body never reaches a testing failure method.
func (NoFailurePathTestRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") {
		return nil
	}
	findings := []finding.Finding{}
	testingPackages := testingPackageNames(unit.AST)
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !isTestFunction(fn) {
			continue
		}
		if fn.Body == nil || len(fn.Body.List) == 0 {
			continue
		}
		if hasFailureCall(fn, testingPackages) {
			continue
		}
		position := unit.FileSet.Position(fn.Name.NamePos)
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("test %s has no path that calls a testing failure method", fn.Name.Name),
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Symbol:   fn.Name.Name,
		})
	}
	return findings
}

// isTestFunction returns true for top-level Test... / Benchmark... / Fuzz... functions.
func isTestFunction(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || fn.Name == nil {
		return false
	}
	name := fn.Name.Name
	switch {
	case strings.HasPrefix(name, "Test"):
		return true
	case strings.HasPrefix(name, "Benchmark"):
		return true
	case strings.HasPrefix(name, "Fuzz"):
		return true
	default:
		return false
	}
}

// hasFailureCall reports whether fn invokes either:
//   - a known testing failure helper on a *testing.T/B/F receiver, or
//   - an assertion helper (Assert*/Require*/Expect*/Must*/Check*) that
//     receives the testing receiver as one of its arguments.
//
// The helper-call heuristic was added because most Go test suites factor
// assertions into helpers (`testutil.AssertStatus(t, ...)`); without it the
// rule produced a wave of false positives on otherwise well-asserted tests.
// Requiring the helper to take the receiver as an argument keeps unrelated
// `MustX` calls (e.g. `json.MustDecode`) from being mistaken for assertions.
func hasFailureCall(fn *ast.FuncDecl, testingPackages map[string]bool) bool {
	receivers := testingReceiverNames(fn, testingPackages)
	if len(receivers) == 0 {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isReceiverFailureCall(call, receivers) {
			found = true
			return false
		}
		if isAssertionHelperCall(call, receivers) {
			found = true
			return false
		}
		return true
	})
	return found
}

// isReceiverFailureCall reports whether the call is `<t>.<failing-method>(...)`
// where <t> is one of the known testing receivers.
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

// isAssertionHelperCall reports whether the call looks like a third-party
// assertion helper that will fail the test on its own. The function name must
// begin with a known assertion prefix AND one of its arguments must be a
// testing receiver — both halves are needed to avoid catching unrelated
// `Must*`/`Check*` helpers that have nothing to do with testing.
func isAssertionHelperCall(call *ast.CallExpr, receivers map[string]bool) bool {
	name := callFunctionName(call)
	if !hasAssertionHelperPrefix(name) {
		return false
	}
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

// callFunctionName returns the bare identifier name of a call's function,
// whether the call is `Foo()` or `pkg.Foo()`. Returns empty string for
// dynamic calls (e.g. closures or chained method calls).
func callFunctionName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// hasAssertionHelperPrefix recognizes the common assertion-helper name shapes
// across Go testing libraries (stdlib-style Assert*, testify-style Require*,
// gomega/Ginkgo Expect*, builder Must*, table Check*). The prefix must be
// followed by an uppercase character so prefixes like "Asserts" or "Mustache"
// don't trigger.
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
		case ".", "_":
			continue
		default:
			names[imported.Name.Name] = true
		}
	}
	return names
}

// testingReceiverNames returns the parameter names in fn whose type is *testing.T, *testing.B, or *testing.F.
func testingReceiverNames(fn *ast.FuncDecl, testingPackages map[string]bool) map[string]bool {
	receivers := map[string]bool{}
	if fn.Type == nil || fn.Type.Params == nil {
		return receivers
	}
	for _, field := range fn.Type.Params.List {
		if !isTestingTBFType(field.Type, testingPackages) {
			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" {
				receivers[name.Name] = true
			}
		}
	}
	return receivers
}

// isTestingTBFType reports whether expr names *testing.T, *testing.B, or *testing.F.
func isTestingTBFType(expr ast.Expr, testingPackages map[string]bool) bool {
	pointer, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := pointer.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok || !testingPackages[pkg.Name] {
		return false
	}
	switch selector.Sel.Name {
	case "T", "B", "F":
		return true
	default:
		return false
	}
}
