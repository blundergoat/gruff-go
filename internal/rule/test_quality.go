// Package rule defines gruff-go's rule registry and analysers.
// This file implements the test-quality.* rules that grade Go test files.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"path"
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
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"tests"},
		Remediation:    "Add an assertion that exercises the behaviour the test name claims, or remove the empty test.",
	}
}

// AnalyzeUnit reports each Test/Benchmark/Fuzz function in the unit that has an empty body.
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
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"tests"},
		// The former text also offered "or document why the test cannot fail", which nothing
		// checks: no doc comment, build tag or annotation suppresses this rule, so the advice
		// named a remedy that does not work.
		Remediation: "Add an assertion, or disable this rule for a package whose tests deliberately assert nothing.",
	}
}

// AnalyzeProject reports every runnable test that cannot fail, judging each one
// against its whole package rather than its own file.
//
// This is a project rule and not a unit rule for one reason: Go test suites
// routinely put shared assertion helpers in a sibling `_test.go`, and a helper
// the rule cannot see is a helper it cannot credit. Reading one file at a time
// reported such tests as assertion-free when they delegate every assertion to a
// helper one file away.
func (NoFailurePathTestRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	findings := []finding.Finding{}
	for _, group := range groupTestUnitsByPackage(units) {
		findings = append(findings, group.analyseNoFailurePath()...)
	}
	return findings
}

// analyseNoFailurePath reports the package's tests that have no failure path,
// crediting helpers declared anywhere in the package.
func (g testPackageGroup) analyseNoFailurePath() []finding.Finding {
	findings := []finding.Finding{}
	failureHelpers := g.failureHelperNames()
	for _, unit := range g.units {
		findings = append(findings, noFailurePathFindingsForUnit(unit, failureHelpers)...)
	}
	return findings
}

// noFailurePathFindingsForUnit reports one file's assertion-free tests, using a
// helper set the caller has already resolved across the package.
func noFailurePathFindingsForUnit(unit parser.Unit, failureHelpers map[string]bool) []finding.Finding {
	findings := []finding.Finding{}
	testingPackages := testingPackageNames(unit.AST)
	assertionPackages := assertionPackageNames(unit.AST)
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !isRunnableFailurePathTestFunction(fn, testingPackages) {
			continue
		}
		if fn.Body == nil || len(fn.Body.List) == 0 {
			continue
		}
		if isExactSkipOnlyFailurePathTest(fn, testingPackages) {
			continue
		}
		if hasFailureCallWithHelpers(fn, testingPackages, assertionPackages, failureHelpers) {
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
//
// Receivers are collected from the outer FuncDecl AND from any nested function
// literal - fuzz tests put their assertions inside `f.Fuzz(func(t *testing.T,
// ...){ t.Fatal(...) })`, where the inner `t` is the only handle that calls
// failure methods.
// hasFailureCallWithHelpers reports whether fn directly fails through a
// testing receiver or delegates to a proven same-file failure helper.
func hasFailureCallWithHelpers(fn *ast.FuncDecl, testingPackages, assertionPackages, failureHelpers map[string]bool) bool {
	receivers := testingReceiverNames(fn, testingPackages)
	if len(receivers) == 0 {
		return false
	}
	return blockHasFailureCallWithHelpers(fn.Body, testingPackages, assertionPackages, receivers, failureHelpers)
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
// assertion helper that will fail the test on its own. Two patterns count:
//
//   - Bare or selector calls whose function name begins with a known assertion
//     prefix (`AssertX`, `RequireX`, `ExpectX`, `MustX`, `CheckX`).
//   - Selector calls whose package qualifier names a well-known assertion
//     library (`assert.X`, `require.X`, `expect.X`, `must.X`, `check.X`) -
//     this covers testify-style `require.NoError(t, err)` and `assert.Equal`
//     where the function name itself does not carry an assertion prefix.
//
// In both cases at least one argument must be a known testing receiver, so
// unrelated `MustX` calls (`json.MustDecode`) and library calls that happen
// to live in an `assert` package but do not take a `*testing.T` are not
// mistaken for assertion helpers.
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

// isCapturedAssertionHelperCall reports whether a local helper object that was
// initialized with the testing receiver calls an assertion-prefixed method.
func isCapturedAssertionHelperCall(call *ast.CallExpr, helperObjects map[string][]token.Pos) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !hasAssertionHelperPrefix(selector.Sel.Name) {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && capturedHelperObjectAvailableBefore(helperObjects[receiver.Name], call.Pos())
}

// capturedHelperObjectAvailableBefore reports whether a helper object was
// initialized with a testing receiver before an assertion-looking method call.
func capturedHelperObjectAvailableBefore(positions []token.Pos, before token.Pos) bool {
	for _, pos := range positions {
		if pos < before {
			return true
		}
	}
	return false
}

// testPackageGroup is the `_test.go` files of one Go package, which is the scope
// a failure helper is actually visible in.
type testPackageGroup struct {
	units []parser.Unit
}

// methodHelperKey prefixes a method helper's name, keeping it in its own namespace so a
// method is never matched by a bare call and a package-qualified call is never matched by a
// method. One map carries both kinds without widening every signature that passes it.
const methodHelperKey = "\x00method:"

// helperKey names a helper declaration by kind, so methods and functions cannot collide.
func helperKey(fn *ast.FuncDecl) string {
	if fn.Recv != nil {
		return methodHelperKey + fn.Name.Name
	}
	return fn.Name.Name
}

// groupTestUnitsByPackage buckets parsed test files by the package they compile
// into, keyed by directory and package clause.
//
// The package clause is part of the key because `foo` and `foo_test` are two
// packages in one directory and cannot see each other's unexported helpers.
func groupTestUnitsByPackage(units []parser.Unit) []testPackageGroup {
	order := []string{}
	byKey := map[string][]parser.Unit{}
	for _, unit := range units {
		if unit.AST == nil || unit.FileSet == nil || unit.AST.Name == nil || !strings.HasSuffix(unit.File.Path, "_test.go") {
			continue
		}
		key := path.Dir(unit.File.Path) + "\x00" + unit.AST.Name.Name
		if _, seen := byKey[key]; !seen {
			order = append(order, key)
		}
		byKey[key] = append(byKey[key], unit)
	}
	groups := make([]testPackageGroup, 0, len(order))
	for _, key := range order {
		groups = append(groups, testPackageGroup{units: byKey[key]})
	}
	return groups
}

// failureHelperNames summarises every helper in the package that accepts a
// testing receiver and can fail the test, whichever file declares it.
//
// This suppresses no-failure-path false positives on tests that delegate all
// assertions to non-Assert-prefixed helpers such as
// runMigrationCompatibilityTest(t, ...). Methods count as well as functions: a
// harness type's `func (h *harness) check(t *testing.T)` fails the test exactly
// as a free function does, and skipping methods reported every suite built that
// way. Both are keyed by bare name, because that is what a call site presents.
func (g testPackageGroup) failureHelperNames() map[string]bool {
	candidates := map[string]*ast.FuncDecl{}
	perFilePackages := map[*ast.FuncDecl][2]map[string]bool{}
	for _, unit := range g.units {
		testingPackages := testingPackageNames(unit.AST)
		assertionPackages := assertionPackageNames(unit.AST)
		for _, decl := range unit.AST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil || isRunnableTestFunction(fn, testingPackages) {
				continue
			}
			if receivers := testingReceiverNames(fn, testingPackages); len(receivers) > 0 {
				candidates[helperKey(fn)] = fn
				perFilePackages[fn] = [2]map[string]bool{testingPackages, assertionPackages}
			}
		}
	}
	resolved := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for key, fn := range candidates {
			if resolved[key] {
				continue
			}
			packages := perFilePackages[fn]
			if hasFailureCallWithHelpers(fn, packages[0], packages[1], resolved) {
				resolved[key] = true
				changed = true
			}
		}
	}
	return resolved
}

// isLocalFailureHelperCall reports whether call invokes a helper from this package
// that was proven to fail through a testing receiver.
//
// Both spellings count. `checkBuild(t, ...)` is the free function; `h.verify(t, ...)`
// is the same helper declared as a method on a harness type, which fails the test in
// exactly the same way. Passing the testing receiver stays required for both, and a
// method is matched only against methods, so `helpers.checkBuild(t, ...)` through an
// imported package stays reported: that is a different function wearing the same name.
func isLocalFailureHelperCall(call *ast.CallExpr, receivers map[string]bool, failureHelpers map[string]bool) bool {
	if len(failureHelpers) == 0 || !callPassesTestingReceiver(call, receivers) {
		return false
	}
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return failureHelpers[fn.Name]
	case *ast.SelectorExpr:
		// Only a method declared in this package counts. A selector whose qualifier is an
		// imported package names a different function that happens to share a helper's name.
		return failureHelpers[methodHelperKey+fn.Sel.Name]
	}
	return false
}

// collectTestingReceiverVariables records local variables initialised as
// *testing.T/B/F values. This keeps tests for assertion helper functions from
// being reported just because they pass a locally allocated mock receiver
// (`mockT := &testing.T{}`) instead of the outer test's `t`.
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

// isTestingReceiverAllocation recognises local mock receiver construction
// forms such as `&testing.T{}` and `new(testing.T)`.
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

// isTestingTBFSelector reports whether expr names testing.T, testing.B, or
// testing.F through an imported standard testing package selector.
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

// callPassesTestingReceiver reports whether any argument of call is a
// known testing receiver identifier.
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

// hasAssertionLibrarySelector recognises calls of the form `assert.X(...)`,
// `require.X(...)`, `expect.X(...)`, `must.X(...)`, or `check.X(...)`. These
// cover testify and similar libraries where the assertion prefix lives on the
// package qualifier, not the method name.
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
func testingReceiverNames(fn *ast.FuncDecl, testingPackages map[string]bool) map[string]bool {
	receivers := map[string]bool{}
	if fn.Type == nil || fn.Type.Params == nil {
		return receivers
	}
	collectTestingFieldNames(fn.Type.Params.List, testingPackages, receivers)
	return receivers
}

// collectNestedTestingReceivers walks body looking for function literals (such
// as the fuzz callback in f.Fuzz(func(t *testing.T, ...){...})) and records
// every *testing.T/B/F parameter name into receivers.
func collectNestedTestingReceivers(body *ast.BlockStmt, testingPackages map[string]bool, receivers map[string]bool) {
	if body == nil {
		return
	}
	ast.Inspect(body, func(node ast.Node) bool {
		funcLit, ok := node.(*ast.FuncLit)
		if !ok || funcLit.Type == nil || funcLit.Type.Params == nil {
			return true
		}
		collectTestingFieldNames(funcLit.Type.Params.List, testingPackages, receivers)
		return true
	})
}

// collectTestingFieldNames adds every non-blank field name whose declared type
// is *testing.T/B/F into receivers.
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
func isTestingTBFType(expr ast.Expr, testingPackages map[string]bool) bool {
	_, ok := testingReceiverTypeName(expr, testingPackages)
	return ok
}
