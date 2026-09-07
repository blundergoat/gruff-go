// Package rule defines gruff-go's rule registry and analysers.
// This file contains scope helpers shared by test-quality rules.
package rule

import (
	"go/ast"
	"go/token"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// knownAssertionPackages lists selector-style assertion libraries whose package
// qualifiers may stand in for an Assert*/Require*/Expect*/Must*/Check* prefix.
var knownAssertionPackages = map[string]bool{
	"github.com/onsi/ginkgo/v2":           true,
	"github.com/onsi/gomega":              true,
	"github.com/stretchr/testify/assert":  true,
	"github.com/stretchr/testify/require": true,
	"gotest.tools/v3/assert":              true,
	"gotest.tools/v3/assert/cmp":          true,
}

// ginkgoSuiteEntrypoints hand the whole test over to the Ginkgo runner, which
// owns failure from that point on. A Go test function that calls one of these is
// a suite bootstrap, not an assertion-free test: its assertions live in specs
// this parser-only rule never sees, so treating it as unable to fail reported
// every Ginkgo suite in a repository.
var ginkgoSuiteEntrypoints = map[string]bool{
	"RunSpecs":            true,
	"RegisterFailHandler": true,
}

// isRunnableTestFunction reports whether fn has a signature the Go test runner
// recognises for Test, Benchmark, or Fuzz entrypoints.
func isRunnableTestFunction(fn *ast.FuncDecl, testingPackages map[string]bool) bool {
	if fn == nil || fn.Recv != nil || fn.Name == nil || fn.Type == nil {
		return false
	}
	kind, ok := testFunctionReceiverKind(fn.Name.Name)
	if !ok || fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
		return false
	}
	paramType, ok := singleParameterType(fn.Type.Params)
	return ok && isSpecificTestingReceiverType(paramType, testingPackages, kind)
}

// isRunnableFailurePathTestFunction reports whether no-failure-path should
// inspect fn. Benchmarks are excluded here only; other test-quality rules still
// use isRunnableTestFunction so their benchmark scope does not change.
func isRunnableFailurePathTestFunction(fn *ast.FuncDecl, testingPackages map[string]bool) bool {
	if fn == nil || fn.Name == nil || strings.HasPrefix(fn.Name.Name, "Benchmark") {
		return false
	}
	return isRunnableTestFunction(fn, testingPackages)
}

// isExactSkipOnlyFailurePathTest reports the one duplicate-ownership shape:
// a runnable Test/Fuzz body whose sole AST statement directly skips through
// its entrypoint testing receiver.
func isExactSkipOnlyFailurePathTest(fn *ast.FuncDecl, testingPackages map[string]bool) bool {
	if !isRunnableFailurePathTestFunction(fn, testingPackages) || fn.Body == nil || len(fn.Body.List) != 1 {
		return false
	}
	expression, ok := fn.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expression.X.(*ast.CallExpr)
	return ok && isTestingSkipCall(call, testingReceiverNames(fn, testingPackages))
}

// testFunctionReceiverKind maps a runnable Go test function name to its required
// receiver type name: T for tests, B for benchmarks, and F for fuzz targets.
func testFunctionReceiverKind(name string) (string, bool) {
	for _, candidate := range []struct {
		prefix string
		kind   string
	}{
		{prefix: "Test", kind: "T"},
		{prefix: "Benchmark", kind: "B"},
		{prefix: "Fuzz", kind: "F"},
	} {
		if name == candidate.prefix {
			return candidate.kind, true
		}
		if strings.HasPrefix(name, candidate.prefix) && runnableTestSuffix(name[len(candidate.prefix):]) {
			return candidate.kind, true
		}
	}
	return "", false
}

// runnableTestSuffix mirrors the testing package's convention that the first
// rune after Test/Benchmark/Fuzz must not be lowercase.
func runnableTestSuffix(suffix string) bool {
	if suffix == "" {
		return true
	}
	r, _ := utf8.DecodeRuneInString(suffix)
	return !unicode.IsLower(r)
}

// singleParameterType returns the sole parameter type from a function signature.
func singleParameterType(params *ast.FieldList) (ast.Expr, bool) {
	if params == nil {
		return nil, false
	}
	var out ast.Expr
	count := 0
	for _, field := range params.List {
		names := len(field.Names)
		if names == 0 {
			names = 1
		}
		count += names
		out = field.Type
	}
	return out, count == 1
}

// isSpecificTestingReceiverType reports whether expr is a pointer to the named
// testing receiver type, including dot-imported forms such as *T.
func isSpecificTestingReceiverType(expr ast.Expr, testingPackages map[string]bool, kind string) bool {
	got, ok := testingReceiverTypeName(expr, testingPackages)
	return ok && got == kind
}

// testingReceiverTypeName extracts T, B, or F from *testing.T/B/F or a
// dot-imported *T/B/F receiver type.
func testingReceiverTypeName(expr ast.Expr, testingPackages map[string]bool) (string, bool) {
	pointer, ok := expr.(*ast.StarExpr)
	if !ok {
		return "", false
	}
	switch value := pointer.X.(type) {
	case *ast.SelectorExpr:
		pkg, ok := value.X.(*ast.Ident)
		if !ok || !testingPackages[pkg.Name] {
			return "", false
		}
		return testingReceiverKind(value.Sel.Name)
	case *ast.Ident:
		if !testingPackages["."] {
			return "", false
		}
		return testingReceiverKind(value.Name)
	default:
		return "", false
	}
}

// testingReceiverKind validates a receiver type name accepted by package testing.
func testingReceiverKind(name string) (string, bool) {
	switch name {
	case "T", "B", "F":
		return name, true
	default:
		return "", false
	}
}

// assertionPackageNames returns local import names for known selector-style
// assertion libraries in a test file.
func assertionPackageNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	if file == nil {
		return names
	}
	for _, imported := range file.Imports {
		if imported.Path == nil {
			continue
		}
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil || !knownAssertionPackages[importPath] {
			continue
		}
		name := path.Base(importPath)
		if imported.Name != nil {
			switch imported.Name.Name {
			// A blank import runs init and exposes no name, so nothing can qualify a call.
			case "_":
				continue
			// A dot import puts the library's names in file scope, so its assertions are
			// called bare. Discarding it made every gomega-style `Expect(x).To(...)` and
			// every dot-imported Ginkgo suite look assertion-free.
			case ".":
				names[dotImportedAssertions] = true
				continue
			default:
				name = imported.Name.Name
			}
		}
		names[name] = true
	}
	// A file whose own package clause names an assertion library is inside that library.
	// Its tests call the package's assertions without a qualifier, because they are the
	// package: the single largest false-positive shape measured for this rule, 98 findings,
	// was testify/assert's own test file calling Equal(t, ...) bare.
	if file.Name != nil && assertionPackageBaseNames[file.Name.Name] {
		names[insideAssertionPackage] = true
	}
	return names
}

// assertionPackageBaseNames is the final path segment of every known assertion package,
// which is the identifier such a package declares and the name its own files compile under.
var assertionPackageBaseNames = buildAssertionPackageBaseNames()

// buildAssertionPackageBaseNames derives the base names once, so the two lists cannot drift.
func buildAssertionPackageBaseNames() map[string]bool {
	names := map[string]bool{}
	for importPath := range knownAssertionPackages {
		names[path.Base(importPath)] = true
	}
	return names
}

// dotImportedAssertions is the sentinel name recorded when a test file dot-imports
// an assertion library. There is no qualifier to match on, so the file's bare calls
// are judged by whether they carry a testing receiver instead.
const dotImportedAssertions = "."

// insideAssertionPackage is the sentinel recorded when the file under analysis is part
// of an assertion library rather than a consumer of one.
const insideAssertionPackage = "\x00self"

// isGinkgoSuiteEntrypoint reports whether the call hands the test to Ginkgo.
//
// `RunSpecs(t, "suite")` and `RegisterFailHandler(Fail)` are how a Go test starts a
// spec suite. The assertions then live in specs a parser-only rule cannot follow, so
// the entrypoint itself is the evidence that the test can fail.
func isGinkgoSuiteEntrypoint(call *ast.CallExpr, assertionPackages map[string]bool) bool {
	if !ginkgoSuiteEntrypoints[callFunctionName(call)] {
		return false
	}
	// Qualified is the ordinary spelling; a dot import makes it bare, and either way the
	// file must actually import an assertion library for the name to mean this.
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		receiver, isIdent := selector.X.(*ast.Ident)
		return isIdent && assertionPackages[receiver.Name]
	}
	_, bare := call.Fun.(*ast.Ident)
	return bare && assertionPackages[dotImportedAssertions]
}

// isDelegatedSubtest reports whether the call is `t.Run(name, fn)` where fn is an
// expression rather than a literal body.
//
// A table test that writes `t.Run(tc.name, tc.test)` or `t.Run(name, suite.check)`
// has handed the assertions to a function this walk cannot enter. The literal form is
// already walked as a FuncLit, so this covers only the non-literal argument, which the
// rule previously read as a subtest that asserts nothing.
func isDelegatedSubtest(call *ast.CallExpr, receivers map[string]bool) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Run" || len(call.Args) != 2 {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !receivers[receiver.Name] {
		return false
	}
	_, isLiteral := call.Args[1].(*ast.FuncLit)
	return !isLiteral
}

// isInPackageAssertionCall reports whether a bare call inside an assertion library's
// own package is one of that library's assertions.
//
// Inside `testify/assert` the package's own tests call `Equal(t, a, b)` with no
// qualifier, because the qualifier is the package they are in. The selector check
// cannot see that, which is why the largest single false-positive shape measured for
// this rule was 98 findings inside testify's own test file. Requiring the call to pass
// a testing receiver keeps ordinary in-package helpers out.
func isInPackageAssertionCall(call *ast.CallExpr, receivers map[string]bool, assertionPackages map[string]bool) bool {
	if _, bare := call.Fun.(*ast.Ident); !bare {
		return false
	}
	// Only inside the library itself: elsewhere a bare call is ordinary project code, and
	// crediting it would suppress the findings this rule exists to make.
	if !assertionPackages[insideAssertionPackage] {
		return false
	}
	return callPassesTestingReceiver(call, receivers)
}

// blockHasFailureCall walks one lexical function body with receiver names scoped
// to that function and nested function literals.
func blockHasFailureCall(body *ast.BlockStmt, testingPackages, assertionPackages, receivers map[string]bool) bool {
	return blockHasFailureCallWithHelpers(body, testingPackages, assertionPackages, receivers, nil)
}

// blockHasFailureCallWithHelpers walks one lexical function body and includes
// same-file failure helper summaries when matching delegated assertion paths.
func blockHasFailureCallWithHelpers(body *ast.BlockStmt, testingPackages, assertionPackages, receivers, failureHelpers map[string]bool) bool {
	if body == nil {
		return false
	}
	localReceivers := copyReceiverNames(receivers)
	collectTestingReceiverVariables(body, testingPackages, localReceivers)
	helperObjects := capturedAssertionHelperObjects(body, localReceivers)
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		if funcLit, ok := node.(*ast.FuncLit); ok {
			nestedReceivers := scopedReceiversForFuncType(localReceivers, funcLit.Type, testingPackages)
			found = blockHasFailureCallWithHelpers(funcLit.Body, testingPackages, assertionPackages, nestedReceivers, failureHelpers)
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		found = isReceiverFailureCall(call, localReceivers) ||
			isAssertionHelperCall(call, localReceivers, assertionPackages) ||
			isCapturedAssertionHelperCall(call, helperObjects) ||
			isLocalFailureHelperCall(call, localReceivers, failureHelpers) ||
			isGinkgoSuiteEntrypoint(call, assertionPackages) ||
			isDelegatedSubtest(call, localReceivers) ||
			isInPackageAssertionCall(call, localReceivers, assertionPackages)
		return !found
	})
	return found
}

// capturedAssertionHelperObjects records local helper objects initialized from
// calls that receive a testing handle, such as h := NewHarness(t).
func capturedAssertionHelperObjects(body *ast.BlockStmt, receivers map[string]bool) map[string][]token.Pos {
	objects := map[string][]token.Pos{}
	if body == nil {
		return objects
	}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch stmt := node.(type) {
		case *ast.AssignStmt:
			for index, rhs := range stmt.Rhs {
				if index >= len(stmt.Lhs) || !callExprPassesTestingReceiver(rhs, receivers) {
					continue
				}
				if ident, ok := stmt.Lhs[index].(*ast.Ident); ok && ident.Name != "_" {
					objects[ident.Name] = append(objects[ident.Name], rhs.Pos())
				}
			}
		case *ast.ValueSpec:
			for index, value := range stmt.Values {
				if index >= len(stmt.Names) || !callExprPassesTestingReceiver(value, receivers) {
					continue
				}
				if name := stmt.Names[index]; name.Name != "_" {
					objects[name.Name] = append(objects[name.Name], value.Pos())
				}
			}
		}
		return true
	})
	return objects
}

// callExprPassesTestingReceiver reports whether expr is a call whose arguments
// include a known testing receiver.
func callExprPassesTestingReceiver(expr ast.Expr, receivers map[string]bool) bool {
	call, ok := expr.(*ast.CallExpr)
	return ok && callPassesTestingReceiver(call, receivers)
}

// scopedReceiversForFuncType applies nested function parameters to an inherited
// receiver set, adding testing receivers and removing shadowing non-testing names.
func scopedReceiversForFuncType(parent map[string]bool, fnType *ast.FuncType, testingPackages map[string]bool) map[string]bool {
	scoped := copyReceiverNames(parent)
	if fnType == nil || fnType.Params == nil {
		return scoped
	}
	for _, field := range fnType.Params.List {
		if isTestingTBFType(field.Type, testingPackages) {
			addTestingFieldNames(field, scoped)
			continue
		}
		removeFieldNames(field, scoped)
	}
	return scoped
}

// addTestingFieldNames records named testing receiver parameters in receivers.
func addTestingFieldNames(field *ast.Field, receivers map[string]bool) {
	for _, name := range field.Names {
		if name.Name != "_" {
			receivers[name.Name] = true
		}
	}
}

// removeFieldNames deletes parameter names that shadow inherited receivers.
func removeFieldNames(field *ast.Field, receivers map[string]bool) {
	for _, name := range field.Names {
		if name.Name != "_" {
			delete(receivers, name.Name)
		}
	}
}

// copyReceiverNames returns an independent copy of a testing receiver set.
func copyReceiverNames(receivers map[string]bool) map[string]bool {
	out := map[string]bool{}
	for name, ok := range receivers {
		if ok {
			out[name] = true
		}
	}
	return out
}
