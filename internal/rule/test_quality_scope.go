// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds the scope helpers the test-quality rules share: Test, Benchmark, and Fuzz signature checks and testing-handle names per scope.
// It also decides which calls count as failure evidence; delegation and assertion-shaped calls count even though their bodies are never read.
package rule

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// knownAssertionPackages maps selector-style assertion library import paths to their default local package names.
//
// Their qualifiers may stand in for an Assert*/Require*/Expect*/Must*/Check* prefix.
// assertionPackageNames records each file's local name for these import paths; a library missing here earns no such credit.
var knownAssertionPackages = map[string]string{
	"github.com/onsi/ginkgo/v2":           "ginkgo",
	"github.com/onsi/gomega":              "gomega",
	"github.com/stretchr/testify/assert":  "assert",
	"github.com/stretchr/testify/require": "require",
	"gotest.tools/v3/assert":              "assert",
	"gotest.tools/v3/assert/cmp":          "cmp",
}

// ginkgoSuiteEntrypoints lists the Ginkgo suite runner entrypoint that counts as failure evidence.
//
// A Go test calling RunSpecs bootstraps a spec suite whose specs this parser-only rule never sees, so the call stands in for its assertions.
// RegisterFailHandler only wires a handler and cannot fail a test by itself, so it is intentionally excluded.
var ginkgoSuiteEntrypoints = map[string]bool{
	"RunSpecs": true,
}

// isRunnableTestFunction reports whether fn matches the supported Test, Benchmark, or Fuzz signature shape; type parameters are not checked.
//
// fn must be a plain function with no results, a name testFunctionReceiverKind accepts, and one matching *testing.T, B, or F parameter.
// testingPackages holds the qualifiers that name package testing in the file, with the key "." standing for a dot import.
// A false result, also given for a method or a nil declaration, means fn is not treated as a test entrypoint.
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

// testFunctionReceiverKind maps a runnable Go test function name to its required receiver type name.
//
// name is the declared function name; T is required for tests, B for benchmarks, and F for fuzz targets.
// It returns the kind and true for Test, Benchmark, or Fuzz alone or followed by a non-lowercase rune, and an empty string and false otherwise.
// So a helper named Testable or Fuzzy is not mistaken for a test entrypoint.
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

// runnableTestSuffix mirrors the testing package's convention that the first rune after Test/Benchmark/Fuzz must not be lowercase.
//
// It reports true when suffix, the name after that prefix, is empty or starts with a rune that is not lowercase, and false otherwise.
func runnableTestSuffix(suffix string) bool {
	if suffix == "" {
		return true
	}
	r, _ := utf8.DecodeRuneInString(suffix)
	return !unicode.IsLower(r)
}

// singleParameterType returns the sole parameter type from a function signature.
//
// params is the signature's parameter list; a grouped field such as a, b int counts once per name and an unnamed field counts once.
// The bool is true only when exactly one parameter is declared; otherwise it is false and the type is nil or the last field's type.
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

// isSpecificTestingReceiverType reports whether expr is a pointer to the named testing receiver type, including dot-imported forms such as *T.
//
// kind is the wanted type name, T, B, or F, and testingPackages holds the qualifiers that name package testing, with "." for a dot import.
// A false result means the parameter is another type, such as *testing.B on a function whose name starts with Test.
func isSpecificTestingReceiverType(expr ast.Expr, testingPackages map[string]bool, kind string) bool {
	got, ok := testingReceiverTypeName(expr, testingPackages)
	return ok && got == kind
}

// testingReceiverTypeName extracts T, B, or F from *testing.T/B/F or a dot-imported *T/B/F receiver type.
//
// expr is the parameter type to inspect, and testingPackages holds the qualifiers that name package testing, with "." for a dot import.
// It returns the type name and true for a match.
// A non-pointer, a qualifier or dot import missing from testingPackages, or any other type name gives an empty string and false.
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
	// A bare *T, *B, or *F names a testing type only when the file dot-imports package testing; otherwise it is a local type.
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
// It returns name and true when name is T, B, or F, and an empty string and false for any other name.
func testingReceiverKind(name string) (string, bool) {
	switch name {
	case "T", "B", "F":
		return name, true
	default:
		return "", false
	}
}

// assertionPackageNames returns the local names a test file uses for known selector-style assertion libraries, plus a dot-import sentinel.
//
// file is the test file; each known import adds its alias, or its package's default local name when unaliased.
// A dot import adds the dotImportedAssertions sentinel instead, and a blank import adds nothing.
//
// It returns an empty, non-nil map for a nil file or one with no known assertion-library imports.
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
		defaultName, known := knownAssertionPackages[importPath]
		if err != nil || !known {
			continue
		}
		name := defaultName
		if imported.Name != nil {
			switch imported.Name.Name {
			// A blank import runs init and exposes no name, so nothing can qualify a call.
			case "_":
				continue
			// A dot import puts the library's names in file scope, so its calls are bare and only the dotImportedAssertions sentinel records it.
			// The sentinel credits bare suite-runner calls; other bare assertion calls still need a recognised testing receiver argument.
			case ".":
				names[dotImportedAssertions] = true
				continue
			default:
				name = imported.Name.Name
			}
		}
		names[name] = true
	}
	return names
}

// dotImportedAssertions is the sentinel recorded when a test file dot-imports an assertion library, leaving no qualifier to match on.
//
// Bare suite runner calls such as RunSpecs(t, "Suite") match on the sentinel; other bare assertion calls still need a testing receiver.
const dotImportedAssertions = "."

// isGinkgoSuiteEntrypoint reports whether call invokes Ginkgo's RunSpecs through a known assertion-library import.
//
// RunSpecs(t, "suite") starts a spec suite whose specs a parser-only rule cannot follow.
// assertionPackages holds the file's local names for known assertion libraries and the dot-import sentinel when one is dot-imported.
// A qualified RunSpecs call needs its qualifier in that set, and a bare one needs the dot-import sentinel.
func isGinkgoSuiteEntrypoint(call *ast.CallExpr, assertionPackages map[string]bool) bool {
	if !ginkgoSuiteEntrypoints[callFunctionName(call)] {
		return false
	}
	// Qualified is the ordinary spelling, a dot import makes it bare, and either way the file must import an assertion library.
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		receiver, isIdent := selector.X.(*ast.Ident)
		return isIdent && assertionPackages[receiver.Name]
	}
	_, bare := call.Fun.(*ast.Ident)
	return bare && assertionPackages[dotImportedAssertions]
}

// blockHasFailureCall walks one function body for parser-visible failure evidence, with receiver names scoped per function literal.
//
// It reports true when body or a nested function literal holds a recognised testing failure, assertion-library, or Ginkgo RunSpecs call.
// A nil body, or one with no such call, reports false; the called functions themselves are not walked.
// True is evidence, not proof: assertion-shaped calls are credited without reading their bodies.
//
// testingPackages and assertionPackages hold the file's qualifiers for package testing and for known assertion libraries.
// receivers holds inherited testing handle names and is not modified; no same-file failure helpers are consulted.
func blockHasFailureCall(body *ast.BlockStmt, testingPackages, assertionPackages, receivers map[string]bool) bool {
	return blockHasFailureCallWithHelpers(body, testingPackages, assertionPackages, receivers, nil)
}

// blockHasFailureCallWithHelpers walks one function body and also matches calls against same-file failure helper summaries.
//
// It reports true when body or a nested function literal holds a recognised testing failure, assertion-library, helper, or Ginkgo RunSpecs call.
// A nil body, or one with no such call, reports false; the called functions themselves are not walked.
// True is evidence, not proof: assertion-shaped calls are credited without reading their bodies.
//
// testingPackages and assertionPackages hold the file's qualifiers for package testing and for known assertion libraries.
// receivers holds inherited testing handle names, and failureHelpers the same-file helper summaries; blockHasFailureCall passes nil for it.
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
		// A closure is walked with its own receiver scope, so a non-testing parameter that shadows an outer t no longer counts as a testing handle.
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
			isGinkgoSuiteEntrypoint(call, assertionPackages)
		return !found
	})
	return found
}

// capturedAssertionHelperObjects records non-blank names paired with calls receiving a testing handle in declarations or assignments.
//
// body is the function body to scan, skipping nested function literals, and receivers holds the testing handle names a call must pass.
// It returns each captured name mapped to the positions of those calls, and an empty map for a nil body or when nothing is captured.
func capturedAssertionHelperObjects(body *ast.BlockStmt, receivers map[string]bool) map[string][]token.Pos {
	objects := map[string][]token.Pos{}
	if body == nil {
		return objects
	}
	ast.Inspect(body, func(node ast.Node) bool {
		// A closure's own helpers are captured when blockHasFailureCallWithHelpers walks that closure with its own receivers.
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

// callExprPassesTestingReceiver reports whether expr is a call whose arguments include a known testing receiver.
// receivers holds the in-scope testing handle names, and any expr that is not a call reports false.
func callExprPassesTestingReceiver(expr ast.Expr, receivers map[string]bool) bool {
	call, ok := expr.(*ast.CallExpr)
	return ok && callPassesTestingReceiver(call, receivers)
}

// scopedReceiversForFuncType applies nested function parameters to an inherited receiver set: testing handles join, other names leave.
//
// testingPackages holds the qualifiers that name package testing, used to decide whether each parameter in fnType is a testing handle.
// It returns a new set built from a copy of parent, which is left unchanged; a nil fnType or parameter list gives the plain copy.
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
// It adds every name field declares except the blank identifier, without checking field's type; scopedReceiversForFuncType checks that first.
func addTestingFieldNames(field *ast.Field, receivers map[string]bool) {
	for _, name := range field.Names {
		if name.Name != "_" {
			receivers[name.Name] = true
		}
	}
}

// removeFieldNames deletes parameter names that shadow inherited receivers.
// It deletes every name field declares, except the blank identifier, from receivers whatever the type of field is.
func removeFieldNames(field *ast.Field, receivers map[string]bool) {
	for _, name := range field.Names {
		if name.Name != "_" {
			delete(receivers, name.Name)
		}
	}
}

// copyReceiverNames returns an independent copy of a testing receiver set.
// Only names that receivers maps to true are copied, so a nil receivers gives an empty, non-nil set.
func copyReceiverNames(receivers map[string]bool) map[string]bool {
	out := map[string]bool{}
	for name, ok := range receivers {
		if ok {
			out[name] = true
		}
	}
	return out
}
