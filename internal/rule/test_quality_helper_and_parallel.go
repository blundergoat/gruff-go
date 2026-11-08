// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements two parser-only test-quality checks: test-quality.helper-missing-t-helper and test-quality.parallel-range-capture.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// HelperMissingTHelperRule flags test helper functions that fail tests without marking themselves as helpers.
//
// Without t.Helper, a failure inside the helper reports the helper's line instead of the calling test's line, which slows triage.
type HelperMissingTHelperRule struct{}

// Definition declares the test-quality.helper-missing-t-helper rule that gruff-go analyse reports on test helpers.
// It returns the same advisory, medium-confidence, default-enabled Definition on every call.
func (HelperMissingTHelperRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.helper-missing-t-helper",
		Title:          "Test helper missing t.Helper",
		Description:    "Flags non-test helper functions that accept testing.TB, *testing.T, or *testing.B and can fail the test but never call Helper.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"tests"},
		Remediation:    "Call t.Helper() at the start of the helper so failures report the caller's line.",
	}
}

// AnalyzeUnit emits findings for assertion-style helpers that omit t.Helper().
//
// unit is the parsed file, analysed only when it has an AST, a file set and a _test.go path; runnable test functions are never reported.
// It returns one finding per helper that takes a testing handle, has recognised failure evidence, never calls Helper, and is not a whole test body.
// The slice is empty when no helper qualifies, and nil when unit is not analysed.
func (HelperMissingTHelperRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") {
		return nil
	}
	testingPackages := testingPackageNames(unit.AST)
	assertionPackages := assertionPackageNames(unit.AST)
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || isRunnableTestFunction(fn, testingPackages) {
			continue
		}
		receivers := testingHelperReceiverNames(fn, testingPackages)
		if len(receivers) == 0 || helperCallPresent(fn.Body, receivers) || isWholeTestBody(unit, fn, receivers) {
			continue
		}
		if !failsThroughOwnHandle(fn.Body, testingPackages, assertionPackages, receivers) {
			continue
		}
		position := unit.FileSet.Position(fn.Name.NamePos)
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("test helper %s can fail without calling Helper", fn.Name.Name),
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Symbol:   fn.Name.Name,
		})
	}
	return findings
}

// wholeTestBodyMinLines is the span from which a test-named function with no results reads as a whole parameterized test body, not a helper.
//
// A testXxx function that returns nothing and spans 30 or more lines, func line to closing brace, gets no finding even without t.Helper.
const wholeTestBodyMinLines = 30

// isWholeTestBody reports whether fn reads as a whole test body, which this rule exempts from a missing-Helper finding.
//
// It matches selector use drivesBenchmark finds, or a testXxx function that returns nothing and spans wholeTestBodyMinLines or more.
// These bodies are exempt so their failures keep their own source lines rather than being attributed to a caller.
//
// unit supplies the file set that measures the span of fn, the candidate helper, and receivers holds its testing handle names.
// It reports false for any other function, so its missing Helper call can still raise a finding.
func isWholeTestBody(unit parser.Unit, fn *ast.FuncDecl, receivers map[string]bool) bool {
	if drivesBenchmark(fn.Body, receivers) {
		return true
	}
	name := fn.Name.Name
	if len(name) <= len("test") || !strings.HasPrefix(name, "test") || !unicode.IsUpper(rune(name[len("test")])) {
		return false
	}
	if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
		return false
	}
	start, end := unit.FileSet.Position(fn.Pos()).Line, unit.FileSet.Position(fn.End()).Line
	return end-start+1 >= wholeTestBodyMinLines
}

// drivesBenchmark reports whether body selects a benchmark-shaped member on a testing handle, exempting the function from the missing-Helper rule.
//
// body is the helper body, searched with its closures, and receivers holds the testing handle names to match.
// Any selector of N, Loop, ResetTimer, StartTimer, StopTimer, ReportAllocs, ReportMetric or RunParallel on a receiver counts, called or not.
func drivesBenchmark(body *ast.BlockStmt, receivers map[string]bool) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || found {
			return !found
		}
		if root, isIdent := selector.X.(*ast.Ident); isIdent && receivers[root.Name] {
			switch selector.Sel.Name {
			case "N", "Loop", "ResetTimer", "StartTimer", "StopTimer", "ReportAllocs", "ReportMetric", "RunParallel":
				found = true
			}
		}
		return !found
	})
	return found
}

// failsThroughOwnHandle reports whether body has recognised failure or assertion-shaped calls involving testing handles.
// Callee bodies are not inspected.
//
// A closure parameter that redeclares the handle's name, such as t.Run's func(t *testing.T), is the subtest's handle.
// Failures there, and the delegation to the subtest, do not need this helper to call Helper.
//
// body is the helper body and receivers its testing handle names, plus any that collectTestingReceiverVariables finds in body.
// testingPackages and assertionPackages hold the testing and assertion import names used to recognise failure calls and assertion helpers.
func failsThroughOwnHandle(body *ast.BlockStmt, testingPackages, assertionPackages, receivers map[string]bool) bool {
	ownHandles := copyReceiverNames(receivers)
	collectTestingReceiverVariables(body, testingPackages, ownHandles)
	helperObjects := capturedAssertionHelperObjects(body, ownHandles)
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		// A closure such as t.Run's func(t *testing.T) redeclares t, so only the handles it does not redeclare are followed inside.
		if closure, ok := node.(*ast.FuncLit); ok {
			inherited := copyReceiverNames(ownHandles)
			for _, field := range closure.Type.Params.List {
				removeFieldNames(field, inherited)
			}
			found = len(inherited) > 0 && failsThroughOwnHandle(closure.Body, testingPackages, assertionPackages, inherited)
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		found = isReceiverFailureCall(call, ownHandles) || isAssertionHelperCall(call, ownHandles, assertionPackages) ||
			isCapturedAssertionHelperCall(call, helperObjects) || isInPackageAssertionCall(call, ownHandles, assertionPackages)
		return !found
	})
	return found
}

// typeAssertedNames returns names assigned from a type assertion, such as h in h, ok := ti.(tHelper), whose Helper call marks a helper.
//
// body is searched outside nested closures for single type-assertion assignments; the map is empty when body has none.
func typeAssertedNames(body *ast.BlockStmt) map[string]bool {
	names := map[string]bool{}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		if _, asserted := assign.Rhs[0].(*ast.TypeAssertExpr); asserted {
			if name, isIdent := assign.Lhs[0].(*ast.Ident); isIdent {
				names[name.Name] = true
			}
		}
		return true
	})
	return names
}

// ParallelRangeCaptureRule flags parallel subtests that close over range variables.
//
// It reports only in modules on pre-Go 1.22 loop-variable semantics, where parallel subtests can all see the loop's last value.
type ParallelRangeCaptureRule struct{}

// Definition declares the test-quality.parallel-range-capture rule for table-test closure capture.
// It returns the same advisory, medium-confidence, default-enabled Definition on every call.
func (ParallelRangeCaptureRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.parallel-range-capture",
		Title:          "Parallel subtest captures range variable",
		Description:    "Flags t.Parallel subtests that close over range variables without an explicit shadow copy in modules using pre-Go 1.22 loop-variable semantics.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"tests"},
		Remediation:    "Create an explicit shadow copy such as `tc := tc` before starting the parallel subtest, or update the module to Go 1.22+ loop-variable semantics.",
	}
}

// AnalyzeUnit emits findings for table-driven parallel subtests that capture range variables.
//
// unit is the parsed file, analysed only with an AST, a file set and a _test.go path, and ctx holds the scan root bounding the go.mod search.
// It returns the findings for parallel subtest calls that capture a range variable, and an empty slice when none does.
// It returns nil when unit is not analysed, its module targets Go 1.22 or later, or no go.mod version can be read.
func (ParallelRangeCaptureRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") {
		return nil
	}
	// A module on Go 1.22 or later, or a file with no go.mod version up to the scan root, gets no finding from this rule.
	if !usesLegacyRangeLoopVariables(unit, ctx) {
		return nil
	}
	testingPackages := testingPackageNames(unit.AST)
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		findings = append(findings, parallelRangeCaptureFindings(unit, fn.Body, testingPackages)...)
	}
	return findings
}

// testingHelperReceiverNames returns parameter names that can act as test handles inside helper functions.
//
// fn is the function whose parameters are read and testingPackages the testing import names; method receivers and blank names are left out.
// The map is empty when fn has no named parameter of a testing handle type.
func testingHelperReceiverNames(fn *ast.FuncDecl, testingPackages map[string]bool) map[string]bool {
	receivers := map[string]bool{}
	if fn.Type == nil || fn.Type.Params == nil {
		return receivers
	}
	for _, field := range fn.Type.Params.List {
		if !isTestingHelperReceiverType(field.Type, testingPackages) {
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

// isTestingHelperReceiverType recognises testing.TB plus pointer T/B/F receivers.
//
// expr is a parameter type and testingPackages the testing import names, where the key "." marks a dot import.
// It reports true for those types, an unqualified TB under a dot import included, and false for any other expr.
func isTestingHelperReceiverType(expr ast.Expr, testingPackages map[string]bool) bool {
	if isTestingTBFType(expr, testingPackages) {
		return true
	}
	switch value := expr.(type) {
	case *ast.SelectorExpr:
		pkg, ok := value.X.(*ast.Ident)
		return ok && testingPackages[pkg.Name] && value.Sel.Name == "TB"
	case *ast.Ident:
		return testingPackages["."] && value.Name == "TB"
	default:
		return false
	}
}

// helperCallPresent reports whether a known testing receiver invokes Helper in the helper's own body.
//
// body is the helper body, searched outside nested closures, and receivers holds its testing handle names.
// A Helper call through a type-asserted name, or directly on a type assertion expression, also counts.
func helperCallPresent(body *ast.BlockStmt, receivers map[string]bool) bool {
	asserted := typeAssertedNames(body)
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Helper" {
			return true
		}
		switch receiver := selector.X.(type) {
		case *ast.Ident:
			found = receivers[receiver.Name] || asserted[receiver.Name]
		case *ast.TypeAssertExpr:
			// t.(interface{ Helper() }).Helper() reaches Helper through an assertion.
			found = true
		}
		return !found
	})
	return found
}

// parallelRangeCaptureFindings finds t.Run closures with t.Parallel that use unshadowed range variables.
//
// unit supplies the file path and positions, body is the function body to search, and testingPackages holds the testing import names.
// It returns the parallelCapturesInRange findings of every range statement in body, nested ones included; the slice is empty when nothing is found.
func parallelRangeCaptureFindings(unit parser.Unit, body *ast.BlockStmt, testingPackages map[string]bool) []finding.Finding {
	findings := []finding.Finding{}
	ast.Inspect(body, func(node ast.Node) bool {
		rangeStmt, ok := node.(*ast.RangeStmt)
		if !ok {
			return true
		}
		rangeVars := rangeVariableNames(rangeStmt)
		// A range with blank or absent key and value, such as for range items, has nothing a subtest could capture.
		if len(rangeVars) == 0 {
			return true
		}
		findings = append(findings, parallelCapturesInRange(unit, rangeStmt, rangeVars, testingPackages)...)
		return true
	})
	return findings
}

// parallelCapturesInRange checks one range body for unsafe parallel subtest captures.
//
// unit supplies the file path and positions, rangeStmt is the loop whose body is read, and rangeVars holds its key and value names.
// testingPackages holds the testing import names used to find t.Parallel inside each Run closure.
// It returns at most one finding per Run call, naming one unshadowed captured variable, and an empty slice when none is found.
func parallelCapturesInRange(unit parser.Unit, rangeStmt *ast.RangeStmt, rangeVars map[string]bool, testingPackages map[string]bool) []finding.Finding {
	findings := []finding.Finding{}
	shadowed := map[string]bool{}
	for _, stmt := range rangeStmt.Body.List {
		recordRangeShadow(stmt, rangeVars, shadowed)
		ast.Inspect(stmt, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !isSubtestRunCall(call) {
				return true
			}
			lit := subtestFuncLiteral(call)
			if lit == nil || !funcLitCallsParallel(lit, testingPackages) {
				return true
			}
			// With both key and value captured, map order picks which one the finding names, so the message can change between runs.
			for name := range rangeVars {
				if shadowed[name] || !funcLitUsesIdent(lit, name) {
					continue
				}
				position := unit.FileSet.Position(call.Pos())
				findings = append(findings, finding.Finding{
					Message:  fmt.Sprintf("parallel subtest captures range variable %q", name),
					File:     unit.File.Path,
					Location: &finding.Location{Line: position.Line, Column: position.Column},
					Metadata: map[string]any{"variable": name},
				})
				break
			}
			return true
		})
	}
	return findings
}

// rangeVariableNames returns non-blank key/value identifiers named by a range statement, whether declared with := or assigned with =.
// stmt is the range statement read; the map is empty when neither key nor value is a non-blank identifier.
func rangeVariableNames(stmt *ast.RangeStmt) map[string]bool {
	out := map[string]bool{}
	for _, expr := range []ast.Expr{stmt.Key, stmt.Value} {
		ident, ok := expr.(*ast.Ident)
		if ok && ident.Name != "_" {
			out[ident.Name] = true
		}
	}
	return out
}

// recordRangeShadow recognises tc := tc style copies before t.Run, which stop a range variable from raising a capture finding.
// stmt is one statement of the range body, rangeVars holds the loop's variable names, and shadowed receives each one copied to itself with :=.
func recordRangeShadow(stmt ast.Stmt, rangeVars, shadowed map[string]bool) {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != len(assign.Rhs) {
		return
	}
	for index, lhs := range assign.Lhs {
		left, leftOK := lhs.(*ast.Ident)
		right, rightOK := assign.Rhs[index].(*ast.Ident)
		if leftOK && rightOK && left.Name == right.Name && rangeVars[left.Name] {
			shadowed[left.Name] = true
		}
	}
}

// isSubtestRunCall reports whether call is a selector Run invocation.
// Any x.Run counts, not only a testing handle's, so a Run method on another type is checked as a subtest too.
func isSubtestRunCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Run"
}

// subtestFuncLiteral returns the function literal argument passed to t.Run.
// call is the Run call; the first function literal among its arguments is returned, or nil when call has none.
func subtestFuncLiteral(call *ast.CallExpr) *ast.FuncLit {
	for _, arg := range call.Args {
		if lit, ok := arg.(*ast.FuncLit); ok {
			return lit
		}
	}
	return nil
}

// funcLitCallsParallel reports whether a Parallel call anywhere in lit's body uses one of lit's testing-handle parameter names.
// Nested closures are searched without rescoping those names.
// lit is the subtest closure and testingPackages the testing import names that identify its handle parameters; a nil lit or body reports false.
func funcLitCallsParallel(lit *ast.FuncLit, testingPackages map[string]bool) bool {
	if lit == nil || lit.Body == nil {
		return false
	}
	receivers := scopedReceiversForFuncType(map[string]bool{}, lit.Type, testingPackages)
	found := false
	ast.Inspect(lit.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Parallel" {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		found = ok && receivers[receiver.Name]
		return !found
	})
	return found
}

// funcLitUsesIdent reports whether lit references name without redeclaring it inside the closure.
//
// Closures nested inside lit are skipped; parameters, := assignments and var or const specs hide later uses of name, but range bindings do not.
// A nil lit or body reports false.
func funcLitUsesIdent(lit *ast.FuncLit, name string) bool {
	if lit == nil || lit.Body == nil {
		return false
	}
	declared := map[string]bool{}
	if lit.Type != nil && lit.Type.Params != nil {
		for _, field := range lit.Type.Params.List {
			for _, param := range field.Names {
				declared[param.Name] = true
			}
		}
	}
	used := false
	ast.Inspect(lit.Body, func(node ast.Node) bool {
		if used {
			return false
		}
		switch value := node.(type) {
		case *ast.FuncLit:
			return value == lit
		case *ast.AssignStmt:
			if value.Tok == token.DEFINE {
				for _, lhs := range value.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						declared[ident.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, ident := range value.Names {
				declared[ident.Name] = true
			}
		case *ast.Ident:
			if value.Name == name && !declared[name] {
				used = true
				return false
			}
		}
		return true
	})
	return used
}

// usesLegacyRangeLoopVariables reports whether the nearest module still uses the pre-Go 1.22 range-loop capture semantics.
//
// Without module metadata the default-on rule stays silent instead of guessing, so the result is false when no go.mod version is found.
// unit is the file whose directory starts the go.mod search, and ctx supplies the scan root that ends it.
func usesLegacyRangeLoopVariables(unit parser.Unit, ctx Context) bool {
	major, minor, ok := nearestGoModVersion(unit, ctx)
	return ok && majorMinorLessThan(major, minor, 1, 22)
}

// nearestGoModVersion finds the nearest go.mod from the unit's directory up to the scan root and returns its go directive major/minor version.
//
// unit supplies the file's absolute path, and ctx supplies the scan root, which falls back to the file's own directory when ctx.Root is empty.
// It returns 0, 0 and false when unit has no absolute path or no readable go.mod sits within the root; otherwise parseGoDirective decides.
func nearestGoModVersion(unit parser.Unit, ctx Context) (int, int, bool) {
	if unit.File.AbsPath == "" {
		return 0, 0, false
	}
	fileDir, err := filepath.Abs(filepath.Dir(unit.File.AbsPath))
	if err != nil {
		return 0, 0, false
	}
	root := ctx.Root
	if root == "" {
		root = fileDir
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return 0, 0, false
	}
	for dir := fileDir; pathWithinOrEqual(dir, rootAbs); dir = filepath.Dir(dir) {
		data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		// The nearest go.mod decides even when its go line is missing or malformed; a parent module's go.mod is never consulted.
		if err == nil {
			return parseGoDirective(data)
		}
		// The search stops at the scan root, so a go.mod above that root never decides the finding.
		if dir == rootAbs || filepath.Dir(dir) == dir {
			break
		}
	}
	return 0, 0, false
}

// pathWithinOrEqual reports whether path is root or under root.
func pathWithinOrEqual(path string, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// parseGoDirective returns the major/minor version from the first go directive in a go.mod file.
//
// A module without that directive has implicit Go 1.16 semantics, so the rule treats it as legacy and can report captures.
// data is the go.mod content; a missing or unparseable version after go returns 0, 0 and false.
// A parseable go version returns its major/minor numbers and true; no go directive returns 1, 16 and true.
func parseGoDirective(data []byte) (int, int, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "go" {
			continue
		}
		if len(fields) < 2 {
			return 0, 0, false
		}
		return parseGoMajorMinor(fields[1])
	}
	return 1, 16, true
}

// parseGoMajorMinor parses Go directives such as 1.21, 1.22.0, or 1.25rc1.
//
// version is the directive's text; minor keeps only the leading digits of the second dot-separated part, so 25rc1 reads as 25.
// It returns major, minor and true, or 0, 0 and false when version has no dot, a non-numeric major part, or no leading minor digit.
func parseGoMajorMinor(version string) (int, int, bool) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minorText := ""
	for _, r := range parts[1] {
		if r < '0' || r > '9' {
			break
		}
		minorText += string(r)
	}
	if minorText == "" {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(minorText)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// majorMinorLessThan compares two Go major/minor versions, used here to decide whether a module predates Go 1.22 loop variables.
//
// major and minor are the version checked, and thresholdMajor and thresholdMinor the version it is compared against.
// It reports true only when the checked version is strictly older than the threshold, and false when the two are equal.
func majorMinorLessThan(major, minor, thresholdMajor, thresholdMinor int) bool {
	if major != thresholdMajor {
		return major < thresholdMajor
	}
	return minor < thresholdMinor
}
