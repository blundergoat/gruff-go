// Package rule defines gruff-go's rule registry and analysers.
// This file implements additional parser-only test-quality checks.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// HelperMissingTHelperRule flags test helper functions that fail tests without marking themselves as helpers.
type HelperMissingTHelperRule struct{}

// Definition declares the test-quality.helper-missing-t-helper rule for helper diagnostics.
func (HelperMissingTHelperRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.helper-missing-t-helper",
		Title:          "Test helper missing t.Helper",
		Description:    "Flags non-test helper functions that accept testing.TB, *testing.T, or *testing.B and can fail the test but never call Helper.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"tests"},
		Remediation:    "Call t.Helper() at the start of the helper so failures report the caller's line.",
	}
}

// AnalyzeUnit emits findings for assertion-style helpers that omit t.Helper().
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
		if len(receivers) == 0 || helperCallPresent(fn.Body, receivers) {
			continue
		}
		if !blockHasFailureCall(fn.Body, testingPackages, assertionPackages, receivers) {
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

// ParallelRangeCaptureRule flags parallel subtests that close over range variables.
type ParallelRangeCaptureRule struct{}

// Definition declares the test-quality.parallel-range-capture rule for table-test closure capture.
func (ParallelRangeCaptureRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.parallel-range-capture",
		Title:          "Parallel subtest captures range variable",
		Description:    "Flags t.Parallel subtests that close over range variables without an explicit shadow copy in modules using pre-Go 1.22 loop-variable semantics.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"tests"},
		Remediation:    "Create an explicit shadow copy such as `tc := tc` before starting the parallel subtest, or update the module to Go 1.22+ loop-variable semantics.",
	}
}

// AnalyzeUnit emits findings for table-driven parallel subtests that capture range variables.
func (ParallelRangeCaptureRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !strings.HasSuffix(unit.File.Path, "_test.go") {
		return nil
	}
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
func helperCallPresent(body *ast.BlockStmt, receivers map[string]bool) bool {
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
		receiver, ok := selector.X.(*ast.Ident)
		found = ok && receivers[receiver.Name]
		return !found
	})
	return found
}

// parallelRangeCaptureFindings finds t.Run closures with t.Parallel that use unshadowed range variables.
func parallelRangeCaptureFindings(unit parser.Unit, body *ast.BlockStmt, testingPackages map[string]bool) []finding.Finding {
	findings := []finding.Finding{}
	ast.Inspect(body, func(node ast.Node) bool {
		rangeStmt, ok := node.(*ast.RangeStmt)
		if !ok {
			return true
		}
		rangeVars := rangeVariableNames(rangeStmt)
		if len(rangeVars) == 0 {
			return true
		}
		findings = append(findings, parallelCapturesInRange(unit, rangeStmt, rangeVars, testingPackages)...)
		return true
	})
	return findings
}

// parallelCapturesInRange checks one range body for unsafe parallel subtest captures.
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

// rangeVariableNames returns non-blank key/value identifiers declared by a range statement.
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

// recordRangeShadow recognises `tc := tc`-style copies before t.Run.
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
func isSubtestRunCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Run"
}

// subtestFuncLiteral returns the function literal argument passed to t.Run.
func subtestFuncLiteral(call *ast.CallExpr) *ast.FuncLit {
	for _, arg := range call.Args {
		if lit, ok := arg.(*ast.FuncLit); ok {
			return lit
		}
	}
	return nil
}

// funcLitCallsParallel reports whether the subtest closure calls t.Parallel.
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

// usesLegacyRangeLoopVariables reports whether the nearest module still uses
// the pre-Go 1.22 range-loop capture semantics. Without module metadata the
// default-on rule stays silent instead of guessing.
func usesLegacyRangeLoopVariables(unit parser.Unit, ctx Context) bool {
	major, minor, ok := nearestGoModVersion(unit, ctx)
	return ok && majorMinorLessThan(major, minor, 1, 22)
}

// nearestGoModVersion finds the nearest go.mod from the unit's directory up to
// the scan root and returns its `go` directive major/minor version.
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
		if err == nil {
			return parseGoDirective(data)
		}
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

// parseGoDirective returns the major/minor version from the first `go` directive.
func parseGoDirective(data []byte) (int, int, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "go" {
			continue
		}
		return parseGoMajorMinor(fields[1])
	}
	return 0, 0, false
}

// parseGoMajorMinor parses Go directives such as 1.21, 1.22.0, or 1.25rc1.
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

// majorMinorLessThan compares two Go major/minor versions.
func majorMinorLessThan(major, minor, thresholdMajor, thresholdMinor int) bool {
	if major != thresholdMajor {
		return major < thresholdMajor
	}
	return minor < thresholdMinor
}
