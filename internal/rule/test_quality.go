package rule

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

type EmptyTestRule struct{}

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

type NoFailurePathTestRule struct{}

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
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || !receivers[receiver.Name] {
			return true
		}
		switch selector.Sel.Name {
		case "Error", "Errorf", "Fatal", "Fatalf", "Fail", "FailNow":
			found = true
		case "Helper", "Skip", "Skipf", "SkipNow", "Log", "Logf", "Cleanup", "Parallel", "Name", "Run", "Setenv":
			// Known non-failing helpers — keep scanning siblings.
		}
		return !found
	})
	return found
}

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

func testingReceiverNames(fn *ast.FuncDecl, testingPackages map[string]bool) map[string]bool {
	receivers := map[string]bool{}
	if fn.Type == nil || fn.Type.Params == nil {
		return receivers
	}
	for _, field := range fn.Type.Params.List {
		if !isTestingHandleType(field.Type, testingPackages) {
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

func isTestingHandleType(expr ast.Expr, testingPackages map[string]bool) bool {
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
