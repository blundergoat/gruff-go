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
		DefaultEnabled: false,
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
		DefaultEnabled: false,
		Tags:           []string{"opt-in", "tests"},
		Remediation:    "Add an assertion or document why the test cannot fail.",
	}
}

func (NoFailurePathTestRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
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
			continue
		}
		if hasFailureCall(fn.Body) {
			continue
		}
		position := unit.FileSet.Position(fn.Name.NamePos)
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("test %s has no path that calls t.Error/t.Fatal/t.Fail/Errorf/Fatalf/FailNow", fn.Name.Name),
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

func hasFailureCall(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
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
