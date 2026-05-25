// Package rule defines gruff-go's rule registry and analysers.
// This file implements parser-only maintainability checks for error handling and production placeholders.
package rule

import (
	"go/ast"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// IgnoredErrorRule flags direct assignments of error-looking values to the blank identifier.
type IgnoredErrorRule struct{}

// Definition declares the maintainability.ignored-error rule for explicit ignored error values.
func (IgnoredErrorRule) Definition() Definition {
	return Definition{
		ID:             "maintainability.ignored-error",
		Title:          "Ignored error",
		Description:    "Flags error-looking values that are assigned directly to the blank identifier.",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"errors"},
		Remediation:    "Handle the error, return it to the caller, or document why ignoring it is safe.",
	}
}

// AnalyzeUnit emits findings for direct `_ = err`-style assignments. It stays
// conservative because parser-only analysis cannot prove arbitrary call return
// types without type information.
func (IgnoredErrorRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	errorsPackages := packageImportNames(unit.AST, "errors", "errors")
	fmtPackages := packageImportNames(unit.AST, "fmt", "fmt")
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for index, lhs := range assign.Lhs {
			if !isBlankIdent(lhs) {
				continue
			}
			expr, evidence, ok := ignoredErrorEvidence(assign.Rhs[index], errorsPackages, fmtPackages)
			if !ok {
				continue
			}
			position := unit.FileSet.Position(lhs.Pos())
			findings = append(findings, finding.Finding{
				Message:  "error value is assigned to the blank identifier",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Metadata: map[string]any{
					"expression": formatExpr(expr),
					"evidence":   evidence,
				},
			})
		}
		return true
	})
	return findings
}

// ContextTODOProductionRule flags context.TODO calls in production code.
type ContextTODOProductionRule struct{}

// Definition declares the maintainability.context-todo-production rule for TODO contexts outside tests and examples.
func (ContextTODOProductionRule) Definition() Definition {
	return Definition{
		ID:             "maintainability.context-todo-production",
		Title:          "Context TODO in production",
		Description:    "Flags context.TODO calls in production files where cancellation ownership should be explicit.",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"context"},
		Remediation:    "Accept a caller-provided context or use a documented bootstrap context where cancellation is intentionally unavailable.",
	}
}

// AnalyzeUnit emits findings for context.TODO() calls outside test/example paths.
func (ContextTODOProductionRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	contextPackages := packageImportNames(unit.AST, "context", "context")
	if len(contextPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !selectorCallMatches(call, contextPackages, "TODO") {
			return true
		}
		position := unit.FileSet.Position(call.Pos())
		findings = append(findings, finding.Finding{
			Message:  "context.TODO used in production code",
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Metadata: map[string]any{"call": formatExpr(call.Fun)},
		})
		return true
	})
	return findings
}

// ProductionPanicRule flags direct literal panics outside tests and bootstrap code.
type ProductionPanicRule struct{}

// Definition declares the maintainability.production-panic rule for concrete production panic sites.
func (ProductionPanicRule) Definition() Definition {
	return Definition{
		ID:             "maintainability.production-panic",
		Title:          "Production panic",
		Description:    "Flags direct literal panic calls in non-test, non-main production code.",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"errors"},
		Remediation:    "Return an error or fail during command/bootstrap setup instead of panicking from reusable production code.",
	}
}

// AnalyzeUnit emits findings for panic calls with literal messages in reusable production code.
func (ProductionPanicRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) || unit.AST.Name.Name == "main" {
		return nil
	}
	if isBootstrapPath(unit.File.Path) {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || productionPanicFunctionExempt(fn.Name.Name) {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok || !isDirectPanicCall(call) || !panicHasLiteralEvidence(call) {
				return true
			}
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "production code calls panic with a literal message",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   functionName(fn),
			})
			return true
		})
	}
	return findings
}

// ignoredErrorEvidence classifies the small set of expression shapes where an
// ignored value is clearly an error without resolving types.
func ignoredErrorEvidence(expr ast.Expr, errorsPackages, fmtPackages map[string]bool) (ast.Expr, string, bool) {
	switch value := expr.(type) {
	case *ast.Ident:
		if isErrorLikeName(value.Name) {
			return expr, "identifier", true
		}
	case *ast.SelectorExpr:
		if isErrorLikeName(value.Sel.Name) {
			return expr, "selector", true
		}
	case *ast.CallExpr:
		if isErrorConstructorCall(value, errorsPackages, fmtPackages) {
			return expr, "error-constructor", true
		}
	}
	return nil, "", false
}

// isBlankIdent reports whether expr is the blank identifier.
func isBlankIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "_"
}

// isErrorLikeName recognises conventional error variable and field names.
func isErrorLikeName(name string) bool {
	lower := strings.ToLower(name)
	return lower == "err" || lower == "error" || strings.HasSuffix(lower, "err") || strings.HasSuffix(lower, "error")
}

// isErrorConstructorCall recognises standard error construction calls whose
// returned value is immediately thrown away.
func isErrorConstructorCall(call *ast.CallExpr, errorsPackages, fmtPackages map[string]bool) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	return selector.Sel.Name == "New" && errorsPackages[receiver.Name] || selector.Sel.Name == "Errorf" && fmtPackages[receiver.Name]
}

// isProductionCodePath reports whether a file is neither a test nor obvious example fixture path.
func isProductionCodePath(path string) bool {
	if isGoTestFile(path) {
		return false
	}
	clean := strings.ReplaceAll(path, "\\", "/")
	for _, marker := range []string{"/testdata/", "/examples/", "/example/"} {
		if strings.Contains(clean, marker) {
			return false
		}
	}
	return !strings.HasPrefix(clean, "testdata/") && !strings.HasPrefix(clean, "examples/") && !strings.HasPrefix(clean, "example/")
}

// isBootstrapPath exempts command/bootstrap entry surfaces where panic is often
// used for impossible setup invariants rather than request-time production flow.
func isBootstrapPath(path string) bool {
	clean := strings.ReplaceAll(path, "\\", "/")
	return strings.HasPrefix(clean, "cmd/") || strings.Contains(clean, "/cmd/")
}

// productionPanicFunctionExempt recognises functions whose names conventionally document panic-on-impossible-invariant behavior.
func productionPanicFunctionExempt(name string) bool {
	return name == "init" || name == "main" || name == "Defaults" || strings.HasPrefix(name, "Must")
}

// isDirectPanicCall reports whether call is the predeclared panic function.
func isDirectPanicCall(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "panic"
}

// panicHasLiteralEvidence limits the rule to panics that clearly embed a
// production crash message instead of internal impossible-error panics.
func panicHasLiteralEvidence(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	if _, ok := stringLiteral(call.Args[0]); ok {
		return true
	}
	nested, ok := call.Args[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	name := callFunctionName(nested)
	return name == "Sprintf" || name == "Errorf" || name == "New"
}
