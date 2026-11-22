// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds parser-only maintainability checks for ignored errors and context.TODO in production code.
// They read syntax only, so a finding marks a likely shape rather than a type-checked fact.
package rule

import (
	"go/ast"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// IgnoredErrorRule flags direct assignments of error-looking values to the blank identifier, as rule maintainability.ignored-error.
//
// A value counts by its name, such as err or parseError, or as an errors.New or fmt.Errorf call; types are never resolved.
type IgnoredErrorRule struct{}

// Definition declares the maintainability.ignored-error rule for explicit ignored error values.
// It returns the same populated Definition on every call: maintainability pillar, advisory severity, medium confidence, enabled by default.
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

// AnalyzeUnit emits findings for direct _ = err style assignments in one parsed file.
//
// It stays conservative because parser-only analysis cannot prove arbitrary call return types without type information.
// unit is that file; assignments with unequal left and right counts are skipped, so a blank from a multi-value call is never reported.
//
// It returns one finding per error-looking blank, recording the expression and evidence kind, and nil when unit has no AST or FileSet.
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

// ContextTODOProductionRule flags context.TODO calls in production code, as rule maintainability.context-todo-production.
//
// Test files and testdata or example paths are exempt; elsewhere cancellation ownership should be explicit.
type ContextTODOProductionRule struct{}

// Definition declares the maintainability.context-todo-production rule for TODO contexts outside tests and examples.
// It returns the same populated Definition on every call: maintainability pillar, advisory severity, high confidence, enabled by default.
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

// AnalyzeUnit emits findings for context.TODO() calls outside test and example paths.
//
// unit is one parsed file; only calls through its own context import names count, and each finding records the rendered callee.
// It returns one finding per such call, nil for a non-production path, a missing AST or FileSet, or no usable context import.
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

// ignoredErrorEvidence classifies an ignored value as error-like by its name or constructor call, without resolving types.
//
// expr is the value assigned to a blank; errorsPackages and fmtPackages hold the import names under which errors.New and fmt.Errorf count.
// It returns expr, an evidence kind of identifier, selector or error-constructor, and true; any other shape gives nil, an empty string and false.
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
// It reports true when the lower-cased name is err or error or ends in err or error, such as myErr or parseError, and false otherwise.
func isErrorLikeName(name string) bool {
	lower := strings.ToLower(name)
	return lower == "err" || lower == "error" || strings.HasSuffix(lower, "err") || strings.HasSuffix(lower, "error")
}

// isErrorConstructorCall recognises an errors.New or fmt.Errorf call by the import names the file uses for errors and fmt.
//
// call must be pkg.New with pkg in errorsPackages or pkg.Errorf with pkg in fmtPackages; any other callee, dot imports included, gives false.
// It reports true only for that call shape; the discard comes from the caller, which reads the right side of a blank assignment.
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

// isProductionCodePath reports whether path is neither a Go test file nor under a testdata, examples or example directory.
// A false result keeps rules such as context-todo-production silent on that file.
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

// isBootstrapPath exempts command entry files under cmd from the runtime-pitfall rules.
//
// Code there often uses panic for impossible setup invariants rather than request-time production flow.
// It reports true when path, after backslashes become slashes, starts with cmd/ or contains /cmd/, and false otherwise.
func isBootstrapPath(path string) bool {
	clean := strings.ReplaceAll(path, "\\", "/")
	return strings.HasPrefix(clean, "cmd/") || strings.Contains(clean, "/cmd/")
}

// isDirectPanicCall reports whether call has the unqualified callee name panic, without resolving shadowing.
// A local function named panic is therefore treated as the builtin, and its calls can be reported.
func isDirectPanicCall(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "panic"
}
