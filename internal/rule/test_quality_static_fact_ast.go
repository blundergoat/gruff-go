// Package rule defines gruff-go's rule registry and analysers.
// This file holds AST helper routines for static-analysis-redundant test candidates.
package rule

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"strconv"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// reflectedCompositeTypeName extracts the named type from reflect.TypeOf(T{}) expressions.
func reflectedCompositeTypeName(expr ast.Expr, reflectPackages map[string]bool) (string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok || !isReflectTypeOfCall(call, reflectPackages) || len(call.Args) != 1 {
		return "", false
	}
	literal, ok := call.Args[0].(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	ident, ok := literal.Type.(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name, true
}

// isReflectTypeOfCall reports whether a call expression invokes the standard reflect.TypeOf helper.
func isReflectTypeOfCall(call *ast.CallExpr, reflectPackages map[string]bool) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		pkg, ok := fun.X.(*ast.Ident)
		return ok && reflectPackages[pkg.Name] && fun.Sel.Name == "TypeOf"
	case *ast.Ident:
		return reflectPackages["."] && fun.Name == "TypeOf"
	default:
		return false
	}
}

// isReflectKindSelector reports whether an expression names a standard reflect.Kind selector.
func isReflectKindSelector(expr ast.Expr, reflectPackages map[string]bool, kind string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != kind {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && reflectPackages[pkg.Name]
}

// reflectPackageNames returns local import aliases for the standard reflect package.
func reflectPackageNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, imported := range file.Imports {
		if imported.Path == nil {
			continue
		}
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil || path != "reflect" {
			continue
		}
		name := "reflect"
		if imported.Name != nil {
			name = imported.Name.Name
		}
		if name != "_" {
			names[name] = true
		}
	}
	return names
}

// stringLiteralValue extracts an unquoted string token from an AST basic literal expression.
func stringLiteralValue(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

// intLiteralValue extracts a base-10 integer from an AST literal expression.
func intLiteralValue(expr ast.Expr) (int, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	value, err := strconv.Atoi(lit.Value)
	return value, err == nil
}

// finding converts a static fact candidate into scanner output with assertion and source-proof metadata.
func (c staticFactCandidate) finding(path string) finding.Finding {
	return finding.Finding{
		Message: fmt.Sprintf(
			"%s contains a static-analysis-redundant candidate: %s",
			c.testFunction,
			c.staticFact,
		),
		File:       path,
		Location:   &c.location,
		Symbol:     c.testFunction,
		Confidence: c.confidence,
		Metadata: map[string]any{
			"assertion":        c.assertion,
			"staticFact":       c.staticFact,
			"staticFactFile":   c.staticFactFile,
			"staticFactLine":   c.staticFactLine,
			"confidenceReason": c.confidenceWhy,
		},
	}
}

// locationForNode returns scanner location data for a node's starting token position.
func locationForNode(unit parser.Unit, node ast.Node) finding.Location {
	position := unit.FileSet.Position(node.Pos())
	return finding.Location{Line: position.Line, Column: position.Column}
}

// renderNode returns stable Go source text for a condition or expression node.
func renderNode(fset *token.FileSet, node any) string {
	var out bytes.Buffer
	if err := printer.Fprint(&out, fset, node); err != nil {
		return ""
	}
	return out.String()
}
