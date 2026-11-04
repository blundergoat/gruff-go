// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds AST helper routines for static-analysis-redundant test candidates.
// They spot reflect.TypeOf calls and reflect Kind constants, read string and integer literals, and build the finding reported on a test function.
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
//
// The expr must call TypeOf through a qualifier in reflectPackages or its dot import, with one composite literal whose type is a bare name.
// It returns that type name and true, or an empty string and false for any other expression, including qualified or generic types.
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
// A selector call matches when its package name is in reflectPackages and the selector is TypeOf; a bare TypeOf call needs a dot import there.
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
//
// It is true only when expr is a selector whose package name is in reflectPackages and whose selected name equals kind.
// A bare Kind constant under a dot import of reflect never matches, though isReflectTypeOfCall accepts a bare TypeOf there.
func isReflectKindSelector(expr ast.Expr, reflectPackages map[string]bool, kind string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != kind {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && reflectPackages[pkg.Name]
}

// reflectPackageNames returns local import aliases for the standard reflect package.
//
// It checks each import of file whose path is reflect and adds its local name: reflect when unaliased, otherwise the alias or a dot.
// Blank imports are skipped, and the map is empty, not nil, when file has no usable reflect import.
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
// It returns the unquoted value and true when expr is a string literal that strconv.Unquote accepts, or an empty string and false otherwise.
func stringLiteralValue(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

// intLiteralValue extracts a base-10 integer from an AST literal expression.
//
// It returns the value and true when expr is an integer literal that strconv.Atoi parses, or zero and false when expr is not an integer literal.
// Literals with 0x, 0o or 0b prefixes or underscores give false, and a leading-zero literal such as 077 is read as decimal 77.
func intLiteralValue(expr ast.Expr) (int, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	value, err := strconv.Atoi(lit.Value)
	return value, err == nil
}

// finding converts a static fact candidate into scanner output with assertion and source-proof metadata.
//
// It returns a finding whose File is path, whose Symbol is the test function, and whose message names that function and the static fact.
// It copies the candidate's location and confidence; the rule ID and pillar are left unset.
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
// It resolves the start of node through the FileSet of unit and keeps only the line and column.
func locationForNode(unit parser.Unit, node ast.Node) finding.Location {
	position := unit.FileSet.Position(node.Pos())
	return finding.Location{Line: position.Line, Column: position.Column}
}

// renderNode returns stable Go source text for a condition or expression node.
// It prints node with go/printer using the positions in fset, and returns an empty string when printing fails.
func renderNode(fset *token.FileSet, node any) string {
	var out bytes.Buffer
	if err := printer.Fprint(&out, fset, node); err != nil {
		return ""
	}
	return out.String()
}
