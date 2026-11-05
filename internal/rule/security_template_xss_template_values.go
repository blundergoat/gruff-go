// Package rule defines gruff-go's rule registry and analysers.
//
// This file tracks parser-visible text/template vs html/template value origins for the template/XSS rule.
//
// Origins come only from this file's names and expressions, so a template returned by a call into another file stays untraced.
// A local template.Must(load()) is still classified by Must's own package, even when load builds the template in another file.
// Parameter bindings are not resolved, so a parameter named like a known package-level template variable takes that variable's origin.
package rule

import (
	"go/ast"
	"go/token"
)

// templateKind records which standard-library template package produced a value.
type templateKind int

const (
	// templateKindUnknown marks values the parser cannot tie to a template package.
	templateKindUnknown templateKind = iota
	// templateKindText marks values produced by text/template constructors.
	templateKindText
	// templateKindHTML marks values produced by html/template constructors.
	templateKindHTML
)

// templateValueKinds maps local or package variable names to their template origin.
type templateValueKinds map[string]templateKind

// templateExecuteReceiverKind reports which template package an Execute call's receiver traces to within the same parsed file.
//
// call is the Execute call to inspect; its selector receiver is traced by templateExprKind using pkgs and values.
// pkgs holds the local import names of text/template and html/template; values maps variable names to their known template origin.
// It returns templateKindText or templateKindHTML when traced, and templateKindUnknown for a non-selector call or an untraced receiver.
func templateExecuteReceiverKind(call *ast.CallExpr, pkgs templateXSSPackages, values templateValueKinds) templateKind {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return templateKindUnknown
	}
	return templateExprKind(selector.X, pkgs, values)
}

// collectFileTemplateValueKinds records package-level template variables, so a handler's page.Execute can trace a value built outside it.
//
// file is scanned for top-level var declarations only; pkgs holds the local import names of text/template and html/template.
// Declarations are read in source order, so a var aliasing one declared later stays unrecorded.
// It returns a non-nil map from variable name to template origin, empty when no package-level var traces to a template package.
func collectFileTemplateValueKinds(file *ast.File, pkgs templateXSSPackages) templateValueKinds {
	values := templateValueKinds{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			updateTemplateValueSpecKinds(values, valueSpec, pkgs)
		}
	}
	return values
}

// collectTemplateValueKinds records local names assigned from template constructors or methods, seeded with package-level values.
//
// body is walked twice without entering nested function literals; two passes settle simple aliasing such as page := base.
// pkgs holds the local import names of text/template and html/template.
// seed is copied, leaving the caller's map untouched; a name is dropped only when its paired right-hand expression has unknown origin.
//
// It returns the new map of names to template origins, empty when seed is empty and nothing in body traces to a template package.
func collectTemplateValueKinds(body *ast.BlockStmt, pkgs templateXSSPackages, seed templateValueKinds) templateValueKinds {
	values := cloneTemplateValueKinds(seed)
	for pass := 0; pass < 2; pass++ {
		ast.Inspect(body, func(node ast.Node) bool {
			// Assignments inside a nested func literal are skipped, so a template built in a closure stays untraced for this body.
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			switch stmt := node.(type) {
			case *ast.AssignStmt:
				for i, lhs := range stmt.Lhs {
					ident, ok := lhs.(*ast.Ident)
					// In t, err := tmpl.Parse(s) only t pairs with the call; err has no right-hand expression of its own and is skipped.
					if !ok || ident.Name == "_" || i >= len(stmt.Rhs) {
						continue
					}
					setTemplateValueKind(values, ident.Name, templateExprKind(stmt.Rhs[i], pkgs, values))
				}
			case *ast.ValueSpec:
				updateTemplateValueSpecKinds(values, stmt, pkgs)
			}
			return true
		})
	}
	return values
}

// cloneTemplateValueKinds copies package-level template origins into a function scope.
// It returns a new non-nil map with every entry of seed, which is left unchanged; the map is empty when seed is nil or empty.
func cloneTemplateValueKinds(seed templateValueKinds) templateValueKinds {
	values := templateValueKinds{}
	for name, kind := range seed {
		values[name] = kind
	}
	return values
}

// updateTemplateValueSpecKinds records template origins introduced by a var block.
//
// values is updated in place: each name in spec paired with a value expression is set to that expression's origin, or removed when unknown.
// Blank names and names without a value are skipped; pkgs holds the local import names of text/template and html/template.
func updateTemplateValueSpecKinds(values templateValueKinds, spec *ast.ValueSpec, pkgs templateXSSPackages) {
	for i, name := range spec.Names {
		if name.Name == "_" || i >= len(spec.Values) {
			continue
		}
		setTemplateValueKind(values, name.Name, templateExprKind(spec.Values[i], pkgs, values))
	}
}

// setTemplateValueKind stores a known template origin or clears stale evidence.
// values is modified in place: name maps to kind, or is deleted from values when kind is templateKindUnknown.
func setTemplateValueKind(values templateValueKinds, name string, kind templateKind) {
	if kind == templateKindUnknown {
		delete(values, name)
		return
	}
	values[name] = kind
}

// templateExprKind traces constructors, aliases, and template-returning methods.
//
// expr may be parenthesised; identifiers are looked up in values, and package calls are classified using pkgs.
// It returns the traced origin; a call to a method in templateMethodReturnsTemplate takes its receiver's origin.
// An identifier missing from values, an unrecognised call, or any other expression gives templateKindUnknown.
func templateExprKind(expr ast.Expr, pkgs templateXSSPackages, values templateValueKinds) templateKind {
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return templateExprKind(e.X, pkgs, values)
	case *ast.Ident:
		return values[e.Name]
	case *ast.CallExpr:
		if kind := templatePackageCallKind(e, pkgs); kind != templateKindUnknown {
			return kind
		}
		selector, ok := e.Fun.(*ast.SelectorExpr)
		if !ok || !templateMethodReturnsTemplate(selector.Sel.Name) {
			return templateKindUnknown
		}
		return templateExprKind(selector.X, pkgs, values)
	default:
		return templateKindUnknown
	}
}

// templatePackageCallKind classifies direct text/template or html/template calls.
//
// call must name New, Must, ParseFS, ParseFiles, or ParseGlob on a package identifier; pkgs holds the text/template and html/template imports.
// It returns templateKindText or templateKindHTML for the matching import, checking text/template first, and templateKindUnknown otherwise.
func templatePackageCallKind(call *ast.CallExpr, pkgs templateXSSPackages) templateKind {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !templatePackageFunctionReturnsTemplate(selector.Sel.Name) {
		return templateKindUnknown
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok {
		return templateKindUnknown
	}
	switch {
	case pkgs.textTemplate[receiver.Name]:
		return templateKindText
	case pkgs.htmlTemplate[receiver.Name]:
		return templateKindHTML
	default:
		return templateKindUnknown
	}
}

// templatePackageFunctionReturnsTemplate reports package functions that return templates.
// name is the selected function name; only New, Must, ParseFS, ParseFiles, and ParseGlob report true.
func templatePackageFunctionReturnsTemplate(name string) bool {
	switch name {
	case "New", "Must", "ParseFS", "ParseFiles", "ParseGlob":
		return true
	default:
		return false
	}
}

// templateMethodReturnsTemplate reports template methods that keep a template receiver.
// name is the method name; only Clone, Delims, Funcs, Lookup, New, Option, and Parse report true.
func templateMethodReturnsTemplate(name string) bool {
	switch name {
	// ParseFiles, ParseGlob, and ParseFS are not listed, so a value built as template.New(name).ParseFiles(path) stays untraced.
	case "Clone", "Delims", "Funcs", "Lookup", "New", "Option", "Parse":
		return true
	default:
		return false
	}
}
