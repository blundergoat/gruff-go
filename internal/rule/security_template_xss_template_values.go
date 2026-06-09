// Package rule defines gruff-go's rule registry and analysers.
// This file tracks parser-visible text/template vs html/template value origins
// for the template/XSS rule.
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

// templateExecuteReceiverKind reports whether an Execute receiver can be traced
// to text/template or html/template within the same parsed file.
func templateExecuteReceiverKind(call *ast.CallExpr, pkgs templateXSSPackages, values templateValueKinds) templateKind {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return templateKindUnknown
	}
	return templateExprKind(selector.X, pkgs, values)
}

// collectFileTemplateValueKinds records package-level template variables so
// handler functions can recognise `page.Execute(...)` values built outside the
// function body.
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

// collectTemplateValueKinds records local names assigned from template
// constructors/methods, seeded with package-level values. Two passes settle simple
// aliasing such as `page := base`.
func collectTemplateValueKinds(body *ast.BlockStmt, pkgs templateXSSPackages, seed templateValueKinds) templateValueKinds {
	values := cloneTemplateValueKinds(seed)
	for pass := 0; pass < 2; pass++ {
		ast.Inspect(body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			switch stmt := node.(type) {
			case *ast.AssignStmt:
				for i, lhs := range stmt.Lhs {
					ident, ok := lhs.(*ast.Ident)
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
func cloneTemplateValueKinds(seed templateValueKinds) templateValueKinds {
	values := templateValueKinds{}
	for name, kind := range seed {
		values[name] = kind
	}
	return values
}

// updateTemplateValueSpecKinds records template origins introduced by a var block.
func updateTemplateValueSpecKinds(values templateValueKinds, spec *ast.ValueSpec, pkgs templateXSSPackages) {
	for i, name := range spec.Names {
		if name.Name == "_" || i >= len(spec.Values) {
			continue
		}
		setTemplateValueKind(values, name.Name, templateExprKind(spec.Values[i], pkgs, values))
	}
}

// setTemplateValueKind stores a known template origin or clears stale evidence.
func setTemplateValueKind(values templateValueKinds, name string, kind templateKind) {
	if kind == templateKindUnknown {
		delete(values, name)
		return
	}
	values[name] = kind
}

// templateExprKind traces constructors, aliases, and template-returning methods.
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
func templatePackageFunctionReturnsTemplate(name string) bool {
	switch name {
	case "New", "Must", "ParseFS", "ParseFiles", "ParseGlob":
		return true
	default:
		return false
	}
}

// templateMethodReturnsTemplate reports template methods that keep a template receiver.
func templateMethodReturnsTemplate(name string) bool {
	switch name {
	case "Clone", "Delims", "Funcs", "Lookup", "New", "Option", "Parse":
		return true
	default:
		return false
	}
}
