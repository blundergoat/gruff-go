// Package rule keeps HTTP redirect-status recognition separate from request
// taint analysis so each security policy remains small enough to review.
package rule

import (
	"go/ast"
	"go/token"
	"strconv"
)

// locationHeaderHasRedirectStatus ties a Location write to a later redirect
// status on the same response writer. Dynamic status expressions stay out of
// this candidate rule because their redirect behavior cannot be proven here.
func locationHeaderHasRedirectStatus(functionBody *ast.BlockStmt, locationCall *ast.CallExpr, httpPackageAliases map[string]bool) bool {
	responseWriter, ok := locationHeaderResponseWriter(locationCall)
	if !ok {
		return false
	}
	found := false
	ast.Inspect(functionBody, func(node ast.Node) bool {
		if found {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		statusCall, isCall := node.(*ast.CallExpr)
		if !isCall || statusCall.Pos() <= locationCall.Pos() || len(statusCall.Args) != 1 {
			return true
		}
		selector, isSelector := statusCall.Fun.(*ast.SelectorExpr)
		writer, isIdentifier := selectorReceiverIdent(selector)
		if !isSelector || !isIdentifier || selector.Sel.Name != "WriteHeader" || writer.Name != responseWriter {
			return true
		}
		found = isRedirectHTTPStatus(statusCall.Args[0], httpPackageAliases)
		return !found
	})
	return found
}

// locationHeaderResponseWriter returns the `w` from w.Header().Set(...).
func locationHeaderResponseWriter(locationCall *ast.CallExpr) (string, bool) {
	setSelector, ok := locationCall.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	headerCall, ok := setSelector.X.(*ast.CallExpr)
	if !ok || len(headerCall.Args) != 0 {
		return "", false
	}
	headerSelector, ok := headerCall.Fun.(*ast.SelectorExpr)
	if !ok || headerSelector.Sel.Name != "Header" {
		return "", false
	}
	writer, ok := headerSelector.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return writer.Name, true
}

// selectorReceiverIdent safely returns an identifier receiver for method calls.
func selectorReceiverIdent(selector *ast.SelectorExpr) (*ast.Ident, bool) {
	if selector == nil {
		return nil, false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return receiver, ok
}

// isRedirectHTTPStatus recognises the net/http statuses clients follow as
// redirects, accepting either their integer or package-constant spelling.
func isRedirectHTTPStatus(statusExpression ast.Expr, httpPackageAliases map[string]bool) bool {
	if literal, ok := statusExpression.(*ast.BasicLit); ok && literal.Kind == token.INT {
		statusCode, err := strconv.Atoi(literal.Value)
		if err == nil {
			switch statusCode {
			case 301, 302, 303, 307, 308:
				return true
			}
		}
		return false
	}
	selector, ok := statusExpression.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	packageIdentifier, ok := selector.X.(*ast.Ident)
	if !ok || !httpPackageAliases[packageIdentifier.Name] {
		return false
	}
	switch selector.Sel.Name {
	case "StatusMovedPermanently", "StatusFound", "StatusSeeOther", "StatusTemporaryRedirect", "StatusPermanentRedirect":
		return true
	default:
		return false
	}
}
