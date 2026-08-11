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
		// Only a redirect status on the same response binding activates Location.
		if !isSelector || !isIdentifier || selector.Sel.Name != "WriteHeader" || !identifiersShareBinding(writer, responseWriter) {
			return true
		}
		// Mutually exclusive branches cannot combine a Location value with a
		// redirect status on any execution path.
		if !nodesCanShareControlPath(functionBody, locationCall, statusCall) {
			return true
		}
		found = isRedirectHTTPStatus(statusCall.Args[0], httpPackageAliases)
		return !found
	})
	return found
}

// locationHeaderResponseWriter returns the lexical `w` from w.Header().Set(...).
// The caller uses its object identity so a shadowed writer cannot activate Location.
func locationHeaderResponseWriter(locationCall *ast.CallExpr) (*ast.Ident, bool) {
	setSelector, ok := locationCall.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	headerCall, ok := setSelector.X.(*ast.CallExpr)
	if !ok || len(headerCall.Args) != 0 {
		return nil, false
	}
	headerSelector, ok := headerCall.Fun.(*ast.SelectorExpr)
	if !ok || headerSelector.Sel.Name != "Header" {
		return nil, false
	}
	writer, ok := headerSelector.X.(*ast.Ident)
	if !ok {
		return nil, false
	}
	return writer, true
}

// identifiersShareBinding reports whether two receiver names resolve to the
// same lexical object. Name fallback preserves scans of unresolved partial code.
func identifiersShareBinding(leftIdentifier, rightIdentifier *ast.Ident) bool {
	// Missing receiver syntax cannot describe one response writer.
	if leftIdentifier == nil || rightIdentifier == nil {
		return false
	}
	// When either side resolves, both must resolve to the exact same declaration.
	if leftIdentifier.Obj != nil || rightIdentifier.Obj != nil {
		return leftIdentifier.Obj != nil && leftIdentifier.Obj == rightIdentifier.Obj
	}
	return leftIdentifier.Name == rightIdentifier.Name
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
