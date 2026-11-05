// Package rule keeps HTTP redirect-status recognition separate from request taint analysis so each security policy remains small enough to review.
//
// A Location header write is paired with a redirect only when the same response writer may later send a redirect status.
// A recognised non-redirect status, or one in another branch of the same if, switch or select, cannot qualify the header; a later status still can.
package rule

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

// locationHeaderHasRedirectStatus ties a Location write to a later redirect status on the same response writer.
//
// A dynamic status expression counts as a possible redirect, because its redirect behavior cannot be ruled out here.
// functionBody is searched, outside nested function literals, for a one-argument WriteHeader call after locationCall on the same writer.
// httpPackageAliases is passed to statusCanRedirect so net/http Status constants can be read by name.
//
// It reports true once such a call and locationCall sit in no different branches of one if, switch or select, and its status can redirect.
// Switch clauses joined by fallthrough still count as different branches, so such a redirect is missed.
// The result is false when locationCall is not a method call on an identifier's Header() result, or when no such call qualifies.
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
		// A WriteHeader inside a closure, such as a deferred func literal, is never paired with this Location write.
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		statusCall, isCall := node.(*ast.CallExpr)
		if !isCall || statusCall.Pos() <= locationCall.Pos() || len(statusCall.Args) != 1 {
			return true
		}
		selector, isSelector := statusCall.Fun.(*ast.SelectorExpr)
		writer, isIdentifier := selectorReceiverIdent(selector)
		// A redirect or unresolved status counts only from WriteHeader on the same response binding, so a shadowed or different writer is ignored.
		if !isSelector || !isIdentifier || selector.Sel.Name != "WriteHeader" || !identifiersShareBinding(writer, responseWriter) {
			return true
		}
		// Calls in different branches of one if, switch or select are never paired, even when switch fallthrough would run both.
		if !nodesCanShareControlPath(functionBody, locationCall, statusCall) {
			return true
		}
		found = statusCanRedirect(statusCall.Args[0], httpPackageAliases)
		return !found
	})
	return found
}

// locationHeaderResponseWriter returns the lexical w from w.Header().Set(...).
//
// The caller uses its object identity so a shadowed writer cannot activate Location.
// The bool is false, with a nil identifier, unless locationCall calls a method on the result of a no-argument Header() call on a plain identifier.
// A writer reached through a field, such as s.w.Header().Set, gives false, so that Location write is never paired with a status.
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

// identifiersShareBinding reports whether two receiver names resolve to the same lexical object.
//
// Name fallback preserves scans of unresolved partial code.
// It is false when leftIdentifier or rightIdentifier is nil, or when only one resolves; with neither resolved it compares their names.
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
//
// A nil selector, such as one left by a failed type assertion, yields a nil identifier and false.
// Otherwise the bool is true exactly when selector.X is an identifier, and that identifier is returned.
func selectorReceiverIdent(selector *ast.SelectorExpr) (*ast.Ident, bool) {
	if selector == nil {
		return nil, false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return receiver, ok
}

// statusCanRedirect reports whether a WriteHeader argument can send the browser somewhere else.
//
// Integer literals are parsed as decimal and net/http Status constants are matched by name.
// A recognised non-redirect such as 200 gives false here, though another WriteHeader may still qualify the Location header.
// Everything else, such as a variable, a helper call or another package's constant, stays a redirect candidate.
//
// A status variable stays unresolved, so a handler that stores http.StatusFound in a variable before WriteHeader still counts as a candidate.
// An unreported open redirect costs more than one extra finding on a response whose status this parser-only rule cannot read.
//
// statusExpression is the WriteHeader argument; httpPackageAliases decides, through isImportedPackageIdentifier, which selectors count as net/http.
// An integer literal that strconv.Atoi cannot parse, such as a hex or underscored one, also stays a redirect candidate.
// A leading-zero octal literal is misread as decimal, so 0455, which is 301, is not a candidate, and 0301, which is 193, is.
func statusCanRedirect(statusExpression ast.Expr, httpPackageAliases map[string]bool) bool {
	if literal, isLiteral := statusExpression.(*ast.BasicLit); isLiteral && literal.Kind == token.INT {
		statusCode, err := strconv.Atoi(literal.Value)
		// An unreadable literal leaves the status unknown rather than settled.
		if err != nil {
			return true
		}
		return isRedirectStatusCode(statusCode)
	}
	selector, isSelector := statusExpression.(*ast.SelectorExpr)
	// A bare identifier or call carries a status this rule cannot resolve.
	if !isSelector {
		return true
	}
	packageIdentifier, isIdentifier := selector.X.(*ast.Ident)
	// Only net/http's own constants are resolvable by name here.
	if !isIdentifier || !isImportedPackageIdentifier(packageIdentifier, httpPackageAliases) {
		return true
	}
	// A net/http selector that is not a Status constant says nothing about the
	// response code, so it stays unresolved rather than counting as non-redirect.
	if !strings.HasPrefix(selector.Sel.Name, "Status") {
		return true
	}
	return isRedirectStatusConstant(selector.Sel.Name)
}

// isRedirectStatusCode lists the numeric statuses clients follow as redirects.
// It reports true when statusCode is 301, 302, 303, 307 or 308, and false for any other code, including 300 and 304.
func isRedirectStatusCode(statusCode int) bool {
	switch statusCode {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

// isRedirectStatusConstant lists the net/http spellings of the statuses isRedirectStatusCode accepts.
//
// It reports true when constantName is StatusMovedPermanently, StatusFound, StatusSeeOther, StatusTemporaryRedirect or StatusPermanentRedirect.
// Any other name, such as StatusMultipleChoices or StatusNotModified, gives false; the match is exact and case-sensitive.
func isRedirectStatusConstant(constantName string) bool {
	switch constantName {
	case "StatusMovedPermanently", "StatusFound", "StatusSeeOther", "StatusTemporaryRedirect", "StatusPermanentRedirect":
		return true
	default:
		return false
	}
}
