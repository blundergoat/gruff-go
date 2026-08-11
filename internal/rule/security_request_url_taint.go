// Package rule keeps syntax-only net/url parsing transparent to request taint.
// It ensures a user still sees a finding after storing url.Parse output, while
// affirmative destination guards remain the URL policy's separate decision.
package rule

import (
	"go/ast"
	"strings"
)

// isParsedURLExpr reports whether expr is a net/url parse call whose result is
// tracked separately from arbitrary tainted values for transparent String use.
func (s *requestTaintScope) isParsedURLExpr(expr ast.Expr) bool {
	expr = unwrapRequestExprParens(expr)
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	_, isSyntaxParse := s.urlSyntaxParseArg(call)
	return isSyntaxParse
}

// markParsedURLBinding records the lexical local that holds a parsed request URL.
// Shadowed locals stay independent, so only the parsed value preserves request taint.
func (s *requestTaintScope) markParsedURLBinding(identifier *ast.Ident) {
	// Unresolved or blank syntax cannot identify a local the user later calls String on.
	if identifier == nil || identifier.Name == "_" || identifier.Obj == nil {
		return
	}
	s.parsedURLBindings[identifier.Obj] = true
}

// parsedURLStringReceiver returns the parsed local converted by url.URL.String.
// Restricting this transparency to known parse results avoids treating every
// unknown String method as a taint-preserving operation.
func (s *requestTaintScope) parsedURLStringReceiver(call *ast.CallExpr) (ast.Expr, bool) {
	if len(call.Args) != 0 {
		return nil, false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "String" {
		return nil, false
	}
	receiver := unwrapRequestExprParens(selector.X)
	identifier, ok := receiver.(*ast.Ident)
	// A same-named local is unrelated unless it resolves to the parsed binding.
	if !ok || identifier.Obj == nil || !s.parsedURLBindings[identifier.Obj] {
		return nil, false
	}
	return receiver, true
}

// unwrapRequestExprParens removes syntax-only parentheses from request-flow
// expressions shared by taint and destination-constraint analysis.
func unwrapRequestExprParens(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// urlSyntaxParseArg returns the request-controlled input to the two net/url
// parsers that produce a URL. Successful parsing proves syntax only; the result
// remains attacker-controlled until a destination constraint is established.
func (s *requestTaintScope) urlSyntaxParseArg(candidateCall *ast.CallExpr) (ast.Expr, bool) {
	// A malformed or multi-input call is not one of net/url's supported parsers.
	if len(candidateCall.Args) != 1 {
		return nil, false
	}
	parserSelector, isSelector := candidateCall.Fun.(*ast.SelectorExpr)
	// Only Parse and ParseRequestURI preserve the user's destination value here.
	if !isSelector || (parserSelector.Sel.Name != "Parse" && parserSelector.Sel.Name != "ParseRequestURI") {
		return nil, false
	}
	packageIdentifier, isIdentifier := parserSelector.X.(*ast.Ident)
	// A matching import alias prevents an unrelated Parse method from gaining taint.
	if !isIdentifier || !s.netURLPkgs[packageIdentifier.Name] {
		return nil, false
	}
	return candidateCall.Args[0], true
}

// precededByDestinationNegation rejects exact positive tokens when the prior
// token explicitly reverses their meaning, as in notTrusted or isNotAllowed.
func precededByDestinationNegation(identifierTokens []string, tokenIndex int) bool {
	// The first token has no earlier word that can reverse its user-facing meaning.
	if tokenIndex == 0 {
		return false
	}
	switch strings.ToLower(identifierTokens[tokenIndex-1]) {
	case "deny", "denied", "no", "non", "not", "reject", "rejected", "without":
		return true
	default:
		return false
	}
}
