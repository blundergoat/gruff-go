// Package rule keeps syntax-only net/url parsing transparent to request taint.
//
// A user still sees a finding after storing url.Parse output in a local and using that local's String result where the raw input would be flagged.
// Affirmative destination guards remain the URL policy's separate decision.
package rule

import (
	"go/ast"
	"strings"
)

// isParsedURLExpr reports whether expr, ignoring parentheses, is a net/url Parse or ParseRequestURI call; any other expression gives false.
// Such results are tracked apart from other tainted values so a later String call on them keeps request taint.
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
//
// Shadowed locals stay independent, so only the parsed value preserves request taint.
// identifier names the local being bound; a nil, blank or unresolved identifier is ignored because it has no object to record.
func (s *requestTaintScope) markParsedURLBinding(identifier *ast.Ident) {
	// Unresolved or blank syntax cannot identify a local the user later calls String on.
	if identifier == nil || identifier.Name == "_" || identifier.Obj == nil {
		return
	}
	s.parsedURLBindings[identifier.Obj] = true
}

// parsedURLStringReceiver returns the parsed local converted by url.URL.String.
//
// Restricting this transparency to known parse results avoids treating every unknown String method as a taint-preserving operation.
//
// call matches only when it is a zero-argument String call whose unparenthesised receiver resolves to a local marked by markParsedURLBinding.
// The receiver returned is that identifier with its parentheses removed; any other call gives nil and false.
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

// unwrapRequestExprParens removes syntax-only parentheses from request-flow expressions shared by taint and destination-constraint analysis.
// It returns expr with all enclosing parentheses stripped, or expr unchanged when it is not a parenthesised expression, including nil.
func unwrapRequestExprParens(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// urlSyntaxParseArg returns the input to a recognised net/url Parse or ParseRequestURI call, without checking request taint.
//
// Successful parsing proves syntax only, so directRequestExpr keeps a parse of request-controlled input tainted.
//
// candidateCall must be a one-argument Parse or ParseRequestURI call on an unshadowed net/url import name listed in s.netURLPkgs.
// Its single argument is returned with true; any other call gives nil and false.
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
	if !isIdentifier || !isImportedPackageIdentifier(packageIdentifier, s.netURLPkgs) {
		return nil, false
	}
	return candidateCall.Args[0], true
}

// precededByDestinationNegation rejects exact positive tokens when the prior token reverses their meaning, as in notTrusted or isNotAllowed.
//
// identifierTokens holds the words split from one identifier and tokenIndex points at the positive token being checked.
// It reports true when the word before tokenIndex is deny, denied, no, non, not, reject, rejected or without, compared case-insensitively.
// It reports false for tokenIndex 0 or any other prior word, and panics when tokenIndex is negative or greater than len(identifierTokens).
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
