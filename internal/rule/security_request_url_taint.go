// Package rule keeps syntax-only net/url parsing transparent to request taint.
// It ensures a user still sees a finding after storing url.Parse output, while
// affirmative destination guards remain the URL policy's separate decision.
package rule

import (
	"go/ast"
	"strings"
)

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
