// Package rule recognises affirmative destination guards for URL scan results.
// It keeps syntax-only parsing visible while allowing explicit scheme, host,
// and same-origin redirect checks that users can rely on in the scan report.
package rule

import (
	"go/ast"
	"go/token"
	"strings"
)

// parsedDestinationEvidence records the two checks a user must provide before
// a parsed request URL disappears from the findings list.
// Both values belong to one parsed URL, preventing partial checks from hiding risk.
type parsedDestinationEvidence struct {
	hasAllowedScheme bool
	hasAllowedHost   bool
}

// bodyHasParsedDestinationAllowlist accepts a parsed URL only when earlier
// return guards constrain both its HTTP scheme and exact host.
func bodyHasParsedDestinationAllowlist(requestScope *requestTaintScope, functionBody *ast.BlockStmt, sinkValueNames map[string]bool, sinkPosition token.Pos) bool {
	parsedURLNames := parsedURLNamesForValue(requestScope, functionBody, sinkValueNames, sinkPosition)
	// Keep the finding when the scanned sink is not linked to a parsed URL local.
	if len(parsedURLNames) == 0 {
		return false
	}
	constraintEvidence := map[string]parsedDestinationEvidence{}
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// Ignore nested callbacks because their checks do not protect the user's sink.
		if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
			return false
		}
		returnGuard, isReturnGuard := syntaxNode.(*ast.IfStmt)
		// Only an earlier guard that exits the handler constrains the later request.
		if !isReturnGuard || returnGuard.Pos() >= sinkPosition || !blockEndsWithReturn(returnGuard.Body) {
			return true
		}
		collectParsedDestinationEvidence(returnGuard.Cond, parsedURLNames, constraintEvidence)
		return true
	})
	// A user needs both checks on the same parsed value to remove the finding.
	for _, parsedURLConstraint := range constraintEvidence {
		// A partial scheme-only or host-only check remains visible in the report.
		if parsedURLConstraint.hasAllowedScheme && parsedURLConstraint.hasAllowedHost {
			return true
		}
	}
	return false
}

// parsedURLNamesForValue links a report sink to locals created by net/url
// parsing before that sink, including `parsed.String()` request arguments.
func parsedURLNamesForValue(requestScope *requestTaintScope, functionBody *ast.BlockStmt, sinkValueNames map[string]bool, sinkPosition token.Pos) map[string]bool {
	parsedURLNames := map[string]bool{}
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// Nested handlers have separate user input and do not validate this sink.
		if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
			return false
		}
		parseAssignment, isAssignment := syntaxNode.(*ast.AssignStmt)
		// Ignore non-assignments, later work, and empty right-hand sides.
		if !isAssignment || parseAssignment.Pos() >= sinkPosition || len(parseAssignment.Rhs) == 0 {
			return true
		}
		syntaxParseCall, isCall := parseAssignment.Rhs[0].(*ast.CallExpr)
		// Only known net/url parsing can establish the parsed-value relationship.
		if !isCall {
			return true
		}
		parsedInput, isSyntaxParse := requestScope.urlSyntaxParseArg(syntaxParseCall)
		usesSinkValue := nodeUsesAnyIdent(parsedInput, sinkValueNames) || lhsUsesAnyName(parseAssignment.Lhs, sinkValueNames)
		// Unrelated parse calls cannot validate the URL shown in the user's finding.
		if !isSyntaxParse || !usesSinkValue {
			return true
		}
		parsedURLName, hasNamedResult := parseAssignment.Lhs[0].(*ast.Ident)
		// Blank results cannot be referenced by a later scheme or host guard.
		if hasNamedResult && parsedURLName.Name != "_" {
			parsedURLNames[parsedURLName.Name] = true
		}
		return true
	})
	return parsedURLNames
}

// lhsUsesAnyName reports whether an assignment writes the value shown at the
// user's request or redirect sink.
func lhsUsesAnyName(leftHandValues []ast.Expr, sinkValueNames map[string]bool) bool {
	// Check each result because net/url parsing commonly assigns both URL and error.
	for _, leftHandValue := range leftHandValues {
		identifier, isIdentifier := leftHandValue.(*ast.Ident)
		// A matching named result links the parsed value to the sink.
		if isIdentifier && sinkValueNames[identifier.Name] {
			return true
		}
	}
	return false
}

// collectParsedDestinationEvidence extracts rejecting scheme and host checks
// that explain why a URL is absent from the user's findings list.
func collectParsedDestinationEvidence(condition ast.Expr, parsedURLNames map[string]bool, evidenceByName map[string]parsedDestinationEvidence) {
	ast.Inspect(condition, func(syntaxNode ast.Node) bool {
		comparison, isComparison := syntaxNode.(*ast.BinaryExpr)
		// Only `!=` checks inside an exiting guard form a positive allowlist.
		if !isComparison || comparison.Op != token.NEQ {
			return true
		}
		parsedURLName, fieldName, allowedLiteral, isURLComparison := parsedURLLiteralComparison(comparison.X, comparison.Y, parsedURLNames)
		// Users may write the literal on the left, so inspect the reverse order too.
		if !isURLComparison {
			parsedURLName, fieldName, allowedLiteral, isURLComparison = parsedURLLiteralComparison(comparison.Y, comparison.X, parsedURLNames)
		}
		// Other comparisons do not constrain the destination represented at the sink.
		if !isURLComparison {
			return true
		}
		destinationEvidence := evidenceByName[parsedURLName]
		// The report accepts only HTTP schemes, not arbitrary parsed schemes.
		if fieldName == "scheme" && (allowedLiteral == "http" || allowedLiteral == "https") {
			destinationEvidence.hasAllowedScheme = true
		}
		// A non-empty literal is an exact host allowlist entry from the user's code.
		if fieldName == "host" && allowedLiteral != "" {
			destinationEvidence.hasAllowedHost = true
		}
		evidenceByName[parsedURLName] = destinationEvidence
		return true
	})
}

// parsedURLLiteralComparison returns one parsed field and its literal when the
// comparison belongs to the URL reaching the user's sink.
func parsedURLLiteralComparison(valueExpression, literalExpression ast.Expr, parsedURLNames map[string]bool) (string, string, string, bool) {
	allowedLiteral, hasLiteral := stringLiteral(literalExpression)
	// Dynamic values are not an explicit scheme or host allowlist.
	if !hasLiteral {
		return "", "", "", false
	}
	parsedURLName, fieldName, hasField := parsedURLField(valueExpression, parsedURLNames)
	return parsedURLName, fieldName, allowedLiteral, hasField
}

// parsedURLField recognises Scheme, Host, or Hostname checks on the parsed URL
// associated with the user's outbound destination.
func parsedURLField(valueExpression ast.Expr, parsedURLNames map[string]bool) (string, string, bool) {
	methodCall, isMethodCall := valueExpression.(*ast.CallExpr)
	// Hostname() is the method form users commonly choose for a port-free host.
	if isMethodCall && len(methodCall.Args) == 0 {
		selector, isSelector := methodCall.Fun.(*ast.SelectorExpr)
		// Other zero-argument methods do not prove destination ownership.
		if !isSelector || selector.Sel.Name != "Hostname" {
			return "", "", false
		}
		parsedURLIdentifier, isIdentifier := selector.X.(*ast.Ident)
		return identNameAndField(parsedURLIdentifier, "host", parsedURLNames, isIdentifier)
	}
	fieldSelector, isSelector := valueExpression.(*ast.SelectorExpr)
	// The UI policy intentionally accepts only net/url's Scheme and Host fields.
	if !isSelector || (fieldSelector.Sel.Name != "Scheme" && fieldSelector.Sel.Name != "Host") {
		return "", "", false
	}
	parsedURLIdentifier, isIdentifier := fieldSelector.X.(*ast.Ident)
	return identNameAndField(parsedURLIdentifier, strings.ToLower(fieldSelector.Sel.Name), parsedURLNames, isIdentifier)
}

// identNameAndField validates that a selector belongs to the parsed URL whose
// destination would otherwise appear in the scan report.
func identNameAndField(identifier *ast.Ident, fieldName string, parsedURLNames map[string]bool, isIdentifier bool) (string, string, bool) {
	// Nil, non-identifier, or unrelated selectors cannot validate this finding.
	if !isIdentifier || identifier == nil || !parsedURLNames[identifier.Name] {
		return "", "", false
	}
	return identifier.Name, fieldName, true
}

// blockEndsWithReturn requires a guard to stop the unsafe user destination
// before the scanner accepts its checks as protection.
func blockEndsWithReturn(statementBlock *ast.BlockStmt) bool {
	// An empty or absent block lets the request continue and cannot protect users.
	if statementBlock == nil || len(statementBlock.List) == 0 {
		return false
	}
	_, endsWithReturn := statementBlock.List[len(statementBlock.List)-1].(*ast.ReturnStmt)
	return endsWithReturn
}

// bodyHasCommittedRelativePrefix accepts an exiting HasPrefix guard only when
// its literal names a real path segment rather than a bare slash.
func bodyHasCommittedRelativePrefix(functionBody *ast.BlockStmt, sinkValueNames, stringPackageAliases map[string]bool, sinkPosition token.Pos) bool {
	foundCommittedPrefix := false
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// Stop once the scan has user-visible evidence for this destination.
		if foundCommittedPrefix {
			return false
		}
		// A nested callback does not protect the outer redirect shown to the user.
		if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
			return false
		}
		returnGuard, isReturnGuard := syntaxNode.(*ast.IfStmt)
		// Only an earlier exiting guard constrains the later redirect.
		if !isReturnGuard || returnGuard.Pos() >= sinkPosition || !blockEndsWithReturn(returnGuard.Body) {
			return true
		}
		negatedCondition, isNegated := returnGuard.Cond.(*ast.UnaryExpr)
		// The safe form rejects values that do not start with the committed segment.
		if !isNegated || negatedCondition.Op != token.NOT {
			return true
		}
		prefixCall, isCall := negatedCondition.X.(*ast.CallExpr)
		// Unrelated helpers and malformed calls do not constrain the redirect target.
		if !isCall || !selectorCallMatches(prefixCall, stringPackageAliases, "HasPrefix") || len(prefixCall.Args) != 2 {
			return true
		}
		committedPrefix, hasLiteral := stringLiteral(prefixCall.Args[1])
		// A user-visible safe guard needs both a path segment and this sink value.
		if hasLiteral && isSafeRelativePrefix(committedPrefix) && nodeUsesAnyIdent(prefixCall.Args[0], sinkValueNames) {
			foundCommittedPrefix = true
		}
		return !foundCommittedPrefix
	})
	return foundCommittedPrefix
}

// bodyStripsProtocolRelativePrefix accepts a loop that removes leading slashes
// until a user-supplied redirect can no longer name an external host.
func bodyStripsProtocolRelativePrefix(functionBody *ast.BlockStmt, sinkValueNames, stringPackageAliases map[string]bool, sinkPosition token.Pos) bool {
	foundSafeLoop := false
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// Stop once one complete normalization loop protects the redirect.
		if foundSafeLoop {
			return false
		}
		// Checks in nested callbacks do not change the outer response destination.
		if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
			return false
		}
		prefixLoop, isForLoop := syntaxNode.(*ast.ForStmt)
		// Only a loop before the redirect can remove every repeated leading slash.
		if !isForLoop || prefixLoop.Pos() >= sinkPosition {
			return true
		}
		prefixCheck, isCall := prefixLoop.Cond.(*ast.CallExpr)
		// The loop condition must specifically test strings.HasPrefix(value, "//").
		if !isCall || !selectorCallMatches(prefixCheck, stringPackageAliases, "HasPrefix") || len(prefixCheck.Args) != 2 {
			return true
		}
		protocolRelativePrefix, hasLiteral := stringLiteral(prefixCheck.Args[1])
		redirectIdentifier, isIdentifier := prefixCheck.Args[0].(*ast.Ident)
		// Unrelated values or prefixes do not explain why this finding is safe.
		if !hasLiteral || protocolRelativePrefix != "//" || !isIdentifier || !sinkValueNames[redirectIdentifier.Name] {
			return true
		}
		foundSafeLoop = loopTrimsOneLeadingSlash(prefixLoop.Body, redirectIdentifier.Name, stringPackageAliases)
		return !foundSafeLoop
	})
	return foundSafeLoop
}

// loopTrimsOneLeadingSlash verifies that each loop pass updates the checked
// redirect value with strings.TrimPrefix(value, "/").
func loopTrimsOneLeadingSlash(loopBody *ast.BlockStmt, redirectVariableName string, stringPackageAliases map[string]bool) bool {
	// Inspect every statement because users may log or count normalization work.
	for _, loopStatement := range loopBody.List {
		trimAssignment, isAssignment := loopStatement.(*ast.AssignStmt)
		// The normalizing assignment must have one target and one replacement value.
		if !isAssignment || len(trimAssignment.Lhs) != 1 || len(trimAssignment.Rhs) != 1 {
			continue
		}
		targetIdentifier, hasTarget := trimAssignment.Lhs[0].(*ast.Ident)
		trimCall, isCall := trimAssignment.Rhs[0].(*ast.CallExpr)
		// Only an assignment back to the checked redirect can make the loop progress.
		if !hasTarget || targetIdentifier.Name != redirectVariableName || !isCall ||
			!selectorCallMatches(trimCall, stringPackageAliases, "TrimPrefix") || len(trimCall.Args) != 2 {
			continue
		}
		trimmedIdentifier, hasInput := trimCall.Args[0].(*ast.Ident)
		trimmedPrefix, hasLiteral := stringLiteral(trimCall.Args[1])
		// Removing exactly one slash per pass guarantees a later value cannot start `//`.
		if hasInput && trimmedIdentifier.Name == redirectVariableName && hasLiteral && trimmedPrefix == "/" {
			return true
		}
	}
	return false
}
