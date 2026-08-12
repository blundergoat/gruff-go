// Package rule recognises affirmative destination guards for URL scan results.
//
// When a handler sends a browser or an outbound request somewhere the visitor
// chose, this file decides whether the author proved the destination is safe.
// Only affirmative evidence clears a finding: an explicit scheme *and* host
// check on the same parsed URL, a committed path prefix, or a loop that strips
// every leading slash so `//evil.example` cannot survive as a redirect target.
//
// Parsing is not proof. `url.Parse` establishes syntax, not trust, so a handler
// that merely parses the value keeps its finding. Evidence also expires: a guard
// stops counting once anything can change the value between the check and the
// request, which is why the staleness helpers here look at what a write really
// touches rather than only at whole-variable reassignment.
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

// bodyHasParsedDestinationAllowlist accepts a parsed URL only when guards the
// sink cannot skip constrain both its HTTP scheme and exact host. Parsing
// establishes syntax, not destination trust, so nothing weaker clears the sink.
func bodyHasParsedDestinationAllowlist(requestScope *requestTaintScope, functionBody *ast.BlockStmt, sinkValueNames map[string]bool, sinkPosition token.Pos) bool {
	parsedURLAssignments := parsedURLNamesForValue(requestScope, functionBody, sinkValueNames, sinkPosition)
	// Keep the finding when the scanned sink is not linked to a parsed URL local.
	if len(parsedURLAssignments) == 0 {
		return false
	}
	constraintEvidence := map[string]parsedDestinationEvidence{}
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// A nested callback runs against its own arguments, so a guard inside it
		// says nothing about the value reaching this sink.
		if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
			return false
		}
		returnGuard, isReturnGuard := syntaxNode.(*ast.IfStmt)
		// Only an earlier guard that exits the handler constrains the later request.
		if !isReturnGuard || returnGuard.Pos() >= sinkPosition || !blockEndsWithReturn(returnGuard.Body) {
			return true
		}
		// Scheme and host evidence accumulates per parsed value, so a guard the
		// sink can skip would pair with a guard on the opposite branch and read
		// as a complete allowlist that no single execution path performs.
		if !enclosingControlRegionsContainPosition(functionBody, returnGuard, sinkPosition) {
			return true
		}
		parsedURLNames := parsedURLNamesValidAt(functionBody, parsedURLAssignments, returnGuard.Pos())
		collectParsedDestinationEvidence(returnGuard.Cond, parsedURLNames, constraintEvidence)
		return true
	})
	// Scheme alone permits an arbitrary host and host alone permits an arbitrary
	// scheme, so only both checks on one parsed value describe a fixed destination.
	for _, parsedURLConstraint := range constraintEvidence {
		if parsedURLConstraint.hasAllowedScheme && parsedURLConstraint.hasAllowedHost {
			return true
		}
	}
	return false
}

// parsedURLNamesForValue links a report sink to locals created by net/url
// parsing before that sink, including `parsed.String()` request arguments.
func parsedURLNamesForValue(requestScope *requestTaintScope, functionBody *ast.BlockStmt, sinkValueNames map[string]bool, sinkPosition token.Pos) map[string][]token.Pos {
	parsedURLAssignments := map[string][]token.Pos{}
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
		if !isSyntaxParse {
			return true
		}
		linkedValueNames := parsedValueLinkNames(parsedInput, parseAssignment.Lhs, sinkValueNames)
		// Unrelated parse calls cannot validate the URL shown in the user's finding.
		if len(linkedValueNames) == 0 {
			return true
		}
		// Reassigning the linked local after parsing means the guards describe an
		// older value, not the request destination that reaches this sink.
		if anyNameAssignedBetween(functionBody, linkedValueNames, parseAssignment.End(), sinkPosition) {
			return true
		}
		parsedURLName, hasNamedResult := parseAssignment.Lhs[0].(*ast.Ident)
		// Blank results cannot be referenced by a later scheme or host guard.
		if hasNamedResult && parsedURLName.Name != "_" {
			parsedURLAssignments[parsedURLName.Name] = append(parsedURLAssignments[parsedURLName.Name], parseAssignment.End())
		}
		return true
	})
	return parsedURLAssignments
}

// parsedURLNamesValidAt returns parsed results still bound to a linked parse
// when one guard evaluates. Later reuse cannot erase earlier valid evidence,
// while an overwrite before the guard prevents stale checks from counting.
func parsedURLNamesValidAt(functionBody *ast.BlockStmt, assignmentsByName map[string][]token.Pos, guardPosition token.Pos) map[string]bool {
	validNames := map[string]bool{}
	for parsedURLName, assignmentPositions := range assignmentsByName {
		for assignmentIndex := len(assignmentPositions) - 1; assignmentIndex >= 0; assignmentIndex-- {
			assignmentPosition := assignmentPositions[assignmentIndex]
			if assignmentPosition >= guardPosition {
				continue
			}
			if !anyNameAssignedBetween(functionBody, map[string]bool{parsedURLName: true}, assignmentPosition, guardPosition) {
				validNames[parsedURLName] = true
				break
			}
		}
	}
	return validNames
}

// parsedValueLinkNames returns the sink locals that connect one parse result or
// parse input to the destination value used later.
func parsedValueLinkNames(parsedInput ast.Expr, leftHandValues []ast.Expr, sinkValueNames map[string]bool) map[string]bool {
	linkedNames := map[string]bool{}
	ast.Inspect(parsedInput, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && sinkValueNames[identifier.Name] {
			linkedNames[identifier.Name] = true
		}
		return true
	})
	for _, leftHandValue := range leftHandValues {
		identifier, ok := leftHandValue.(*ast.Ident)
		if ok && sinkValueNames[identifier.Name] {
			linkedNames[identifier.Name] = true
		}
	}
	return linkedNames
}

// anyNamePrefixRewrittenBetween reports whether a linked value changes in a way
// that can alter its leading characters between the guard and the sink.
//
// It exists because the two redirect proofs here are both statements about a
// prefix: a committed `/segment` start, or a loop that strips every leading
// slash. Appending to the value cannot reintroduce a `//`, so the canonical
//
//	for strings.HasPrefix(toPath, "//") { toPath = strings.TrimPrefix(toPath, "/") }
//	if r.URL.RawQuery != "" { toPath += "?" + r.URL.RawQuery }
//
// stays safe. Reading that query-string append as invalidation reported the very
// normalisation the rule exists to bless, in real handlers that do it correctly.
func anyNamePrefixRewrittenBetween(functionBody *ast.BlockStmt, names map[string]bool, afterPosition, beforePosition token.Pos) bool {
	rewritten := false
	ast.Inspect(functionBody, func(node ast.Node) bool {
		if rewritten {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		if node == nil || node.Pos() <= afterPosition || node.Pos() >= beforePosition {
			return true
		}
		switch statement := node.(type) {
		case *ast.AssignStmt:
			// A write that only extends the value on the right keeps the
			// checked prefix; anything else replaces what the guard approved.
			rewritten = lhsUsesAnyName(statement.Lhs, names) && !assignmentPreservesPrefix(statement, names)
		case *ast.ValueSpec:
			for _, name := range statement.Names {
				if names[name.Name] {
					rewritten = true
					break
				}
			}
		}
		return !rewritten
	})
	return rewritten
}

// assignmentPreservesPrefix reports whether an assignment only extends its own
// target on the right, leaving the leading characters unchanged.
func assignmentPreservesPrefix(statement *ast.AssignStmt, names map[string]bool) bool {
	// A multi-value assignment does not describe one extended string.
	if len(statement.Lhs) != 1 || len(statement.Rhs) != 1 {
		return false
	}
	target, isIdentifier := statement.Lhs[0].(*ast.Ident)
	if !isIdentifier || !names[target.Name] {
		return false
	}
	// `target += suffix` is exactly `target = target + suffix`.
	if statement.Tok == token.ADD_ASSIGN {
		return true
	}
	if statement.Tok != token.ASSIGN {
		return false
	}
	// `target = target + suffix` keeps the prefix; `target = prefix + target`
	// prepends and can put `//` back at the front, so only the leftmost
	// position counts as an extension.
	return leftmostConcatName(statement.Rhs[0]) == target.Name
}

// leftmostConcatName returns the identifier at the far left of a `+` chain.
func leftmostConcatName(expr ast.Expr) string {
	for {
		switch value := unwrapRequestExprParens(expr).(type) {
		case *ast.BinaryExpr:
			// Only concatenation keeps a readable leading operand.
			if value.Op != token.ADD {
				return ""
			}
			expr = value.X
		case *ast.Ident:
			return value.Name
		default:
			return ""
		}
	}
}

// anyNameAssignedBetween reports whether a linked value is overwritten after
// its evidence was established and before the destination sink executes.
func anyNameAssignedBetween(functionBody *ast.BlockStmt, names map[string]bool, afterPosition, beforePosition token.Pos) bool {
	found := false
	ast.Inspect(functionBody, func(node ast.Node) bool {
		if found {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		if node == nil || node.Pos() <= afterPosition || node.Pos() >= beforePosition {
			return true
		}
		switch statement := node.(type) {
		case *ast.AssignStmt:
			found = lhsUsesAnyName(statement.Lhs, names)
		case *ast.ValueSpec:
			for _, name := range statement.Names {
				if names[name.Name] {
					found = true
					break
				}
			}
		}
		return !found
	})
	return found
}

// branchLeavesTrimLoop reports whether a branch statement can reach code after
// the loop, or skip a pass of it, without the loop condition being re-tested.
// True here voids the whole normalisation proof and the redirect stays in the
// user's report, which is the safe direction for an escape we cannot rule out.
//
// insideNestedBreakable says whether the branch sits inside an inner for, range,
// switch, type switch, or select. Go binds an unlabelled break to the innermost
// such construct, so a break written there ends that construct and the trim loop
// still runs to completion. Treating it as an escape rejected correctly
// normalised handlers - the noise direction, and the reason this depth is
// tracked rather than assumed.
func branchLeavesTrimLoop(branch *ast.BranchStmt, insideNestedBreakable bool) bool {
	switch branch.Tok {
	case token.GOTO:
		// A goto can land anywhere in the function, including past the loop.
		return true
	case token.BREAK:
		// A label always names an outer construct; an unlabelled break escapes
		// only when this loop is the innermost one enclosing it.
		return branch.Label != nil || !insideNestedBreakable
	case token.CONTINUE:
		// A bare `continue` re-tests `HasPrefix(target, "//")` and is safe. A
		// labelled one targets an outer loop and abandons the trim entirely.
		return branch.Label != nil
	default:
		// `fallthrough` stays inside its own switch clause.
		return false
	}
}

// trimLoopBodyEscapes reports whether any branch inside the trim loop can leave
// it before the condition is re-tested. It walks depth-aware because an
// unlabelled break changes meaning once it sits inside an inner breakable
// construct; a single flat scan cannot tell those two spellings apart.
func trimLoopBodyEscapes(subtree ast.Node, insideNestedBreakable bool) bool {
	escapes := false
	ast.Inspect(subtree, func(node ast.Node) bool {
		if escapes || node == nil {
			return false
		}
		// A closure cannot branch out of the loop that encloses it.
		if _, isFunction := node.(*ast.FuncLit); isFunction {
			return false
		}
		// Re-enter an inner breakable construct so its own branches are read
		// against it rather than against the trim loop.
		if node != subtree && isBreakableConstruct(node) {
			escapes = trimLoopBodyEscapes(node, true)
			return false
		}
		if branch, isBranch := node.(*ast.BranchStmt); isBranch && branchLeavesTrimLoop(branch, insideNestedBreakable) {
			escapes = true
			return false
		}
		return true
	})
	return escapes
}

// isBreakableConstruct reports whether a node captures an unlabelled break.
func isBreakableConstruct(node ast.Node) bool {
	switch node.(type) {
	case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
		return true
	default:
		return false
	}
}

// lhsUsesAnyName reports whether an assignment writes the value shown at the
// user's request or redirect sink. A true answer expires the guard that came
// before it, so the destination appears in the report again.
func lhsUsesAnyName(leftHandValues []ast.Expr, sinkValueNames map[string]bool) bool {
	// Check each result because net/url parsing commonly assigns both URL and error.
	for _, leftHandValue := range leftHandValues {
		// A matching named result links the parsed value to the sink. Writing a
		// field, element, or pointee of that name changes the same value the
		// guard checked, so `parsed.Host = ...` invalidates the guard exactly as
		// reassigning `parsed` does.
		if rootName, hasRoot := assignedRootName(leftHandValue); hasRoot && sinkValueNames[rootName] {
			return true
		}
	}
	return false
}

// assignedRootName returns the identifier an assignment target ultimately
// writes through, stepping past selectors, indexes, and pointer dereferences.
// An index expression roots at the collection, so `cache[target] = value`
// reports cache rather than the target used to address it.
//
// The empty, false result means the write goes through something this
// parser-only rule cannot follow, such as `pick().Host = ...`. That answer
// invalidates nothing, so an earlier guard keeps standing and the finding stays
// hidden - the losing direction for a security rule, and a residual blind spot
// rather than a deliberate exemption. It is bounded: it applies only where the
// write does not root at a plain name, and it is strictly narrower than the
// identifier-only check it replaced.
func assignedRootName(target ast.Expr) (string, bool) {
	for {
		switch value := target.(type) {
		case *ast.Ident:
			// Reached the variable itself - this is the name being written.
			return value.Name, true
		case *ast.ParenExpr:
			target = value.X
		case *ast.SelectorExpr:
			// `parsed.Host = ...` - the user replaced one field of the URL they
			// had already checked, which changes where the request goes.
			target = value.X
		case *ast.IndexExpr:
			// `targets[0] = ...` - an element changed, so the collection the
			// guard reasoned about no longer holds the value it approved.
			target = value.X
		case *ast.StarExpr:
			// `*parsed = ...` - written through a pointer, replacing the whole
			// value the earlier scheme and host checks were about.
			target = value.X
		default:
			return "", false
		}
	}
}

// collectParsedDestinationEvidence extracts rejecting scheme and host checks
// that explain why a URL is absent from the user's findings list.
func collectParsedDestinationEvidence(condition ast.Expr, parsedURLNames map[string]bool, evidenceByName map[string]parsedDestinationEvidence) {
	condition = unwrapRequestExprParens(condition)
	binaryCondition, isBinary := condition.(*ast.BinaryExpr)
	if !isBinary {
		return
	}
	// In a rejecting guard, each side of OR independently rejects an invalid
	// dimension. Under AND, either invalid dimension can pass on its own, so no
	// comparison in that subtree is affirmative allowlist evidence.
	if binaryCondition.Op == token.LOR {
		collectParsedDestinationEvidence(binaryCondition.X, parsedURLNames, evidenceByName)
		collectParsedDestinationEvidence(binaryCondition.Y, parsedURLNames, evidenceByName)
		return
	}
	if binaryCondition.Op != token.NEQ {
		return
	}
	recordParsedDestinationComparison(binaryCondition, parsedURLNames, evidenceByName)
}

// recordParsedDestinationComparison stores one rejection-safe field check.
func recordParsedDestinationComparison(comparison *ast.BinaryExpr, parsedURLNames map[string]bool, evidenceByName map[string]parsedDestinationEvidence) {
	parsedURLName, fieldName, allowedLiteral, isURLComparison := parsedURLLiteralComparison(comparison.X, comparison.Y, parsedURLNames)
	// Users may write the literal on the left, so inspect the reverse order too.
	if !isURLComparison {
		parsedURLName, fieldName, allowedLiteral, isURLComparison = parsedURLLiteralComparison(comparison.Y, comparison.X, parsedURLNames)
	}
	if !isURLComparison {
		return
	}
	destinationEvidence := evidenceByName[parsedURLName]
	if fieldName == "scheme" && (allowedLiteral == "http" || allowedLiteral == "https") {
		destinationEvidence.hasAllowedScheme = true
	}
	if fieldName == "host" && allowedLiteral != "" {
		destinationEvidence.hasAllowedHost = true
	}
	evidenceByName[parsedURLName] = destinationEvidence
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
		// An optional outer branch lets the sink bypass this prefix requirement.
		if !enclosingControlRegionsContainPosition(functionBody, returnGuard, sinkPosition) {
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
		// A user-visible safe guard needs a path segment, this sink value, and no
		// later overwrite that invalidates the checked value before the redirect.
		if hasLiteral && isSafeRelativePrefix(committedPrefix) && nodeUsesAnyIdent(prefixCall.Args[0], sinkValueNames) &&
			!anyNamePrefixRewrittenBetween(functionBody, sinkValueNames, returnGuard.End(), sinkPosition) {
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
		// Normalization must run on every path that can reach the later redirect.
		if !enclosingControlRegionsContainPosition(functionBody, prefixLoop, sinkPosition) {
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
		foundSafeLoop = loopTrimsOneLeadingSlash(prefixLoop.Body, redirectIdentifier.Name, stringPackageAliases) &&
			!anyNamePrefixRewrittenBetween(functionBody, sinkValueNames, prefixLoop.End(), sinkPosition)
		return !foundSafeLoop
	})
	return foundSafeLoop
}

// loopTrimsOneLeadingSlash verifies that each loop pass updates the checked
// redirect value with strings.TrimPrefix(value, "/").
func loopTrimsOneLeadingSlash(loopBody *ast.BlockStmt, redirectVariableName string, stringPackageAliases map[string]bool) bool {
	// A break, goto, or labelled continue written directly in this loop can
	// reach the sink while the value still begins with `//`, because each one
	// leaves the loop rather than re-testing its condition. Reject the whole
	// normalization proof instead of approximating branch reachability in this
	// parser-only rule. A label naming this same loop would in fact be safe, but
	// the label is not in scope here and over-rejecting only costs a visible
	// finding.
	if trimLoopBodyEscapes(loopBody, false) {
		return false
	}
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
