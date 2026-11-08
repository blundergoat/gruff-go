// Package rule recognises affirmative destination guards for URL scan results.
//
// When a handler sends a browser or an outbound request somewhere the visitor chose, this file looks for syntactic destination constraints.
// A recognised constraint is evidence for suppressing the finding, within the limitations each helper states, not a proof of safety.
//
// Only affirmative evidence counts: a scheme and host check on one parsed URL, a committed path prefix, or a slash-trimming loop.
// That loop removes repeated leading slashes until at most one remains, so //evil.example cannot survive as a redirect target.
//
// Parsing is not proof: url.Parse establishes syntax, not trust, so a handler that merely parses the value keeps its finding.
// Evidence expires when a later write is recognised as invalidating; an accepted append can still restore a // prefix.
// The staleness helpers look at what a write really touches rather than only at whole-variable reassignment.
package rule

import (
	"go/ast"
	"go/token"
	"strings"
)

// parsedDestinationEvidence records the two checks a user must provide before a parsed request URL disappears from the findings list.
//
// Both values belong to one parsed URL, preventing partial checks from hiding risk.
type parsedDestinationEvidence struct {
	hasAllowedScheme bool
	hasAllowedHost   bool
}

// bodyHasParsedDestinationAllowlist recognises rejecting HTTP scheme and exact host checks on one parsed URL linked to the sink.
// A sink inside a rejecting guard's body can qualify even though that destination need not pass those checks.
//
// Parsing establishes syntax, not destination trust, so nothing weaker clears the sink.
//
// The requestScope recognises net/url parse calls, functionBody is the body searched, and sinkValueNames are the locals carrying the destination.
// Only parses and exiting guards starting before sinkPosition count; every region enclosing a guard must also contain the sink.
// Jumps such as goto are not followed, so this does not prove every path to the sink runs the guard.
//
// It returns true when one parsed URL has both a rejecting http or https scheme check and a non-empty host check; false means none was found.
func bodyHasParsedDestinationAllowlist(requestScope *requestTaintScope, functionBody *ast.BlockStmt, sinkValueNames map[string]bool, sinkPosition token.Pos) bool {
	parsedURLAssignments := parsedURLNamesForValue(requestScope, functionBody, sinkValueNames, sinkPosition)
	// Keep the finding when the scanned sink is not linked to a parsed URL local.
	if len(parsedURLAssignments) == 0 {
		return false
	}
	constraintEvidence := map[string]parsedDestinationEvidence{}
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// Guards inside closures are ignored here, even when they check a captured outer destination.
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

// parsedURLNamesForValue links a report sink to locals created by net/url parsing before that sink, including parsed.String() request arguments.
//
// The requestScope recognises parse calls, functionBody is walked outside nested closures, and sinkValueNames are the sink's destination locals.
// A parse before sinkPosition counts only when its input or results name one of those locals and no linked local is reassigned before the sink.
// It returns each named parse result mapped to the end positions of its qualifying parse assignments, and an empty map when none qualify.
func parsedURLNamesForValue(requestScope *requestTaintScope, functionBody *ast.BlockStmt, sinkValueNames map[string]bool, sinkPosition token.Pos) map[string][]token.Pos {
	parsedURLAssignments := map[string][]token.Pos{}
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// Parses inside closures are ignored, even when they read or assign the outer destination.
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

// parsedURLNamesValidAt returns the parsed results still bound to a linked parse when one guard evaluates.
//
// Later reuse cannot erase earlier valid evidence, while an overwrite before the guard prevents stale checks from counting.
//
// The assignmentsByName map gives each parsed name the end positions of its linked parses, as parsedURLNamesForValue builds it.
// A name stays valid when a parse ending before guardPosition has no reassignment in functionBody between it and that guard.
// An empty result means no check in that guard can count as evidence.
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

// parsedValueLinkNames returns the sink locals that connect one parse result or parse input to the destination value used later.
//
// Every identifier inside parsedInput, the parse call's argument, and each plain identifier in leftHandValues, the assignment targets, is checked.
// A name is kept when sinkValueNames holds it, so the map is empty when the parse touches no sink local.
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

// anyNamePrefixRewrittenBetween reports whether a linked value changes in a way that can alter its leading characters between guard and sink.
//
// Both redirect proofs here are prefix statements, so appending ? plus RawQuery after the slash-trimming loop keeps the evidence.
// Other appends are accepted too and are not all safe: when the loop leaves one slash, appending /evil.example yields //evil.example.
//
// It walks functionBody outside nested closures, looking at nodes that start strictly after afterPosition and strictly before beforePosition.
// An assignment rooted at one of names counts unless assignmentPreservesPrefix accepts it; a var or const spec naming one always counts.
// Increment and decrement statements are not examined, so they never count.
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
			// A write that appends to the value on the right is treated as keeping the checked prefix; anything else replaces what the guard approved.
			// That append is not inspected, so one that restores // after trimming left a single slash still leaves the evidence standing.
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

// assignmentPreservesPrefix reports whether an assignment only extends its own target on the right, leaving the leading characters unchanged.
//
// For a statement with one identifier target in names and one value, += qualifies, as does = with that target alone or leading a + chain.
// Any other statement gives false, and callers treat it as a write that can change the prefix.
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
	// target = target + suffix counts as an extension and target = prefix + target does not, because prepending can put // back at the front.
	// The suffix itself is not checked, so a self-append can still restore // once trimming has left a single slash.
	return leftmostConcatName(statement.Rhs[0]) == target.Name
}

// leftmostConcatName returns the identifier at the far left of a `+` chain.
// Parentheses around expr are skipped; any operator other than + or a non-identifier operand on the left gives an empty string.
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

// anyNameAssignedBetween reports whether a linked value is overwritten after its evidence was established and before the sink runs.
//
// It walks functionBody outside nested closures, looking at nodes that start strictly after afterPosition and strictly before beforePosition.
// Any assignment rooted at one of names, including through a field, index or pointer, counts, as does a var or const spec naming one.
// Increment and decrement statements are not examined, so they never count.
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

// branchLeavesTrimLoop reports whether branch is conservatively treated as an escape from the trim loop.
//
// True rejects this loop as normalisation evidence; another qualifying loop can still suppress the redirect finding.
// Labelled branches are conservatively treated as escapes without resolving their targets, including labels naming this loop or an inner loop.
//
// insideNestedBreakable says whether the branch sits inside an inner for, range, switch, type switch, or select.
// Go binds an unlabelled break to the innermost such construct, so a break there ends that construct and the trim loop still runs to completion.
// Treating it as an escape rejected correctly normalised handlers, the noise direction, and the reason this depth is tracked rather than assumed.
func branchLeavesTrimLoop(branch *ast.BranchStmt, insideNestedBreakable bool) bool {
	switch branch.Tok {
	case token.GOTO:
		// A goto can land anywhere in the function, including past the loop.
		return true
	case token.BREAK:
		// Labelled breaks are conservatively treated as escapes; an unlabelled break escapes only outside an inner breakable construct.
		return branch.Label != nil || !insideNestedBreakable
	case token.CONTINUE:
		// A bare continue stays in this loop or an inner loop, so it never skips this loop's next condition test.
		// A labelled one is treated as an escape without resolving which loop its label names.
		return branch.Label != nil
	default:
		// `fallthrough` stays inside its own switch clause.
		return false
	}
}

// trimLoopBodyEscapes reports whether a branch in subtree is conservatively treated as an escape before the trim loop's next condition test.
//
// It walks depth-aware because an unlabelled break changes meaning once it sits inside an inner breakable construct.
// A single flat scan cannot tell those two spellings apart.
//
// The subtree is the loop body, or an inner breakable construct on recursive calls, and is walked outside closures.
// insideNestedBreakable is true inside such an inner construct, where an unlabelled break ends that construct rather than the trim loop.
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

// lhsUsesAnyName reports whether an assignment writes the value shown at the user's request or redirect sink.
//
// A true result identifies a matching assignment target; callers decide whether that write invalidates their evidence.
// Each of leftHandValues, the assignment targets, counts when its root name, past field, index, pointer or parentheses, is in sinkValueNames.
// A target with no plain root, such as a field of a call result, never counts.
func lhsUsesAnyName(leftHandValues []ast.Expr, sinkValueNames map[string]bool) bool {
	// Check each result because net/url parsing commonly assigns both URL and error.
	for _, leftHandValue := range leftHandValues {
		// A matching root links the write to the sink value; writing a field, element or pointee changes the same value the guard checked.
		// So parsed.Host = ... matches exactly as reassigning parsed does.
		if rootName, hasRoot := assignedRootName(leftHandValue); hasRoot && sinkValueNames[rootName] {
			return true
		}
	}
	return false
}

// assignedRootName returns the identifier an assignment target writes through, stepping past selectors, indexes, and pointer dereferences.
//
// An index expression roots at the collection, so assigning into cache at index target reports cache rather than the target used to address it.
//
// The empty, false result means the write goes through something this parser-only rule cannot follow, such as a field of pick().
// That answer invalidates nothing, so an earlier guard keeps standing and the finding stays hidden: the losing direction for a security rule.
// It is a residual blind spot rather than a deliberate exemption, bounded to writes that do not root at a plain name.
//
// Roots are matched by spelling, so a shadowed variable with the same name is not told apart.
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

// collectParsedDestinationEvidence extracts rejecting scheme and host checks that explain why a URL is absent from the user's findings list.
//
// Only != comparisons in condition, alone or joined by ||, are read, and recordParsedDestinationComparison handles each one.
// Only a comparison of Scheme, Host or Hostname() on a local in parsedURLNames against a quoted literal updates evidenceByName.
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
//
// The comparison may put the string literal on either side; it must test a Scheme, Host or Hostname of a local in parsedURLNames.
// An http or https scheme or a non-empty host literal sets the matching flag on that local's entry in evidenceByName.
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

// parsedURLLiteralComparison returns one parsed field and its literal when the comparison belongs to the URL reaching the user's sink.
//
// The literalExpression must be a string or rune literal, and valueExpression a Scheme, Host or Hostname() read on a local in parsedURLNames.
// Otherwise the final bool is false and the local and field names are empty.
func parsedURLLiteralComparison(valueExpression, literalExpression ast.Expr, parsedURLNames map[string]bool) (string, string, string, bool) {
	allowedLiteral, hasLiteral := stringLiteral(literalExpression)
	// Dynamic values are not an explicit scheme or host allowlist.
	if !hasLiteral {
		return "", "", "", false
	}
	parsedURLName, fieldName, hasField := parsedURLField(valueExpression, parsedURLNames)
	return parsedURLName, fieldName, allowedLiteral, hasField
}

// parsedURLField recognises Scheme, Host, or Hostname checks on the parsed URL associated with the user's outbound destination.
//
// The valueExpression must read Scheme, Host or Hostname() on a plain identifier that parsedURLNames holds.
// It returns that identifier's name, the field as scheme or host, and true, or two empty strings and false for any other expression.
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

// identNameAndField validates that a selector belongs to the parsed URL whose destination would otherwise appear in the scan report.
//
// The isIdentifier flag says whether the selector base was an identifier at all, and identifier is that base, possibly nil.
// It returns the identifier's name with fieldName unchanged and true when parsedURLNames holds it, or two empty strings and false otherwise.
func identNameAndField(identifier *ast.Ident, fieldName string, parsedURLNames map[string]bool, isIdentifier bool) (string, string, bool) {
	// Nil, non-identifier, or unrelated selectors cannot validate this finding.
	if !isIdentifier || identifier == nil || !parsedURLNames[identifier.Name] {
		return "", "", false
	}
	return identifier.Name, fieldName, true
}

// blockEndsWithReturn requires a guard to stop the unsafe user destination before the scanner accepts its checks as protection.
//
// It returns true only when statementBlock is non-empty and its last statement is a return, and false for a nil or empty block.
func blockEndsWithReturn(statementBlock *ast.BlockStmt) bool {
	// An empty or absent block lets the request continue and cannot protect users.
	if statementBlock == nil || len(statementBlock.List) == 0 {
		return false
	}
	_, endsWithReturn := statementBlock.List[len(statementBlock.List)-1].(*ast.ReturnStmt)
	return endsWithReturn
}

// bodyHasCommittedRelativePrefix recognises an exiting HasPrefix guard with a literal starting / followed by neither / nor backslash.
//
// A negated strings.HasPrefix guard in functionBody must start before sinkPosition; the sink may be inside its rejecting body.
// Every region enclosing the guard must also contain the sink; jumps such as goto are not followed.
//
// The stringPackageAliases set names that package's import aliases, and the call's first argument must use one of sinkValueNames.
// It returns true when such a guard's literal is a safe relative prefix and no sink local's prefix is rewritten after it, and false otherwise.
func bodyHasCommittedRelativePrefix(functionBody *ast.BlockStmt, sinkValueNames, stringPackageAliases map[string]bool, sinkPosition token.Pos) bool {
	foundCommittedPrefix := false
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// Stop once the scan has user-visible evidence for this destination.
		if foundCommittedPrefix {
			return false
		}
		// Guards inside closures are ignored, even when they check the captured outer redirect.
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

// bodyStripsProtocolRelativePrefix accepts a matching slash-trimming loop as evidence for suppressing a redirect finding.
// A sink inside the loop body before trimming can qualify, even while its target still starts with //.
//
// A for loop in functionBody starting before sinkPosition must test HasPrefix of one of sinkValueNames against a double slash.
// Every region enclosing the loop must also contain the sink; jumps such as goto are not followed.
// Its body must contain a recognised top-level trim assignment made through stringPackageAliases.
//
// The requestScope decides whether an earlier backslash fold is also required, and that fold evidence is only an earlier matching assignment.
// No check here excludes an absolute URL: https://evil.example passes the loop unchanged and still counts as evidence.
//
// It returns true when such a loop qualifies and no sink local's prefix is rewritten after it, and false otherwise, keeping the finding.
func bodyStripsProtocolRelativePrefix(requestScope *requestTaintScope, functionBody *ast.BlockStmt, sinkValueNames, stringPackageAliases map[string]bool, sinkPosition token.Pos) bool {
	foundSafeLoop := false
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// One accepted loop is enough evidence to suppress this redirect finding, so later loops are not examined.
		if foundSafeLoop {
			return false
		}
		// Trim loops inside closures are ignored, even when the closure changes the outer redirect value.
		if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
			return false
		}
		prefixLoop, isForLoop := syntaxNode.(*ast.ForStmt)
		// Only a loop that runs before the redirect can change the value the redirect sends.
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
		// The fold guards the leading characters, so require it only where a
		// caller can actually place one there.
		backslashHandled := !requestControlsLeadingCharacters(requestScope, functionBody, redirectIdentifier.Name, prefixLoop.Pos()) ||
			bodyFoldsBackslashBefore(functionBody, redirectIdentifier.Name, stringPackageAliases, prefixLoop.Pos())
		foundSafeLoop = loopTrimsOneLeadingSlash(prefixLoop.Body, redirectIdentifier.Name, stringPackageAliases) &&
			backslashHandled &&
			!anyNamePrefixRewrittenBetween(functionBody, sinkValueNames, prefixLoop.End(), sinkPosition)
		return !foundSafeLoop
	})
	return foundSafeLoop
}

// requestControlsLeadingCharacters reports whether request-controlled data can reach the front of the redirect value before the trim loop runs.
//
// Appending ? plus RawQuery, as Caddy's file server does, cannot create a /\ authority; other appends are skipped even when they can create one.
// Seeding the value from the request, as in target := r.FormValue("next"), lets the caller own the first byte, so a fold is required.
//
// It walks functionBody outside closures for writes to redirectVariableName before loopPosition, where the trim loop starts, skipping appends.
// A write counts when requestScope treats any assigned value as a direct request expression.
// False means no backslash fold is required before the loop.
func requestControlsLeadingCharacters(requestScope *requestTaintScope, functionBody *ast.BlockStmt, redirectVariableName string, loopPosition token.Pos) bool {
	controlsLeadingCharacters := false
	redirectNames := map[string]bool{redirectVariableName: true}
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// Stop at the first write that seeds the value from the request.
		if controlsLeadingCharacters {
			return false
		}
		// Closures are outside this check, even one that captures and changes the outer redirect value.
		if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
			return false
		}
		switch statement := syntaxNode.(type) {
		case *ast.AssignStmt:
			// Only a write landing before the loop decides what it normalises.
			if statement.Pos() >= loopPosition || !lhsUsesAnyName(statement.Lhs, redirectNames) {
				return true
			}
			// Appends are skipped here, even when adding a backslash after a lone slash would create a /\ authority.
			if assignmentPreservesPrefix(statement, redirectNames) {
				return true
			}
			for _, assignedValue := range statement.Rhs {
				if requestScope.directRequestExpr(assignedValue) {
					controlsLeadingCharacters = true
				}
			}
		case *ast.ValueSpec:
			if statement.Pos() >= loopPosition {
				return true
			}
			for valueIndex, declaredName := range statement.Names {
				if !redirectNames[declaredName.Name] || valueIndex >= len(statement.Values) {
					continue
				}
				if requestScope.directRequestExpr(statement.Values[valueIndex]) {
					controlsLeadingCharacters = true
				}
			}
		}
		return !controlsLeadingCharacters
	})
	return controlsLeadingCharacters
}

// bodyFoldsBackslashBefore reports whether a matching strings replacement assignment appears before the trim loop.
//
// Browsers resolve \ as / in the authority position, so /\evil.example passes the loop untouched and still leaves the site.
// Folding first gives //evil.example for the loop to trim; a fold after the loop could restore // and does not count.
//
// It walks functionBody outside closures for an assignment back to redirectVariableName that ends before loopPosition, the trim loop's start.
// The assigned call must be a ReplaceAll, or a Replace whose count isNegativeIntLiteral accepts, made through stringPackageAliases.
// Any such earlier assignment counts, even one on an optional branch or one followed by another write before the loop.
func bodyFoldsBackslashBefore(functionBody *ast.BlockStmt, redirectVariableName string, stringPackageAliases map[string]bool, loopPosition token.Pos) bool {
	foldsBackslash := false
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// One matching earlier assignment satisfies the fold requirement, even when it sits on an optional branch.
		if foldsBackslash {
			return false
		}
		// A fold inside a closure is not counted, even one that captures the outer redirect value.
		if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
			return false
		}
		foldAssignment, isAssignment := syntaxNode.(*ast.AssignStmt)
		// Only a write that completes before the loop can normalise its input.
		if !isAssignment || foldAssignment.End() > loopPosition ||
			len(foldAssignment.Lhs) != 1 || len(foldAssignment.Rhs) != 1 {
			return true
		}
		foldTarget, hasTarget := foldAssignment.Lhs[0].(*ast.Ident)
		replaceCall, isCall := foldAssignment.Rhs[0].(*ast.CallExpr)
		// Only writing back to the checked value changes what the loop sees.
		if !hasTarget || foldTarget.Name != redirectVariableName || !isCall {
			return true
		}
		foldsBackslash = replaceCallFoldsBackslash(replaceCall, redirectVariableName, stringPackageAliases)
		return !foldsBackslash
	})
	return foldsBackslash
}

// replaceCallFoldsBackslash matches ReplaceAll calls and Replace calls whose count passes isNegativeIntLiteral, including forms such as -0x0.
//
// A bounded Replace leaves later backslashes in place, so it cannot stand in for either.
// A -0x0 count replaces nothing yet still counts as a fold, which can hide the finding.
//
// The replaceCall must go through stringPackageAliases, take redirectVariableName as its source, and replace a backslash with a slash.
// It returns true for such a ReplaceAll, or a Replace whose count isNegativeIntLiteral accepts, and false for any other call.
func replaceCallFoldsBackslash(replaceCall *ast.CallExpr, redirectVariableName string, stringPackageAliases map[string]bool) bool {
	replacesAll := selectorCallMatches(replaceCall, stringPackageAliases, "ReplaceAll") && len(replaceCall.Args) == 3
	replacesCounted := selectorCallMatches(replaceCall, stringPackageAliases, "Replace") && len(replaceCall.Args) == 4
	if !replacesAll && !replacesCounted {
		return false
	}
	if replacesCounted && !isNegativeIntLiteral(replaceCall.Args[3]) {
		return false
	}
	foldSource, hasSource := replaceCall.Args[0].(*ast.Ident)
	replacedValue, hasReplaced := stringLiteral(replaceCall.Args[1])
	replacementValue, hasReplacement := stringLiteral(replaceCall.Args[2])
	// The fold must read the same value it writes, turning `\` into `/`.
	return hasSource && foldSource.Name == redirectVariableName &&
		hasReplaced && replacedValue == `\` && hasReplacement && replacementValue == "/"
}

// isNegativeIntLiteral reports whether an expression has unary-minus integer syntax accepted for a strings.Replace count.
//
// Parentheses around countExpression and its operand are skipped; a minus on any integer literal whose text is not 0, even 0x0, gives true.
// The intent is the -1 that makes strings.Replace unbounded, but a zero-valued spelling such as -0x0 or -00 also passes.
func isNegativeIntLiteral(countExpression ast.Expr) bool {
	negation, isNegation := unwrapRequestExprParens(countExpression).(*ast.UnaryExpr)
	if !isNegation || negation.Op != token.SUB {
		return false
	}
	countLiteral, isLiteral := unwrapRequestExprParens(negation.X).(*ast.BasicLit)
	return isLiteral && countLiteral.Kind == token.INT && countLiteral.Value != "0"
}

// loopTrimsOneLeadingSlash recognises a top-level strings.TrimPrefix assignment in a loop body with no rejected branch statements.
//
// The loopBody is rejected for any goto, any labelled break or continue, and any unlabelled break not inside an inner breakable construct.
// A top-level assignment to redirectVariableName must call TrimPrefix on itself and a slash through stringPackageAliases; += also counts.
// Finding that assignment does not prove it runs on every pass: an unlabelled continue placed before it is accepted.
//
// It returns true when the body is not rejected and has that assignment, and false otherwise.
func loopTrimsOneLeadingSlash(loopBody *ast.BlockStmt, redirectVariableName string, stringPackageAliases map[string]bool) bool {
	// An escaping break, goto, or labelled continue in this loop can reach the sink while the value still begins with //, so the proof is rejected.
	//
	// This parser-only rule does not approximate branch reachability, and a continue labelled for this same loop would in fact be safe.
	// The label is not resolved here, and over-rejecting only costs a visible finding.
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
		// Trimming exactly one slash per pass makes progress, and the loop condition decides when no // remains.
		if hasInput && trimmedIdentifier.Name == redirectVariableName && hasLiteral && trimmedPrefix == "/" {
			return true
		}
	}
	return false
}
