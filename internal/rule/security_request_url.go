// Package rule defines gruff-go's rule registry and analysers.
// This file implements parser-only SSRF and open-redirect checks that trace
// request-controlled values into net/http URL and redirect sinks.
package rule

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// destinationSanitizerTokens are exact identifier tokens that affirmatively name
// a destination allowlist or validator. Syntax parsers are intentionally absent.
var destinationSanitizerTokens = map[string]bool{
	"allow": true, "allowed": true, "allowlist": true, "whitelist": true,
	"validate": true, "validated": true, "validation": true, "validator": true,
	"verify": true, "verified": true, "verification": true, "verifier": true,
	"sanitize": true, "sanitized": true, "sanitizer": true,
	"sanitise": true, "sanitised": true, "sanitiser": true,
	"permit": true, "permitted": true, "trust": true, "trusted": true,
}

// redirectDestinationTokens extend affirmative validation with exact local or
// relative-target terminology. A generic prefix operation is not sufficient.
var redirectDestinationTokens = map[string]bool{"local": true, "relative": true}

// RequestControlledURLRule flags request-derived values used as the URL of an
// outbound HTTP request without allowlist or validation evidence.
// Use its finding when reviewing whether a UI-submitted URL can reach net/http.
type RequestControlledURLRule struct{}

// Definition provides the request-URL metadata shown in scan output.
// The UI uses it to explain the risk and the trusted-destination fix.
func (RequestControlledURLRule) Definition() Definition {
	return Definition{
		ID:             "security.request-controlled-url",
		Title:          "Request-controlled request URL",
		Description:    "Flags request-derived values passed as the URL of an outbound net/http request without an affirmative destination allowlist or validation check (possible SSRF). Uses bounded same-function evidence and candidate wording.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"http", "security", "ssrf"},
		Remediation:    "Validate request-derived URLs against an allowlist of trusted hosts, or build the request URL from a fixed base before fetching.",
	}
}

// AnalyzeUnit finds request-controlled URLs that reach HTTP client sinks.
// Run it to populate the user's report with unconstrained outbound destinations.
func (RequestControlledURLRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	// A user sees no URL findings for unparsed, non-production, or test-only input.
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	httpPackageAliases := packageImportNames(unit.AST, "net/http", "http")
	// Without net/http, this file cannot send the request shown in this rule's UI.
	if len(httpPackageAliases) == 0 {
		return nil
	}
	scanFindings := []finding.Finding{}
	// Review each handler separately so the report cites the user's exact sink.
	forEachRequestFunc(unit.AST, httpPackageAliases, func(requestScope *requestTaintScope, functionBody *ast.BlockStmt) {
		httpClientVariables := collectHTTPClientVars(functionBody, httpPackageAliases)
		ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
			// Nested callbacks are analysed as their own request handlers.
			if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
				return false
			}
			candidateCall, isCall := syntaxNode.(*ast.CallExpr)
			// Non-call syntax cannot be an outbound request shown to the user.
			if !isCall {
				return true
			}
			urlArgumentIndex, sinkLabel, isHTTPSink := httpClientURLArg(candidateCall, httpPackageAliases, httpClientVariables)
			// Ignore calls that do not expose a valid net/http URL argument.
			if !isHTTPSink || urlArgumentIndex >= len(candidateCall.Args) {
				return true
			}
			urlArgument := candidateCall.Args[urlArgumentIndex]
			requestSource, isRequestControlled := requestScope.exprHasRequest(urlArgument, candidateCall.Pos())
			// Fixed or internal destinations stay out of the user's findings list.
			if !isRequestControlled {
				return true
			}
			// An affirmative destination guard makes this request safe to omit.
			if destinationHasConstraint(requestScope, functionBody, urlArgument, destinationConstraintOptions{}, candidateCall.Pos()) {
				return true
			}
			sinkPosition := unit.FileSet.Position(candidateCall.Pos())
			scanFindings = append(scanFindings, finding.Finding{
				Message:  "request-controlled value used as HTTP request URL without allowlist or validation (possible SSRF)",
				File:     unit.File.Path,
				Location: &finding.Location{Line: sinkPosition.Line, Column: sinkPosition.Column},
				Metadata: map[string]any{"sink": sinkLabel, "source": requestSource},
			})
			return true
		})
	})
	return scanFindings
}

// OpenRedirectRule flags request-derived values used as a redirect destination
// without validation that the target is safe.
// Use its finding when a submitted next-page value can steer the user's browser.
type OpenRedirectRule struct{}

// Definition provides the open-redirect metadata shown in scan output.
// The UI uses it to explain when a submitted destination can steer the browser.
func (OpenRedirectRule) Definition() Definition {
	return Definition{
		ID:             "security.open-redirect-candidate",
		Title:          "Open redirect candidate",
		Description:    "Flags request-derived values passed to http.Redirect or a Location header without a nearby allowlist or validation check (possible open redirect). Uses bounded same-function evidence and candidate wording.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"http", "redirect", "security"},
		Remediation:    "Validate redirect targets against an allowlist or require a relative path before redirecting request-derived destinations.",
	}
}

// AnalyzeUnit finds request-controlled redirect destinations without safeguards.
// Run it to populate the user's report with redirects that may leave the site.
func (OpenRedirectRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	// A user sees no redirect findings for unparsed, non-production, or test input.
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	httpPackageAliases := packageImportNames(unit.AST, "net/http", "http")
	// Without net/http, this file cannot emit the redirect represented by the rule.
	if len(httpPackageAliases) == 0 {
		return nil
	}
	stringsPackageAliases := packageImportNames(unit.AST, "strings", "strings")
	scanFindings := []finding.Finding{}
	// Review each handler separately so UI locations stay tied to one response.
	forEachRequestFunc(unit.AST, httpPackageAliases, func(requestScope *requestTaintScope, functionBody *ast.BlockStmt) {
		ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
			// Nested callbacks are analysed independently with their own request input.
			if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
				return false
			}
			candidateCall, isCall := syntaxNode.(*ast.CallExpr)
			// Non-call syntax cannot set the redirect shown in the scan report.
			if !isCall {
				return true
			}
			redirectTarget, sinkLabel, isRedirectSink := redirectTargetArg(candidateCall, httpPackageAliases, functionBody)
			// Ignore calls that do not control an HTTP redirect destination.
			if !isRedirectSink {
				return true
			}
			requestSource, isRequestControlled := requestScope.exprHasRequest(redirectTarget, candidateCall.Pos())
			// Fixed destinations do not create an open-redirect warning for the user.
			if !isRequestControlled {
				return true
			}
			fixedPrefix, hasFixedPrefix := leftmostStringLiteral(redirectTarget)
			// A literal path segment keeps any appended user value on the same host.
			if hasFixedPrefix && isSafeRelativePrefix(fixedPrefix) {
				return true
			}
			constraintOptions := destinationConstraintOptions{additionalValidatorTokens: redirectDestinationTokens, stringPackageAliases: stringsPackageAliases}
			// Robust validation or normalization makes the redirect safe to omit.
			if destinationHasConstraint(requestScope, functionBody, redirectTarget, constraintOptions, candidateCall.Pos()) {
				return true
			}
			sinkPosition := unit.FileSet.Position(candidateCall.Pos())
			scanFindings = append(scanFindings, finding.Finding{
				Message:  "request-controlled value used as redirect target without validation (possible open redirect)",
				File:     unit.File.Path,
				Location: &finding.Location{Line: sinkPosition.Line, Column: sinkPosition.Column},
				Metadata: map[string]any{"sink": sinkLabel, "source": requestSource},
			})
			return true
		})
	})
	return scanFindings
}

// redirectTargetArg returns the destination and UI sink label for a redirect call.
// Use it to keep http.Redirect and Location-header findings consistent.
func redirectTargetArg(candidateCall *ast.CallExpr, httpPackageAliases map[string]bool, functionBody *ast.BlockStmt) (ast.Expr, string, bool) {
	// A standard redirect exposes its destination as the third argument in reports.
	if selectorCallMatches(candidateCall, httpPackageAliases, "Redirect") && len(candidateCall.Args) >= 4 {
		return candidateCall.Args[2], "http.Redirect", true
	}
	methodSelector, isSelector := candidateCall.Fun.(*ast.SelectorExpr)
	// Only a two-argument Set call can write a Location response header.
	if !isSelector || methodSelector.Sel.Name != "Set" || len(candidateCall.Args) != 2 {
		return nil, "", false
	}
	// Request or unrelated headers do not redirect the user's browser.
	if !isHeaderMethodCallReceiver(methodSelector.X) {
		return nil, "", false
	}
	headerName, hasLiteralHeader := stringLiteral(candidateCall.Args[0])
	// A dynamic or non-Location header is not an open-redirect sink.
	if !hasLiteralHeader || !isLocationHeader(headerName) {
		return nil, "", false
	}
	// Location is also valid metadata on non-redirect responses (for example
	// 201 Created). Only a matching later redirect status makes it a browser sink.
	if !locationHeaderHasRedirectStatus(functionBody, candidateCall, httpPackageAliases) {
		return nil, "", false
	}
	return candidateCall.Args[1], "Header.Set(Location)", true
}

// isHeaderMethodCallReceiver recognises `<x>.Header()` response access.
// It keeps request-header writes out of the user's redirect findings.
func isHeaderMethodCallReceiver(headerAccessorExpression ast.Expr) bool {
	headerAccessorCall, isCall := headerAccessorExpression.(*ast.CallExpr)
	// The browser response header accessor has no arguments.
	if !isCall || len(headerAccessorCall.Args) != 0 {
		return false
	}
	methodSelector, isSelector := headerAccessorCall.Fun.(*ast.SelectorExpr)
	return isSelector && methodSelector.Sel.Name == "Header"
}

// isLocationHeader reports whether a header name targets the redirect Location
// header, ignoring case as net/http canonicalises header keys.
func isLocationHeader(headerName string) bool {
	return equalFoldASCII(headerName, "Location")
}

// equalFoldASCII reports case-insensitive equality for ASCII header names without
// pulling in Unicode folding.
func equalFoldASCII(leftValue, rightValue string) bool {
	// Different lengths cannot name the same response header.
	if len(leftValue) != len(rightValue) {
		return false
	}
	// Compare each byte because HTTP header names are ASCII in this scanner.
	for characterIndex := 0; characterIndex < len(leftValue); characterIndex++ {
		leftCharacter, rightCharacter := leftValue[characterIndex], rightValue[characterIndex]
		// Normalize uppercase input a user may write in source.
		if 'A' <= leftCharacter && leftCharacter <= 'Z' {
			leftCharacter += 'a' - 'A'
		}
		// Normalize the expected header name the same way.
		if 'A' <= rightCharacter && rightCharacter <= 'Z' {
			rightCharacter += 'a' - 'A'
		}
		// One differing character means the call will not redirect the browser.
		if leftCharacter != rightCharacter {
			return false
		}
	}
	return true
}

// leftmostStringLiteral returns the value of the left-most string literal in a
// + concatenation, used to inspect the fixed prefix of a constructed target.
func leftmostStringLiteral(targetExpression ast.Expr) (string, bool) {
	switch targetSyntax := targetExpression.(type) {
	case *ast.ParenExpr:
		return leftmostStringLiteral(targetSyntax.X)
	case *ast.BinaryExpr:
		// A concatenated target inherits its user-visible prefix from the left side.
		if targetSyntax.Op == token.ADD {
			return leftmostStringLiteral(targetSyntax.X)
		}
	case *ast.BasicLit:
		return stringLiteral(targetSyntax)
	}
	return "", false
}

// isSafeRelativePrefix requires a literal path segment before submitted text.
// A bare slash is unsafe because a user can extend it into `//external-host`.
func isSafeRelativePrefix(fixedPrefix string) bool {
	// Empty, bare-slash, and absolute inputs can still become external redirects.
	if len(fixedPrefix) < 2 || fixedPrefix[0] != '/' {
		return false
	}
	return fixedPrefix[1] != '/' && fixedPrefix[1] != '\\'
}

// destinationConstraintOptions adds redirect-only evidence to the shared URL policy.
// Request scans leave both maps empty; redirect scans provide relative tokens
// and strings aliases so the user sees only destinations lacking real guards.
type destinationConstraintOptions struct {
	additionalValidatorTokens map[string]bool
	stringPackageAliases      map[string]bool
}

// destinationHasConstraint reports an exact validator token, parsed scheme+host
// allowlist, or redirect guard requiring a committed relative-path segment.
func destinationHasConstraint(requestScope *requestTaintScope, functionBody *ast.BlockStmt, sinkArgument ast.Expr, constraintOptions destinationConstraintOptions, sinkPosition token.Pos) bool {
	// An inline validator explains why the destination is absent from the report.
	if argHasDestinationSanitizer(requestScope, sinkArgument, constraintOptions.additionalValidatorTokens) {
		return true
	}
	sinkValueNames := requestScope.sanitizerValueNames(sinkArgument)
	// An earlier exact-named validator can protect a named sink value.
	if bodyHasDestinationSanitizer(functionBody, sinkValueNames, constraintOptions.additionalValidatorTokens, sinkPosition) {
		return true
	}
	// Explicit scheme and host guards provide structural destination evidence.
	if bodyHasParsedDestinationAllowlist(requestScope, functionBody, sinkValueNames, sinkPosition) {
		return true
	}
	// Redirect scans accept only structural same-origin evidence from strings helpers.
	if len(constraintOptions.stringPackageAliases) > 0 {
		return bodyHasCommittedRelativePrefix(functionBody, sinkValueNames, constraintOptions.stringPackageAliases, sinkPosition) ||
			bodyStripsProtocolRelativePrefix(functionBody, sinkValueNames, constraintOptions.stringPackageAliases, sinkPosition)
	}
	return false
}

// argHasDestinationSanitizer recognises an exact validator token whose complete
// result is passed to the sink. A sanitizer nested beside raw request input does
// not constrain the final destination expression.
func argHasDestinationSanitizer(requestScope *requestTaintScope, sinkArgument ast.Expr, additionalValidatorTokens map[string]bool) bool {
	candidateCall, isCall := unwrapRequestExprParens(sinkArgument).(*ast.CallExpr)
	if !isCall || !callHasDestinationToken(candidateCall, additionalValidatorTokens) {
		return false
	}
	_, containsRequestInput := requestScope.exprHasRequest(candidateCall, token.NoPos)
	return containsRequestInput
}

// bodyHasDestinationSanitizer recognises a validator call before the sink only
// when its call name contains a complete approved identifier token.
func bodyHasDestinationSanitizer(functionBody *ast.BlockStmt, sinkValueNames, additionalValidatorTokens map[string]bool, sinkPosition token.Pos) bool {
	// Inline request expressions have no local name for a separate validator call.
	if len(sinkValueNames) == 0 {
		return false
	}
	foundBodySanitizer := false
	ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
		// Stop once the scan has an affirmative reason to omit the finding.
		if foundBodySanitizer {
			return false
		}
		// A nested callback cannot validate the outer user's destination.
		if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
			return false
		}
		candidateCall, isCall := syntaxNode.(*ast.CallExpr)
		// Later or non-validator calls cannot protect the sink already reported.
		if !isCall || candidateCall.Pos() >= sinkPosition || !callHasDestinationToken(candidateCall, additionalValidatorTokens) {
			return true
		}
		// The validator must reference the exact value used by the outbound action,
		// control whether the sink is reachable, and remain valid for that value.
		if nodeUsesAnyIdent(candidateCall, sinkValueNames) &&
			!anyNameAssignedBetween(functionBody, sinkValueNames, candidateCall.End(), sinkPosition) &&
			validatorCallProtectsSink(functionBody, candidateCall, sinkPosition) {
			foundBodySanitizer = true
		}
		return !foundBodySanitizer
	})
	return foundBodySanitizer
}

// validatorCallProtectsSink recognises the two affirmative control-flow forms:
// a rejecting guard whose false path reaches a later sink, or a positive guard
// whose true body contains the sink.
func validatorCallProtectsSink(functionBody *ast.BlockStmt, validatorCall *ast.CallExpr, sinkPosition token.Pos) bool {
	protected := false
	ast.Inspect(functionBody, func(node ast.Node) bool {
		if protected {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		guard, ok := node.(*ast.IfStmt)
		if !ok || !exprContainsExactCall(guard.Cond, validatorCall) {
			return true
		}
		if guard.Body.Pos() < sinkPosition && sinkPosition < guard.Body.End() &&
			conditionOutcomeImpliesValidator(guard.Cond, validatorCall, true) {
			protected = true
			return false
		}
		if guard.End() < sinkPosition && blockEndsWithReturn(guard.Body) &&
			conditionOutcomeImpliesValidator(guard.Cond, validatorCall, false) {
			protected = true
			return false
		}
		return true
	})
	return protected
}

// conditionOutcomeImpliesValidator reports whether observing one boolean result
// proves that validatorCall itself returned true. It preserves AND/OR semantics
// instead of counting a call merely because it appears somewhere in a condition.
func conditionOutcomeImpliesValidator(condition ast.Expr, validatorCall *ast.CallExpr, outcome bool) bool {
	condition = unwrapRequestExprParens(condition)
	if condition == validatorCall {
		return outcome
	}
	switch expression := condition.(type) {
	case *ast.UnaryExpr:
		if expression.Op == token.NOT {
			return conditionOutcomeImpliesValidator(expression.X, validatorCall, !outcome)
		}
	case *ast.BinaryExpr:
		switch expression.Op {
		case token.LAND:
			if outcome {
				return conditionOutcomeImpliesValidator(expression.X, validatorCall, true) ||
					conditionOutcomeImpliesValidator(expression.Y, validatorCall, true)
			}
			return conditionOutcomeImpliesValidator(expression.X, validatorCall, false) &&
				conditionOutcomeImpliesValidator(expression.Y, validatorCall, false)
		case token.LOR:
			if outcome {
				return conditionOutcomeImpliesValidator(expression.X, validatorCall, true) &&
					conditionOutcomeImpliesValidator(expression.Y, validatorCall, true)
			}
			return conditionOutcomeImpliesValidator(expression.X, validatorCall, false) ||
				conditionOutcomeImpliesValidator(expression.Y, validatorCall, false)
		}
	}
	return false
}

// exprContainsExactCall reports whether the condition contains this AST call,
// not merely another call with the same text or name.
func exprContainsExactCall(expression ast.Expr, targetCall *ast.CallExpr) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		if node == targetCall {
			found = true
			return false
		}
		return !found
	})
	return found
}

// callHasDestinationToken uses complete camel/snake-case tokens so names such
// as parser, allowance, disallow, untrusted, and sanitation cannot collide.
func callHasDestinationToken(candidateCall *ast.CallExpr, additionalValidatorTokens map[string]bool) bool {
	callNameTokens := splitIdentifierTokens(callName(candidateCall))
	// Inspect complete tokens so UI labels never trust a substring collision.
	for tokenIndex, identifierToken := range callNameTokens {
		identifierToken = strings.ToLower(identifierToken)
		// Negated names such as notTrusted remain visible findings for the user.
		if (destinationSanitizerTokens[identifierToken] || additionalValidatorTokens[identifierToken]) && !precededByDestinationNegation(callNameTokens, tokenIndex) {
			return true
		}
	}
	return false
}
