// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements parser-only SSRF and open-redirect checks that trace request-controlled values into net/http URL and redirect sinks.
// Guard evidence is recognised from syntax alone: it suppresses a candidate without proving the destination was really validated.
package rule

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// destinationSanitizerTokens are exact identifier tokens that affirmatively name a destination allowlist or validator.
//
// A call whose name holds one of these tokens, such as validateURL, counts as guard evidence and can hide a finding.
// The validator's body is never read, so a validator that accepts everything still suppresses; syntax parsers are intentionally absent.
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

// RequestControlledURLRule flags request-derived values used as the URL of an outbound HTTP request without allowlist or validation evidence.
//
// It reports as security.request-controlled-url, on by default; review each finding for a submitted URL that can reach net/http.
// Recognised guard syntax suppresses a candidate, but validator behaviour is not inspected, so a quiet scan is not proof against SSRF.
type RequestControlledURLRule struct{}

// Definition provides the request-URL metadata shown in scan output, explaining the SSRF risk and the trusted-destination fix.
// It returns the default-enabled, advisory, medium-confidence security.request-controlled-url definition with its SSRF wording and fix.
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

// AnalyzeUnit finds request-controlled URLs that reach HTTP client sinks, filling the user's report with unconstrained outbound destinations.
//
// Only functions and closures that declare a named http.Request pointer parameter are scanned.
// A nested closure is scanned only when it declares such a parameter itself, so a sink in one that captures the outer request is missed.
//
// It returns one finding, with sink and source metadata, per HTTP client sink whose request-controlled URL lacks recognised guard syntax.
// With no such sink it gives an empty slice; guard evidence is syntactic, so a validator is trusted by name and placement, not by its body.
//
// It returns nil when unit has no AST or FileSet, isProductionCodePath rejects its path, or the file does not import net/http.
func (RequestControlledURLRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	// A user sees no URL findings for unparsed, non-production, or test-only input.
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	httpPackageAliases := packageImportNames(unit.AST, "net/http", "http")
	// A file without a net/http import gets no findings, even when it fetches URLs through another HTTP library.
	if len(httpPackageAliases) == 0 {
		return nil
	}
	scanFindings := []finding.Finding{}
	// Review each handler separately so the report cites the user's exact sink.
	forEachRequestFunc(unit.AST, httpPackageAliases, func(requestScope *requestTaintScope, functionBody *ast.BlockStmt) {
		httpClientBindings := collectHTTPClientBindings(requestScope.functionType, functionBody, httpPackageAliases)
		ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
			// Skip nested closures here; only those declaring their own named request parameter receive a separate scan.
			if _, isNestedFunction := syntaxNode.(*ast.FuncLit); isNestedFunction {
				return false
			}
			candidateCall, isCall := syntaxNode.(*ast.CallExpr)
			// Non-call syntax cannot be an outbound request shown to the user.
			if !isCall {
				return true
			}
			urlArgumentIndex, sinkLabel, isHTTPSink := httpClientURLArg(candidateCall, httpPackageAliases, httpClientBindings)
			// Ignore calls that do not expose a valid net/http URL argument.
			if !isHTTPSink || urlArgumentIndex >= len(candidateCall.Args) {
				return true
			}
			urlArgument := candidateCall.Args[urlArgumentIndex]
			requestSource, isRequestControlled := requestScope.exprHasRequest(urlArgument, candidateCall.Pos())
			// A destination with no traced request input produces no URL finding; an internal host alone does not suppress it.
			if !isRequestControlled {
				return true
			}
			// Recognised destination-guard syntax suppresses this candidate; validator behaviour is not inspected.
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

// OpenRedirectRule flags request-derived values used as a redirect destination without validation that the target is safe.
//
// It reports as security.open-redirect-candidate, off by default; a finding marks a submitted value that can steer a visitor's browser.
// Recognised guard syntax suppresses a candidate, but validator behaviour is not inspected, so a quiet scan is not proof of a safe redirect.
type OpenRedirectRule struct{}

// Definition provides the open-redirect metadata shown in scan output, explaining when a submitted destination can steer the browser.
// It returns the advisory, medium-confidence security.open-redirect-candidate definition, disabled by default, with its wording and fix.
func (OpenRedirectRule) Definition() Definition {
	return Definition{
		ID:             "security.open-redirect-candidate",
		Title:          "Open redirect candidate",
		Description:    "Flags request-derived values passed to http.Redirect or a Location header without a nearby allowlist or validation check (possible open redirect). Uses bounded same-function evidence and candidate wording.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: false,
		Tags:           []string{"http", "redirect", "security"},
		Remediation:    "Validate redirect targets against an allowlist or require a relative path before redirecting request-derived destinations.",
	}
}

// AnalyzeUnit reports request-controlled redirect destinations without recognised guards, which may send a visitor off the site.
//
// Only functions and closures that declare a named http.Request pointer parameter are scanned.
// A nested closure is scanned only when it declares such a parameter itself, so a sink in one that captures the outer request is missed.
//
// It returns one finding, with sink and source metadata, per http.Redirect or Location-header sink whose target is request-controlled.
// A target is skipped when it is a recognised HTTPS upgrade, starts with a safe relative prefix, or has recognised guard syntax.
// With no such sink it gives an empty slice; guard evidence is syntactic, so a validator is trusted by name and placement, not by its body.
//
// It returns nil when unit has no AST or FileSet, isProductionCodePath rejects its path, or the file does not import net/http.
func (OpenRedirectRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	// A user sees no redirect findings for unparsed, non-production, or test input.
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	httpPackageAliases := packageImportNames(unit.AST, "net/http", "http")
	// A file with no net/http import of its own is skipped, even when it redirects through writer types declared in another file.
	if len(httpPackageAliases) == 0 {
		return nil
	}
	stringsPackageAliases := packageImportNames(unit.AST, "strings", "strings")
	scanFindings := []finding.Finding{}
	// Review each handler separately so each reported location stays tied to one response.
	forEachRequestFunc(unit.AST, httpPackageAliases, func(requestScope *requestTaintScope, functionBody *ast.BlockStmt) {
		ast.Inspect(functionBody, func(syntaxNode ast.Node) bool {
			// Skip nested closures here; only those declaring their own named request parameter receive a separate scan.
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
			// An HTTPS upgrade of this request's host does not accept a new destination.
			if redirectIsHTTPSUpgrade(unit.AST, requestScope, redirectTarget, candidateCall.Pos()) {
				return true
			}
			fixedPrefix, hasFixedPrefix := leftmostStringLiteral(redirectTarget)
			// A literal path segment keeps any appended user value on the same host.
			if hasFixedPrefix && isSafeRelativePrefix(fixedPrefix) {
				return true
			}
			constraintOptions := destinationConstraintOptions{additionalValidatorTokens: redirectDestinationTokens, stringPackageAliases: stringsPackageAliases}
			// Recognised destination-guard syntax suppresses this candidate; validator behaviour is not inspected.
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

// redirectTargetArg returns the destination and sink label for a redirect call, so http.Redirect and Location-header findings read alike.
//
// candidateCall is the call under test, httpPackageAliases the local names of net/http, and functionBody is searched for a later WriteHeader.
// A Location write qualifies only when a later WriteHeader on the same writer may share its control path and has a redirect or unresolved status.
// It reports false with a nil destination and an empty label when no supported sink matches.
func redirectTargetArg(candidateCall *ast.CallExpr, httpPackageAliases map[string]bool, functionBody *ast.BlockStmt) (ast.Expr, string, bool) {
	// A standard redirect exposes its destination as the third argument in reports.
	if selectorCallMatches(candidateCall, httpPackageAliases, "Redirect") && len(candidateCall.Args) >= 4 {
		return candidateCall.Args[2], "http.Redirect", true
	}
	methodSelector, isSelector := candidateCall.Fun.(*ast.SelectorExpr)
	// Only two-argument Set calls are recognised as Location-header sinks here; Header.Add and direct map writes are missed.
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
	// Location is also valid metadata on non-redirect responses, for example 201 Created.
	// A later WriteHeader on the same writer keeps this a redirect candidate when its status is a redirect or cannot be resolved.
	if !locationHeaderHasRedirectStatus(functionBody, candidateCall, httpPackageAliases) {
		return nil, "", false
	}
	return candidateCall.Args[1], "Header.Set(Location)", true
}

// isHeaderMethodCallReceiver recognises x.Header() response access, which keeps request-header writes out of redirect findings.
// It reports true only when headerAccessorExpression is a no-argument call of a method named Header, and false otherwise.
func isHeaderMethodCallReceiver(headerAccessorExpression ast.Expr) bool {
	headerAccessorCall, isCall := headerAccessorExpression.(*ast.CallExpr)
	// The browser response header accessor has no arguments.
	if !isCall || len(headerAccessorCall.Args) != 0 {
		return false
	}
	methodSelector, isSelector := headerAccessorCall.Fun.(*ast.SelectorExpr)
	return isSelector && methodSelector.Sel.Name == "Header"
}

// isLocationHeader reports whether headerName targets the redirect Location header, ignoring case as net/http canonicalises header keys.
// headerName is compared to Location with equalFoldASCII, so only a case-insensitive exact match counts.
func isLocationHeader(headerName string) bool {
	return equalFoldASCII(headerName, "Location")
}

// equalFoldASCII reports case-insensitive equality for ASCII header names without pulling in Unicode folding.
// leftValue and rightValue match when they have the same byte length and agree byte by byte after the letters A to Z are lowercased.
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

// leftmostStringLiteral returns the text of the leftmost literal in a + concatenation, the fixed prefix of a constructed redirect target.
//
// targetExpression is followed through parentheses and the left operand of each +; a leftmost string or rune literal gives its unquoted value.
// Any other shape, including a number literal or a non-addition operator, gives an empty string and false.
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

// redirectIsHTTPSUpgrade accepts only a fixed HTTPS scheme, the current request's host, and its escaped request URI.
//
// Submitted host or path values stay candidates, and a write to the request before the sink keeps the finding.
// Writes made inside a closure, a called function or through another name for the request are not seen.
//
// target is traced through one unchanged local assignment made before sinkPosition; scope supplies the request names and handler body.
// file supplies the net import names a host-preserving helper must call, and sinkPosition ends the check for writes to the request.
// It reports true only for that exact upgrade shape, and false for any other target.
func redirectIsHTTPSUpgrade(file *ast.File, scope *requestTaintScope, target ast.Expr, sinkPosition token.Pos) bool {
	target = redirectAssignedTarget(scope.body, target, sinkPosition)
	host, uri := redirectHTTPSParts(target)
	uriCall, ok := uri.(*ast.CallExpr)
	if !ok || len(uriCall.Args) != 0 {
		return false
	}
	request, members := flattenChain(uriCall.Fun)
	if !scope.isRequestIdentifier(request) || strings.Join(members, ".") != "URL.RequestURI" {
		return false
	}
	if helper, ok := host.(*ast.CallExpr); ok {
		if len(helper.Args) != 1 || !redirectHelperPreservesHost(file, helper) {
			return false
		}
		host = helper.Args[0]
	}
	hostRequest, hostMembers := flattenChain(host)
	return identifiersShareBinding(request, hostRequest) && strings.Join(hostMembers, ".") == "Host" &&
		!anyNameAssignedBetween(scope.body, map[string]bool{request.Name: true}, scope.body.Pos(), sinkPosition)
}

// redirectAssignedTarget follows one unchanged local assignment, so a target built earlier in the handler is judged by its assigned value.
//
// Reassignment keeps the finding because the original destination no longer proves the sink.
// It returns target without parentheses, or the assigned value when target is a resolved identifier.
// It returns nil when that declaration is not an assignment ending before sinkPosition, or the name is reassigned in body before the sink.
//
// It also returns nil when replacementValueFor finds no assigned value; in redirectIsHTTPSUpgrade a nil target keeps the redirect a candidate.
func redirectAssignedTarget(body *ast.BlockStmt, target ast.Expr, sinkPosition token.Pos) ast.Expr {
	target = unwrapRequestExprParens(target)
	if identifier, ok := target.(*ast.Ident); ok && identifier.Obj != nil {
		assignment, ok := identifier.Obj.Decl.(*ast.AssignStmt)
		if !ok || assignment.End() >= sinkPosition ||
			anyNameAssignedBetween(body, map[string]bool{identifier.Name: true}, assignment.End(), sinkPosition) {
			return nil
		}
		var assigned bool
		target, assigned = replacementValueFor(assignment, identifier.Obj)
		if !assigned {
			return nil
		}
	}
	return target
}

// redirectHTTPSParts separates an exact three-part HTTPS target; extra inputs could change the destination, so they are never recognised.
// It returns the host and URI operands, without parentheses, of a target built as "https://" + host + URI, and two nils for any other shape.
func redirectHTTPSParts(target ast.Expr) (ast.Expr, ast.Expr) {
	outer, ok := unwrapRequestExprParens(target).(*ast.BinaryExpr)
	if !ok || outer.Op != token.ADD {
		return nil, nil
	}
	prefix, ok := unwrapRequestExprParens(outer.X).(*ast.BinaryExpr)
	if !ok || prefix.Op != token.ADD {
		return nil, nil
	}
	scheme, literal := stringLiteral(prefix.X)
	if !literal || scheme != "https://" {
		return nil, nil
	}
	return unwrapRequestExprParens(prefix.Y), unwrapRequestExprParens(outer.Y)
}

// redirectHelperPreservesHost recognises the observed SplitHostPort and JoinHostPort helper by its complete body, never by its name.
//
// call must name a receiverless function in this file with one parameter and a three-statement body; file gives the net import names.
// It reports true only when those statements split the host, return the parameter on a split error, and join the host with port 443.
func redirectHelperPreservesHost(file *ast.File, call *ast.CallExpr) bool {
	name, ok := call.Fun.(*ast.Ident)
	if !ok || name.Obj == nil {
		return false
	}
	function, ok := name.Obj.Decl.(*ast.FuncDecl)
	if !ok || function.Recv != nil || function.Body == nil || len(function.Body.List) != 3 ||
		function.Type.Params == nil || len(function.Type.Params.List) != 1 || len(function.Type.Params.List[0].Names) != 1 {
		return false
	}
	netPackages := packageImportNames(file, "net", "net")
	parameter, host, errName, ok := redirectSplitHostPort(function, netPackages)
	return ok && redirectPortFallback(function.Body.List[1], parameter, errName) &&
		redirectJoinedHost(function.Body.List[2], host, netPackages)
}

// redirectSplitHostPort ties the helper's host to net.SplitHostPort's host and error results, so no other input inherits the exemption.
//
// function must already have one named parameter and a non-empty body, as redirectHelperPreservesHost checks before calling.
// netPackages holds the local names of the net import; success gives the parameter, host and error identifiers with true.
// Failure gives false with nils when the first statement is not that split, or partial results when the host or error target is not an identifier.
func redirectSplitHostPort(function *ast.FuncDecl, netPackages map[string]bool) (*ast.Ident, *ast.Ident, *ast.Ident, bool) {
	parameter := function.Type.Params.List[0].Names[0]
	split, ok := function.Body.List[0].(*ast.AssignStmt)
	if !ok || split.Tok != token.DEFINE || len(split.Lhs) != 3 || len(split.Rhs) != 1 {
		return nil, nil, nil, false
	}
	splitCall, ok := split.Rhs[0].(*ast.CallExpr)
	if !ok || !selectorCallMatches(splitCall, netPackages, "SplitHostPort") || len(splitCall.Args) != 1 ||
		!identifierBinds(splitCall.Args[0], parameter.Obj) {
		return nil, nil, nil, false
	}
	host, hostOK := split.Lhs[0].(*ast.Ident)
	errName, errOK := split.Lhs[2].(*ast.Ident)
	return parameter, host, errName, hostOK && errOK
}

// redirectPortFallback requires the helper to return the original host when net.SplitHostPort fails.
//
// statement must be an if without init or else whose condition is errName != nil and whose only statement returns parameter alone.
// It reports true for that exact fallback and false for any other statement shape.
func redirectPortFallback(statement ast.Stmt, parameter, errName *ast.Ident) bool {
	guard, ok := statement.(*ast.IfStmt)
	if !ok || guard.Init != nil || guard.Else != nil || len(guard.Body.List) != 1 {
		return false
	}
	condition, ok := guard.Cond.(*ast.BinaryExpr)
	if !ok || condition.Op != token.NEQ || !identifierBinds(condition.X, errName.Obj) || !isNilIdentifier(condition.Y) {
		return false
	}
	fallback, ok := guard.Body.List[0].(*ast.ReturnStmt)
	return ok && len(fallback.Results) == 1 && identifierBinds(fallback.Results[0], parameter.Obj)
}

// redirectJoinedHost accepts only the split host with the fixed HTTPS port.
//
// statement must return only a net.JoinHostPort call, through a name in netPackages, that joins host with the string literal "443".
// It reports true for that exact return and false for any other statement.
func redirectJoinedHost(statement ast.Stmt, host *ast.Ident, netPackages map[string]bool) bool {
	returned, ok := statement.(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return false
	}
	joined, ok := returned.Results[0].(*ast.CallExpr)
	if !ok || !selectorCallMatches(joined, netPackages, "JoinHostPort") || len(joined.Args) != 2 ||
		!identifierBinds(joined.Args[0], host.Obj) {
		return false
	}
	port, literal := stringLiteral(joined.Args[1])
	return literal && port == "443"
}

// isSafeRelativePrefix requires a literal path segment before submitted text.
//
// A bare slash is unsafe because a visitor can extend it into //external-host and leave the site.
// It reports true only when fixedPrefix has at least two bytes, starts with a slash, and has a second byte that is neither slash nor backslash.
func isSafeRelativePrefix(fixedPrefix string) bool {
	// Empty, bare-slash, and absolute inputs can still become external redirects.
	if len(fixedPrefix) < 2 || fixedPrefix[0] != '/' {
		return false
	}
	return fixedPrefix[1] != '/' && fixedPrefix[1] != '\\'
}

// destinationConstraintOptions adds redirect-only evidence to the shared URL policy.
//
// Request scans leave both maps empty; redirect scans provide relative tokens and strings aliases.
// Recognised destination-guard syntax suppresses a candidate; validator behaviour is not inspected.
type destinationConstraintOptions struct {
	additionalValidatorTokens map[string]bool
	stringPackageAliases      map[string]bool
}

// destinationHasConstraint looks for guard syntax that suppresses a URL or redirect candidate before it reaches the report.
//
// It accepts an exact validator token, a parsed scheme and host allowlist, or a redirect guard requiring a committed relative-path segment.
// requestScope and functionBody give the handler's request input and body, sinkArgument is the destination, and sinkPosition marks the sink.
// constraintOptions adds redirect validator tokens, and its strings aliases turn on the relative-prefix and protocol-relative checks.
//
// It reports true when any such evidence is found, and false when the finding stands; validator bodies are never inspected.
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
			bodyStripsProtocolRelativePrefix(requestScope, functionBody, sinkValueNames, constraintOptions.stringPackageAliases, sinkPosition)
	}
	return false
}

// argHasDestinationSanitizer recognises a call named with an exact validator token whose complete result is passed to the sink.
//
// A sanitizer nested beside raw request input does not constrain the final destination expression.
// sinkArgument must itself be that call, additionalValidatorTokens widens the token set, and requestScope must find request input in it.
// It reports true for such a call, which suppresses the candidate, and false for any other sinkArgument.
func argHasDestinationSanitizer(requestScope *requestTaintScope, sinkArgument ast.Expr, additionalValidatorTokens map[string]bool) bool {
	candidateCall, isCall := unwrapRequestExprParens(sinkArgument).(*ast.CallExpr)
	if !isCall || !callHasDestinationToken(candidateCall, additionalValidatorTokens) {
		return false
	}
	_, containsRequestInput := requestScope.exprHasRequest(candidateCall, token.NoPos)
	return containsRequestInput
}

// bodyHasDestinationSanitizer recognises a validator call before the sink only when its call name holds a complete approved identifier token.
//
// functionBody is searched outside nested closures for such a call before sinkPosition, with additionalValidatorTokens added to the shared set.
// It reports true when the call reads one of sinkValueNames, none is reassigned before the sink, and the call guards it; no names give false.
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
		// Validator calls inside nested closures do not suppress this sink, even when the closure runs before it.
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

// validatorCallProtectsSink recognises the two affirmative control-flow forms a validator guard can take around the sink.
//
// A rejecting guard counts when its body returns and only its false path reaches a later sink.
// A positive guard counts when its true body contains the sink.
//
// It searches functionBody, outside nested closures, for an if whose condition holds validatorCall and whose enclosing regions hold sinkPosition.
// It reports true when such a guard has either form for the sink, and false otherwise.
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
		// A guard inside an optional outer branch does not dominate a sink after
		// that branch; every enclosing control region must also contain the sink.
		if !enclosingControlRegionsContainPosition(functionBody, guard, sinkPosition) {
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

// conditionOutcomeImpliesValidator reports whether observing one boolean result of condition proves that validatorCall itself returned true.
//
// It preserves AND and OR semantics instead of counting a call merely because it appears somewhere in a condition.
// outcome is the observed value of condition, and a condition that is validatorCall itself gives outcome back.
// Negation, comparison with true or false, && and || are followed recursively, and any other form gives false.
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
		case token.EQL, token.NEQ:
			// validate(u) == false guards exactly what !validate(u) guards.
			// Without this, the explicit-boolean style reads as an unguarded sink and fails a default scan on correctly validated code.
			if operand, literal, ok := booleanComparisonOperand(expression); ok {
				return conditionOutcomeImpliesValidator(operand, validatorCall,
					comparisonOperandOutcome(expression.Op, literal, outcome))
			}
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

// booleanComparisonOperand splits a comparison against a predeclared true or false into the other operand and that literal's value.
//
// Only comparisons that name a boolean literal qualify, so a == b still falls through unproven.
// It returns the other operand, the literal's value and true, checking the right side first, or nil, false and false when neither side qualifies.
func booleanComparisonOperand(comparison *ast.BinaryExpr) (ast.Expr, bool, bool) {
	if literal, ok := universeBoolLiteral(comparison.Y); ok {
		return comparison.X, literal, true
	}
	if literal, ok := universeBoolLiteral(comparison.X); ok {
		return comparison.Y, literal, true
	}
	return nil, false, false
}

// universeBoolLiteral reports whether expr is the predeclared true or false; it returns that constant's value and true, or false and false.
// A local may shadow either name, so a resolved identifier is not the constant.
func universeBoolLiteral(expr ast.Expr) (bool, bool) {
	identifier, isIdentifier := unwrapRequestExprParens(expr).(*ast.Ident)
	// A resolved identifier is a declared shadow, not the predeclared constant.
	if !isIdentifier || identifier.Obj != nil {
		return false, false
	}
	switch identifier.Name {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// comparisonOperandOutcome maps an observed comparison result back to the value the non-literal operand must have held for it to occur.
// For the == operator it gives outcome == literal, and for any other operator outcome != literal, where literal is the compared constant.
func comparisonOperandOutcome(operator token.Token, literal bool, outcome bool) bool {
	// Observing `operand == literal` as outcome means they agree exactly when outcome holds.
	if operator == token.EQL {
		return outcome == literal
	}
	return outcome != literal
}

// exprContainsExactCall reports whether expression contains this very AST call node, not merely another call with the same text or name.
// It walks expression and compares each node to targetCall by pointer identity, so only that very node counts.
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

// callHasDestinationToken looks for a validator token in the name of candidateCall, matching complete camel-case and snake-case tokens.
//
// Whole tokens keep names such as parser, allowance, disallow, untrusted and sanitation from colliding with a validator word.
// Each lowercased token of the name of candidateCall is looked up in destinationSanitizerTokens and additionalValidatorTokens.
// It reports true for the first match whose immediately preceding token is not a recognised negation, and false when none qualifies.
func callHasDestinationToken(candidateCall *ast.CallExpr, additionalValidatorTokens map[string]bool) bool {
	callNameTokens := splitIdentifierTokens(callName(candidateCall))
	// Whole tokens only, so a validator word buried inside a longer token never suppresses a finding.
	for tokenIndex, identifierToken := range callNameTokens {
		identifierToken = strings.ToLower(identifierToken)
		// Negated names such as notTrusted remain visible findings for the user.
		if (destinationSanitizerTokens[identifierToken] || additionalValidatorTokens[identifierToken]) && !precededByDestinationNegation(callNameTokens, tokenIndex) {
			return true
		}
	}
	return false
}
