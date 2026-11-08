// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements parser-only HTTP security checks; security.http-client-no-timeout is on by default.
// security.request-body-without-limit is off by default, and both check production files only.
// Without type information, net/http and io are matched through the import names each file declares.
package rule

import (
	"go/ast"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// HTTPClientNoTimeoutRule flags http.Client literals with no Timeout field.
//
// With no Timeout, net/http sets no overall deadline, so a slow server can hold a request open indefinitely.
// Only composite literals are checked; a client made with new(http.Client) or declared as a zero var is not flagged.
type HTTPClientNoTimeoutRule struct{}

// Definition declares the security.http-client-no-timeout rule for static client literals.
// It returns the same metadata on every call: an advisory, high-confidence security rule enabled by default.
func (HTTPClientNoTimeoutRule) Definition() Definition {
	return Definition{
		ID:             "security.http-client-no-timeout",
		Title:          "HTTP client without timeout",
		Description:    "Flags http.Client composite literals in production files that do not set Timeout.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"http", "security"},
		Remediation:    "Set http.Client.Timeout or use a shared client whose timeout ownership is explicit.",
	}
}

// AnalyzeUnit emits findings for http.Client{} literals without a Timeout key.
//
// It returns nil when unit has no parsed AST or FileSet, is not a production-code path, or has no usable net/http import name.
// A dot or blank import of net/http gives no such name, so that file reports nothing.
// Otherwise the result holds one finding per client literal without a Timeout key, and is empty when every literal sets one.
func (HTTPClientNoTimeoutRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	httpPackages := packageImportNames(unit.AST, "net/http", "http")
	if len(httpPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok || !isHTTPClientLiteral(literal, httpPackages) || httpClientLiteralHasTimeout(literal) {
			return true
		}
		position := unit.FileSet.Position(literal.Type.Pos())
		findings = append(findings, finding.Finding{
			Message:  "http.Client literal does not set Timeout",
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Metadata: map[string]any{"type": "http.Client"},
		})
		return true
	})
	return findings
}

// RequestBodyWithoutLimitRule flags unbounded reads of http.Request.Body in handlers.
//
// A client can send a body of any size, so reading it whole with no http.MaxBytesReader or io.LimitReader can let one request exhaust memory.
// The rule is off by default; once enabled, each finding names the request parameter and the ReadAll call.
type RequestBodyWithoutLimitRule struct{}

// Definition declares the security.request-body-without-limit rule for unbounded handler body reads.
// It returns the same metadata on every call: an advisory, medium-confidence security rule that is disabled by default.
func (RequestBodyWithoutLimitRule) Definition() Definition {
	return Definition{
		ID:             "security.request-body-without-limit",
		Title:          "Request body read without limit",
		Description:    "Flags io.ReadAll-style reads of http.Request.Body in production handlers without nearby MaxBytesReader or LimitReader evidence.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: false,
		Tags:           []string{"http", "security"},
		Remediation:    "Wrap request bodies with http.MaxBytesReader or io.LimitReader before reading them fully.",
	}
}

// AnalyzeUnit emits findings for direct unbounded reads of request bodies.
//
// Functions with a named *http.Request parameter are checked, except those with a named testing handle parameter or the RoundTrip signature.
// Reads inside function literals, including a handler written as one, are never examined.
//
// It returns nil when unit has no parsed AST or FileSet or is not a production-code path.
// It also returns nil if net/http has no usable import name, or neither io nor ioutil has one; dot and blank imports give none.
// Otherwise it returns one finding per ReadAll of a request Body that no limiter anywhere in the function covers, or an empty slice.
func (RequestBodyWithoutLimitRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	packages := httpBodyPackages{
		http:    packageImportNames(unit.AST, "net/http", "http"),
		io:      packageImportNames(unit.AST, "io", "io"),
		ioutil:  packageImportNames(unit.AST, "io/ioutil", "ioutil"),
		testing: packageImportNames(unit.AST, "testing", "testing"),
	}
	if len(packages.http) == 0 || len(packages.io) == 0 && len(packages.ioutil) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		requests := httpRequestParamNames(fn, packages.http)
		// Functions with no named *http.Request parameter are skipped, as are those with a named testing handle parameter or the RoundTrip signature.
		// Those two shapes are taken as a sign this program built the request; its real origin and callers are not traced.
		if len(requests) == 0 || readsOwnRequest(fn, packages) {
			continue
		}
		// Limiter assignments anywhere in the function exempt their names everywhere in it, even a read that runs before the limit is set.
		bounded := collectBoundedRequestBodies(fn.Body, requests, packages)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			// Reads inside a function literal are never examined, so a closure inside the handler that reads the body reports nothing.
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			// Only io.ReadAll and ioutil.ReadAll count; a decoder or other reader wrapped around the body is not checked.
			call, ok := node.(*ast.CallExpr)
			if !ok || !isReadAllCall(call, packages) || len(call.Args) == 0 {
				return true
			}
			if isBoundedBodyRead(call.Args[0], requests, bounded, packages) {
				return true
			}
			// Only a read of the request's Body field itself is reported; a ReadAll of a local variable holding the body is not.
			requestName, ok := requestBodyExpr(call.Args[0], requests)
			if !ok {
				return true
			}
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "request body is read without a size limit",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   functionName(fn),
				Metadata: map[string]any{
					"request": requestName,
					"call":    formatExpr(call.Fun),
				},
			})
			return true
		})
	}
	return findings
}

// httpBodyPackages groups import aliases used by request-body checks.
// Each map holds the local names the file uses for net/http, io, io/ioutil or testing; a missing, dot or blank import leaves it empty.
type httpBodyPackages struct {
	http    map[string]bool
	io      map[string]bool
	ioutil  map[string]bool
	testing map[string]bool
}

// readsOwnRequest reports whether fn has a named testing handle parameter, as testingHelperReceiverNames finds, or the RoundTrip signature.
//
// These signature shapes stand in for a request built by this program; neither request origin nor the callers are traced.
// packages holds the file's import names for testing and net/http used by both checks.
// A true result makes AnalyzeUnit skip fn, so none of its request body reads are reported.
func readsOwnRequest(fn *ast.FuncDecl, packages httpBodyPackages) bool {
	return len(testingHelperReceiverNames(fn, packages.testing)) > 0 || isRoundTripperMethod(fn, packages.http)
}

// isRoundTripperMethod matches http.RoundTripper's RoundTrip signature by syntax, so a handler that only shares the name keeps its findings.
// A result spelled error counts even when it shadows the predeclared type.
//
// fn is the method to test, and httpPackages holds the local names under which the file imports net/http.
// It reports true only for a method named RoundTrip taking one *http.Request and returning *http.Response and error, and false otherwise.
func isRoundTripperMethod(fn *ast.FuncDecl, httpPackages map[string]bool) bool {
	if fn.Recv == nil || fn.Name.Name != "RoundTrip" || fn.Type.Params == nil || fn.Type.Results == nil {
		return false
	}
	params, results := fn.Type.Params.List, fn.Type.Results.List
	if len(params) != 1 || len(params[0].Names) > 1 || len(results) != 2 || len(results[0].Names) > 1 || len(results[1].Names) > 1 {
		return false
	}
	return isHTTPRequestPointer(params[0].Type, httpPackages) && isHTTPTypePointer(results[0].Type, httpPackages, "Response") &&
		isErrorType(results[1].Type)
}

// isHTTPClientLiteral reports whether literal has type net/http.Client.
// httpPackages holds the local names under which the file imports net/http, so only a selector on one of those names matches.
func isHTTPClientLiteral(literal *ast.CompositeLit, httpPackages map[string]bool) bool {
	selector, ok := literal.Type.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Client" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && httpPackages[receiver.Name]
}

// httpClientLiteralHasTimeout reports whether a client literal sets Timeout explicitly.
// Any keyed Timeout counts, even Timeout: 0, which net/http treats as no timeout, so that literal is not reported.
func httpClientLiteralHasTimeout(literal *ast.CompositeLit) bool {
	for _, element := range literal.Elts {
		keyValue, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := keyValue.Key.(*ast.Ident)
		if ok && key.Name == "Timeout" {
			return true
		}
	}
	return false
}

// httpRequestParamNames returns parameter names declared as *http.Request.
//
// fn is the function whose parameters are read, and httpPackages holds the local names under which the file imports net/http.
// Blank and unnamed parameters are left out, so the set is empty when none qualifies.
func httpRequestParamNames(fn *ast.FuncDecl, httpPackages map[string]bool) map[string]bool {
	requestNames := map[string]bool{}
	if fn.Type == nil || fn.Type.Params == nil {
		return requestNames
	}
	for _, field := range fn.Type.Params.List {
		if !isHTTPRequestPointer(field.Type, httpPackages) {
			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" {
				requestNames[name.Name] = true
			}
		}
	}
	return requestNames
}

// isHTTPRequestPointer reports whether expr is *http.Request through an imported net/http name.
// httpPackages holds the local names under which the file imports net/http.
func isHTTPRequestPointer(expr ast.Expr, httpPackages map[string]bool) bool {
	return isHTTPTypePointer(expr, httpPackages, "Request")
}

// isHTTPTypePointer reports whether expr is a pointer to the named net/http type through an imported name.
//
// typeName is the net/http type name to match, such as Request or Response.
// httpPackages holds the local names under which the file imports net/http.
func isHTTPTypePointer(expr ast.Expr, httpPackages map[string]bool, typeName string) bool {
	pointer, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := pointer.X.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != typeName {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && httpPackages[receiver.Name]
}

// isReadAllCall reports whether call is io.ReadAll or ioutil.ReadAll.
// packages supplies the local names under which the file imports io and io/ioutil.
func isReadAllCall(call *ast.CallExpr, packages httpBodyPackages) bool {
	return selectorCallMatches(call, packages.io, "ReadAll") || selectorCallMatches(call, packages.ioutil, "ReadAll")
}

// collectBoundedRequestBodies marks request bodies and local names that a recognised limiter call is assigned to anywhere in the function.
//
// requests names the *http.Request parameters, packages holds the file's import names, and body is scanned without entering function literals.
// It returns a set holding the request name plus .Body when that body is reassigned to a limiter, and each local name bound to a limiter.
// The set ignores statement order, branches and later overwrites, and is empty when no recognised limiter wraps a request body.
func collectBoundedRequestBodies(body *ast.BlockStmt, requests map[string]bool, packages httpBodyPackages) map[string]bool {
	bounded := map[string]bool{}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch stmt := node.(type) {
		case *ast.AssignStmt:
			for index, rhs := range stmt.Rhs {
				if !isRequestBodyLimitExpr(rhs, requests, packages) || index >= len(stmt.Lhs) {
					continue
				}
				recordBoundedTarget(stmt.Lhs[index], requests, bounded)
			}
		case *ast.ValueSpec:
			for index, value := range stmt.Values {
				if !isRequestBodyLimitExpr(value, requests, packages) || index >= len(stmt.Names) {
					continue
				}
				bounded[stmt.Names[index].Name] = true
			}
		}
		return true
	})
	return bounded
}

// recordBoundedTarget records either a request body assignment or a limited local variable.
//
// expr is the assignment target and requests names the *http.Request parameters.
// bounded gains the request name plus .Body for a request body target, or a non-blank identifier itself; other targets add nothing.
func recordBoundedTarget(expr ast.Expr, requests, bounded map[string]bool) {
	if requestName, ok := requestBodyExpr(expr, requests); ok {
		bounded[requestName+".Body"] = true
		return
	}
	if ident, ok := expr.(*ast.Ident); ok && ident.Name != "_" {
		bounded[ident.Name] = true
	}
}

// isBoundedBodyRead reports whether expr is itself a recognised limiter call or names an entry in bounded, without checking assignment order.
//
// requests names the *http.Request parameters and packages holds the file's import names.
// bounded is the set collectBoundedRequestBodies built from the whole function, checked for an identifier or a request name plus .Body.
func isBoundedBodyRead(expr ast.Expr, requests, bounded map[string]bool, packages httpBodyPackages) bool {
	if isRequestBodyLimitExpr(expr, requests, packages) {
		return true
	}
	if ident, ok := expr.(*ast.Ident); ok && bounded[ident.Name] {
		return true
	}
	if requestName, ok := requestBodyExpr(expr, requests); ok && bounded[requestName+".Body"] {
		return true
	}
	return false
}

// isRequestBodyLimitExpr reports whether expr wraps a request body in a recognised limiter.
//
// requests names the *http.Request parameters and packages holds the file's import names for net/http and io.
// The recognised limiters are http.MaxBytesReader with a request body as any argument and io.LimitReader with one as its first argument.
func isRequestBodyLimitExpr(expr ast.Expr, requests map[string]bool, packages httpBodyPackages) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	if selectorCallMatches(call, packages.http, "MaxBytesReader") {
		for _, arg := range call.Args {
			if _, ok := requestBodyExpr(arg, requests); ok {
				return true
			}
		}
	}
	if selectorCallMatches(call, packages.io, "LimitReader") && len(call.Args) > 0 {
		_, ok := requestBodyExpr(call.Args[0], requests)
		return ok
	}
	return false
}

// requestBodyExpr reports whether expr is the Body field of a known request parameter, as in r.Body.
// requests names the *http.Request parameters; on a match the request name and true come back, otherwise an empty string and false.
func requestBodyExpr(expr ast.Expr, requests map[string]bool) (string, bool) {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Body" {
		return "", false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !requests[receiver.Name] {
		return "", false
	}
	return receiver.Name, true
}
