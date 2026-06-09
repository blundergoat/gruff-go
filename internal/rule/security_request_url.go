// Package rule defines gruff-go's rule registry and analysers.
// This file implements parser-only SSRF and open-redirect checks that trace
// request-controlled values into net/http URL and redirect sinks.
package rule

import (
	"go/ast"
	"go/token"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// urlSanitizerWords name the same-function evidence that a request-controlled URL
// was validated before reaching an HTTP client: an allowlist, a validator, or a
// parse/verify step. Matching is a lowercased substring test on the call name.
var urlSanitizerWords = []string{"allow", "whitelist", "validate", "verif", "sanit", "permit", "isallow", "parse", "trusted"}

// redirectSanitizerWords name the same-function evidence that a redirect target
// was constrained to a safe destination before use.
var redirectSanitizerWords = []string{"allow", "whitelist", "validate", "verif", "sanit", "islocal", "isrelative", "trusted", "parse", "prefix"}

// RequestControlledURLRule flags request-derived values used as the URL of an
// outbound HTTP request without allowlist or validation evidence.
type RequestControlledURLRule struct{}

// Definition declares the security.request-controlled-url rule for bounded
// same-function SSRF evidence.
func (RequestControlledURLRule) Definition() Definition {
	return Definition{
		ID:             "security.request-controlled-url",
		Title:          "Request-controlled request URL",
		Description:    "Flags request-derived values passed as the URL of an outbound net/http request without a nearby allowlist or parse/validate check (possible SSRF). Uses bounded same-function evidence and candidate wording.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"http", "security", "ssrf"},
		Remediation:    "Validate request-derived URLs against an allowlist of trusted hosts, or build the request URL from a fixed base before fetching.",
	}
}

// AnalyzeUnit emits findings for request-controlled URLs reaching HTTP client sinks.
func (RequestControlledURLRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	httpPackages := packageImportNames(unit.AST, "net/http", "http")
	if len(httpPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	forEachRequestFunc(unit.AST, httpPackages, func(scope *requestTaintScope, body *ast.BlockStmt) {
		clientVars := collectHTTPClientVars(body, httpPackages)
		ast.Inspect(body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			urlIndex, sink, ok := httpClientURLArg(call, httpPackages, clientVars)
			if !ok || urlIndex >= len(call.Args) {
				return true
			}
			urlArg := call.Args[urlIndex]
			source, ok := scope.exprHasRequest(urlArg, call.Pos())
			if !ok {
				return true
			}
			if scope.argHasInlineSanitizer(urlArg, urlSanitizerWords) || bodyHasSanitizingCall(body, scope.sanitizerValueNames(urlArg), urlSanitizerWords, call.Pos()) {
				return true
			}
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "request-controlled value used as HTTP request URL without allowlist or validation (possible SSRF)",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Metadata: map[string]any{"sink": sink, "source": source},
			})
			return true
		})
	})
	return findings
}

// OpenRedirectRule flags request-derived values used as a redirect destination
// without validation that the target is safe.
type OpenRedirectRule struct{}

// Definition declares the security.open-redirect-candidate rule for bounded
// same-function redirect evidence.
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

// AnalyzeUnit emits findings for request-controlled redirect destinations.
func (OpenRedirectRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	httpPackages := packageImportNames(unit.AST, "net/http", "http")
	if len(httpPackages) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	forEachRequestFunc(unit.AST, httpPackages, func(scope *requestTaintScope, body *ast.BlockStmt) {
		ast.Inspect(body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			target, sink, ok := redirectTargetArg(call, httpPackages)
			if !ok {
				return true
			}
			source, ok := scope.exprHasRequest(target, call.Pos())
			if !ok {
				return true
			}
			if literal, ok := leftmostStringLiteral(target); ok && isSafeRelativePrefix(literal) {
				return true
			}
			if scope.argHasInlineSanitizer(target, redirectSanitizerWords) || bodyHasSanitizingCall(body, scope.sanitizerValueNames(target), redirectSanitizerWords, call.Pos()) {
				return true
			}
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "request-controlled value used as redirect target without validation (possible open redirect)",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Metadata: map[string]any{"sink": sink, "source": source},
			})
			return true
		})
	})
	return findings
}

// httpClientURLArg reports the URL argument index and a sink label for net/http
// client calls that fetch a URL, covering both package-qualified helpers and
// methods on a known http.Client value.
func httpClientURLArg(call *ast.CallExpr, httpPackages, clientVars map[string]bool) (int, string, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return 0, "", false
	}
	if receiver, ok := selector.X.(*ast.Ident); ok && httpPackages[receiver.Name] {
		switch selector.Sel.Name {
		case "Get", "Head", "Post", "PostForm":
			return 0, receiver.Name + "." + selector.Sel.Name, true
		case "NewRequest":
			return 1, receiver.Name + ".NewRequest", true
		case "NewRequestWithContext":
			return 2, receiver.Name + ".NewRequestWithContext", true
		}
		return 0, "", false
	}
	if isHTTPClientReceiver(selector.X, httpPackages, clientVars) {
		switch selector.Sel.Name {
		case "Get", "Head", "Post", "PostForm":
			return 0, "client." + selector.Sel.Name, true
		}
	}
	return 0, "", false
}

// redirectTargetArg reports the redirect destination expression and sink label
// for http.Redirect calls and Location-header assignments.
func redirectTargetArg(call *ast.CallExpr, httpPackages map[string]bool) (ast.Expr, string, bool) {
	if selectorCallMatches(call, httpPackages, "Redirect") && len(call.Args) >= 4 {
		return call.Args[2], "http.Redirect", true
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Set" || len(call.Args) != 2 {
		return nil, "", false
	}
	if !isHeaderMethodCallReceiver(selector.X) {
		return nil, "", false
	}
	header, ok := stringLiteral(call.Args[0])
	if !ok || !isLocationHeader(header) {
		return nil, "", false
	}
	return call.Args[1], "Header.Set(Location)", true
}

// isHeaderMethodCallReceiver reports whether expr is a `<x>.Header()` method call —
// the http.ResponseWriter.Header() accessor. It is a method call, unlike the
// http.Request.Header field, so gating a header Set on it distinguishes a response
// header write (w.Header().Set(...)) from setting a header on the inbound request
// or on an unrelated object.
func isHeaderMethodCallReceiver(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Header"
}

// isLocationHeader reports whether a header name targets the redirect Location
// header, ignoring case as net/http canonicalises header keys.
func isLocationHeader(name string) bool {
	return equalFoldASCII(name, "Location")
}

// equalFoldASCII reports case-insensitive equality for ASCII header names without
// pulling in Unicode folding.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// leftmostStringLiteral returns the value of the left-most string literal in a
// + concatenation, used to inspect the fixed prefix of a constructed target.
func leftmostStringLiteral(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return leftmostStringLiteral(e.X)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return leftmostStringLiteral(e.X)
		}
	case *ast.BasicLit:
		return stringLiteral(e)
	}
	return "", false
}

// isSafeRelativePrefix reports whether a fixed literal prefix keeps a redirect
// host-relative no matter what request-controlled suffix is concatenated after it.
// A bare "/" is not enough: a request value beginning with "/" or "\" extends it
// into a protocol-relative "//host" or "/\host", so the prefix must commit to a
// path segment ("/x…") before the request-controlled data.
func isSafeRelativePrefix(value string) bool {
	if len(value) < 2 || value[0] != '/' {
		return false
	}
	return value[1] != '/' && value[1] != '\\'
}

// isHTTPClientReceiver reports whether expr is a known http.Client value: a local
// collected by collectHTTPClientVars or the package-level http.DefaultClient.
func isHTTPClientReceiver(expr ast.Expr, httpPackages, clientVars map[string]bool) bool {
	switch value := expr.(type) {
	case *ast.Ident:
		return clientVars[value.Name]
	case *ast.SelectorExpr:
		receiver, ok := value.X.(*ast.Ident)
		return ok && httpPackages[receiver.Name] && value.Sel.Name == "DefaultClient"
	}
	return false
}

// collectHTTPClientVars records locals bound to an http.Client value so method
// calls on them count as outbound HTTP sinks.
func collectHTTPClientVars(body *ast.BlockStmt, httpPackages map[string]bool) map[string]bool {
	vars := map[string]bool{}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch stmt := node.(type) {
		case *ast.AssignStmt:
			for i, lhs := range stmt.Lhs {
				name, ok := lhs.(*ast.Ident)
				if !ok || name.Name == "_" || i >= len(stmt.Rhs) || !isHTTPClientExpr(stmt.Rhs[i], httpPackages) {
					continue
				}
				vars[name.Name] = true
			}
		case *ast.ValueSpec:
			for i, name := range stmt.Names {
				if name.Name == "_" || i >= len(stmt.Values) || !isHTTPClientExpr(stmt.Values[i], httpPackages) {
					continue
				}
				vars[name.Name] = true
			}
		}
		return true
	})
	return vars
}

// isHTTPClientExpr reports whether expr constructs or references an http.Client:
// a &http.Client{} / http.Client{} literal or the http.DefaultClient value.
func isHTTPClientExpr(expr ast.Expr, httpPackages map[string]bool) bool {
	switch value := expr.(type) {
	case *ast.UnaryExpr:
		if value.Op == token.AND {
			return isHTTPClientExpr(value.X, httpPackages)
		}
	case *ast.CompositeLit:
		return isHTTPClientLiteral(value, httpPackages)
	case *ast.SelectorExpr:
		receiver, ok := value.X.(*ast.Ident)
		return ok && httpPackages[receiver.Name] && value.Sel.Name == "DefaultClient"
	}
	return false
}
