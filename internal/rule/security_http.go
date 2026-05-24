// Package rule defines gruff-go's rule registry and analysers.
// This file implements parser-only HTTP security checks.
package rule

import (
	"go/ast"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// HTTPClientNoTimeoutRule flags http.Client literals with no Timeout field.
type HTTPClientNoTimeoutRule struct{}

// Definition declares the security.http-client-no-timeout rule for static client literals.
func (HTTPClientNoTimeoutRule) Definition() Definition {
	return Definition{
		ID:             "security.http-client-no-timeout",
		Title:          "HTTP client without timeout",
		Description:    "Flags http.Client composite literals in production files that do not set Timeout.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"http", "security"},
		Remediation:    "Set http.Client.Timeout or use a shared client whose timeout ownership is explicit.",
	}
}

// AnalyzeUnit emits findings for http.Client{} literals without a Timeout key.
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
type RequestBodyWithoutLimitRule struct{}

// Definition declares the security.request-body-without-limit rule for unbounded handler body reads.
func (RequestBodyWithoutLimitRule) Definition() Definition {
	return Definition{
		ID:             "security.request-body-without-limit",
		Title:          "Request body read without limit",
		Description:    "Flags io.ReadAll-style reads of http.Request.Body in production handlers without nearby MaxBytesReader or LimitReader evidence.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"http", "security"},
		Remediation:    "Wrap request bodies with http.MaxBytesReader or io.LimitReader before reading them fully.",
	}
}

// AnalyzeUnit emits findings for direct unbounded reads of request bodies.
func (RequestBodyWithoutLimitRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	packages := httpBodyPackages{
		http:   packageImportNames(unit.AST, "net/http", "http"),
		io:     packageImportNames(unit.AST, "io", "io"),
		ioutil: packageImportNames(unit.AST, "io/ioutil", "ioutil"),
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
		if len(requests) == 0 {
			continue
		}
		bounded := collectBoundedRequestBodies(fn.Body, requests, packages)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok || !isReadAllCall(call, packages) || len(call.Args) == 0 {
				return true
			}
			if isBoundedBodyRead(call.Args[0], requests, bounded, packages) {
				return true
			}
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
type httpBodyPackages struct {
	http   map[string]bool
	io     map[string]bool
	ioutil map[string]bool
}

// isHTTPClientLiteral reports whether literal has type net/http.Client.
func isHTTPClientLiteral(literal *ast.CompositeLit, httpPackages map[string]bool) bool {
	selector, ok := literal.Type.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Client" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && httpPackages[receiver.Name]
}

// httpClientLiteralHasTimeout reports whether a client literal sets Timeout explicitly.
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
func httpRequestParamNames(fn *ast.FuncDecl, httpPackages map[string]bool) map[string]bool {
	out := map[string]bool{}
	if fn.Type == nil || fn.Type.Params == nil {
		return out
	}
	for _, field := range fn.Type.Params.List {
		if !isHTTPRequestPointer(field.Type, httpPackages) {
			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" {
				out[name.Name] = true
			}
		}
	}
	return out
}

// isHTTPRequestPointer reports whether expr is *http.Request through an imported net/http name.
func isHTTPRequestPointer(expr ast.Expr, httpPackages map[string]bool) bool {
	pointer, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := pointer.X.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Request" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && httpPackages[receiver.Name]
}

// isReadAllCall reports whether call is io.ReadAll or ioutil.ReadAll.
func isReadAllCall(call *ast.CallExpr, packages httpBodyPackages) bool {
	return selectorCallMatches(call, packages.io, "ReadAll") || selectorCallMatches(call, packages.ioutil, "ReadAll")
}

// collectBoundedRequestBodies records request bodies or variables that have obvious size limits.
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
func recordBoundedTarget(expr ast.Expr, requests, bounded map[string]bool) {
	if requestName, ok := requestBodyExpr(expr, requests); ok {
		bounded[requestName+".Body"] = true
		return
	}
	if ident, ok := expr.(*ast.Ident); ok && ident.Name != "_" {
		bounded[ident.Name] = true
	}
}

// isBoundedBodyRead reports whether expr is already limited or refers to a limited body.
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

// requestBodyExpr reports whether expr is `<request>.Body` for a known request parameter.
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
