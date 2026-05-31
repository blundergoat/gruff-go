// Package rule defines gruff-go's rule registry and analysers.
// This file implements a parser-only server-side template/XSS check over
// request-controlled values rendered into HTTP responses.
package rule

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// templateXSSEscapeWords name calls that escape a value before it is written into
// an HTML response, suppressing the finding.
var templateXSSEscapeWords = []string{"escape", "sanit"}

// unsafeTemplateConversions are the html/template type conversions that bypass
// auto-escaping when fed a request-controlled value.
var unsafeTemplateConversions = map[string]bool{
	"HTML": true, "JS": true, "URL": true, "CSS": true, "HTMLAttr": true, "Srcset": true, "JSStr": true,
}

// TemplateInjectionXSSRule flags request-controlled values rendered into HTML
// responses without escaping: text/template execution, html/template unsafe
// conversions, and raw response writes.
type TemplateInjectionXSSRule struct{}

// Definition declares the security.template-injection-xss rule for bounded
// same-function evidence of unescaped HTML responses.
func (TemplateInjectionXSSRule) Definition() Definition {
	return Definition{
		ID:             "security.template-injection-xss",
		Title:          "Template injection / reflected XSS",
		Description:    "Flags text/template rendered into an HTTP response, html/template HTML/JS/URL/CSS conversions of request-derived values, and raw writes of request-derived data on an HTML content type. html/template auto-escaping and html.EscapeString are treated as safe. Candidate wording, bounded same-function evidence.",
		Pillar:         finding.PillarSecurity,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"http", "security", "xss"},
		Remediation:    "Render HTML with html/template so output is auto-escaped, or escape request-derived values with html.EscapeString before writing them to the response.",
	}
}

// AnalyzeUnit emits findings for unescaped request-derived data reaching HTML responses.
func (TemplateInjectionXSSRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isProductionCodePath(unit.File.Path) {
		return nil
	}
	httpPackages := packageImportNames(unit.AST, "net/http", "http")
	if len(httpPackages) == 0 {
		return nil
	}
	pkgs := templateXSSPackages{
		http:         httpPackages,
		textTemplate: packageImportNames(unit.AST, "text/template", "template"),
		htmlTemplate: packageImportNames(unit.AST, "html/template", "template"),
		fmt:          packageImportNames(unit.AST, "fmt", "fmt"),
		io:           packageImportNames(unit.AST, "io", "io"),
	}
	findings := []finding.Finding{}
	visitFunc := func(funcType *ast.FuncType, body *ast.BlockStmt) {
		if body == nil {
			return
		}
		writers := responseWriterParamNames(funcType, httpPackages)
		var scope *requestTaintScope
		if built, ok := newRequestTaintScope(unit.AST, funcType, body, httpPackages); ok {
			scope = built
		}
		if len(writers) == 0 && scope == nil {
			return
		}
		htmlContentType := functionSetsHTMLContentType(body)
		ast.Inspect(body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if reason, pos, ok := templateXSSHit(call, scope, writers, pkgs, htmlContentType); ok {
				position := unit.FileSet.Position(pos)
				findings = append(findings, finding.Finding{
					Message:  "request-controlled value reaches an HTML response without escaping (possible reflected XSS)",
					File:     unit.File.Path,
					Location: &finding.Location{Line: position.Line, Column: position.Column},
					Metadata: map[string]any{"reason": reason},
				})
			}
			return true
		})
	}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		switch fn := node.(type) {
		case *ast.FuncDecl:
			visitFunc(fn.Type, fn.Body)
		case *ast.FuncLit:
			visitFunc(fn.Type, fn.Body)
		}
		return true
	})
	return findings
}

// templateXSSPackages groups the imported aliases the template/XSS rule consults.
type templateXSSPackages struct {
	http         map[string]bool
	textTemplate map[string]bool
	htmlTemplate map[string]bool
	fmt          map[string]bool
	io           map[string]bool
}

// templateXSSHit classifies one call against the three unescaped-HTML shapes and
// returns the reason and report position when it fires. text/template is unsafe
// for HTML only when html/template is not also imported in the file.
func templateXSSHit(call *ast.CallExpr, scope *requestTaintScope, writers map[string]bool, pkgs templateXSSPackages, htmlContentType bool) (string, token.Pos, bool) {
	textTemplateUnescaped := len(pkgs.textTemplate) > 0 && len(pkgs.htmlTemplate) == 0
	if textTemplateUnescaped && isTemplateExecuteToWriter(call, writers) {
		return "text-template-response", call.Pos(), true
	}
	if scope != nil {
		if arg, ok := unsafeTemplateConversion(call, pkgs.htmlTemplate); ok {
			if _, ok := scope.exprHasRequest(arg); ok && !scope.argHasInlineSanitizer(arg, templateXSSEscapeWords) {
				return "raw-html-conversion", call.Pos(), true
			}
		}
	}
	if scope != nil && htmlContentType {
		if dataArgs, ok := rawResponseWriteArgs(call, writers, pkgs); ok {
			for _, dataArg := range dataArgs {
				if _, ok := scope.exprHasRequest(dataArg); ok && !scope.argHasInlineSanitizer(dataArg, templateXSSEscapeWords) {
					return "unescaped-response-write", call.Pos(), true
				}
			}
		}
	}
	return "", call.Pos(), false
}

// responseWriterParamNames returns the parameter names declared as
// http.ResponseWriter on a function type.
func responseWriterParamNames(funcType *ast.FuncType, httpPackages map[string]bool) map[string]bool {
	out := map[string]bool{}
	if funcType == nil || funcType.Params == nil {
		return out
	}
	for _, field := range funcType.Params.List {
		if !isHTTPResponseWriter(field.Type, httpPackages) {
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

// isHTTPResponseWriter reports whether expr is the http.ResponseWriter interface
// type through an imported net/http name.
func isHTTPResponseWriter(expr ast.Expr, httpPackages map[string]bool) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "ResponseWriter" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && httpPackages[receiver.Name]
}

// functionSetsHTMLContentType reports whether the body sets an HTML Content-Type
// header, the precondition for treating a raw response write as an XSS sink.
func functionSetsHTMLContentType(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Set" || len(call.Args) != 2 {
			return true
		}
		key, ok := stringLiteral(call.Args[0])
		if !ok || !equalFoldASCII(key, "Content-Type") {
			return true
		}
		if value, ok := stringLiteral(call.Args[1]); ok && strings.Contains(strings.ToLower(value), "html") {
			found = true
			return false
		}
		return true
	})
	return found
}

// isTemplateExecuteToWriter reports whether call renders a template into one of
// the response writers via Execute or ExecuteTemplate.
func isTemplateExecuteToWriter(call *ast.CallExpr, writers map[string]bool) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if selector.Sel.Name != "Execute" && selector.Sel.Name != "ExecuteTemplate" {
		return false
	}
	if len(call.Args) == 0 {
		return false
	}
	ident, ok := call.Args[0].(*ast.Ident)
	return ok && writers[ident.Name]
}

// unsafeTemplateConversion reports the converted argument when call is an
// html/template HTML/JS/URL/CSS-style conversion that bypasses auto-escaping.
func unsafeTemplateConversion(call *ast.CallExpr, htmlTemplatePackages map[string]bool) (ast.Expr, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !unsafeTemplateConversions[selector.Sel.Name] || len(call.Args) != 1 {
		return nil, false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !htmlTemplatePackages[receiver.Name] {
		return nil, false
	}
	return call.Args[0], true
}

// rawResponseWriteArgs reports the data arguments written directly to a response
// writer via w.Write, fmt.Fprint*, or io.WriteString.
func rawResponseWriteArgs(call *ast.CallExpr, writers map[string]bool, pkgs templateXSSPackages) ([]ast.Expr, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	if selector.Sel.Name == "Write" {
		if ident, ok := selector.X.(*ast.Ident); ok && writers[ident.Name] {
			return call.Args, true
		}
		return nil, false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok {
		return nil, false
	}
	if pkgs.fmt[receiver.Name] && (selector.Sel.Name == "Fprintf" || selector.Sel.Name == "Fprint" || selector.Sel.Name == "Fprintln") {
		if len(call.Args) >= 2 && isResponseWriterArg(call.Args[0], writers) {
			return call.Args[1:], true
		}
	}
	if pkgs.io[receiver.Name] && selector.Sel.Name == "WriteString" {
		if len(call.Args) == 2 && isResponseWriterArg(call.Args[0], writers) {
			return call.Args[1:], true
		}
	}
	return nil, false
}

// isResponseWriterArg reports whether expr names one of the response writers.
func isResponseWriterArg(expr ast.Expr, writers map[string]bool) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && writers[ident.Name]
}
