// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds security.template-injection-xss, a parser-only check that looks at one function at a time.
// It flags request data rendered by text/template, wrapped in an unsafe html/template conversion, or written raw to an HTML response.
package rule

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// templateXSSEscapeWords are the call-name stems that mark a request value as escaped or sanitized before it reaches HTML.
//
// A sanitizer-named call that itself holds request input, such as html.EscapeString(r.FormValue(name)), clears the argument it sits in.
// Another unescaped argument still flags the write, and an unsafe conversion nested inside an escape call is checked on its own.
var templateXSSEscapeWords = []string{"escape", "sanit"}

// unsafeTemplateConversions are the html/template type conversions that bypass
// auto-escaping when fed a request-controlled value.
var unsafeTemplateConversions = map[string]bool{
	"HTML": true, "JS": true, "URL": true, "CSS": true, "HTMLAttr": true, "Srcset": true, "JSStr": true,
}

// TemplateInjectionXSSRule flags request data in text/template response renders, unsafe html/template conversions and raw HTML response writes.
//
// A conversion such as template.HTML(r.FormValue(name)) is flagged even when the result is never written to a response.
type TemplateInjectionXSSRule struct{}

// Definition declares security.template-injection-xss for same-function candidates: template renders, unsafe conversions and raw writes.
//
// It returns the same fixed metadata on every call: an advisory, medium-confidence, default-enabled security rule with its remediation text.
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

// AnalyzeUnit flags request data in text/template renders, unsafe html/template conversions and raw HTML response writes in one file.
//
// unit is the parsed file; the result is nil when it has no AST or file set, is not a production code path, or does not import net/http.
// It returns one finding per flagged call, with the matched shape as reason metadata, or an empty slice when nothing fires.
//
// Sanitizer matching can panic when lowercasing a call name shortens it past an original token offset, as with the Kelvin sign U+212A.
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
	fileTemplateValues := collectFileTemplateValueKinds(unit.AST, pkgs)
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
		// Every shape below needs the taint scope, so a function with a ResponseWriter but no request taint scope never fires.
		if len(writers) == 0 && scope == nil {
			return
		}
		htmlContentType := functionSetsHTMLContentType(body)
		templateValues := collectTemplateValueKinds(body, pkgs, fileTemplateValues)
		ast.Inspect(body, func(node ast.Node) bool {
			// A closure is checked on its own with only its own ResponseWriter parameters, so a write to the handler's captured w inside it is missed.
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if reason, pos, ok := templateXSSHit(call, templateXSSContext{
				scope:           scope,
				writers:         writers,
				pkgs:            pkgs,
				templateValues:  templateValues,
				htmlContentType: htmlContentType,
			}); ok {
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

// templateXSSContext carries same-function evidence used to classify one call.
type templateXSSContext struct {
	scope           *requestTaintScope
	writers         map[string]bool
	pkgs            templateXSSPackages
	templateValues  templateValueKinds
	htmlContentType bool
}

// templateXSSHit checks one call against the three shapes and returns the finding's reason code and position when one fires.
//
// Each shape requires the value to be request-controlled, so a render of trusted data is not flagged.
// ctx carries the enclosing function's taint scope, response writers, package aliases, template value kinds and HTML Content-Type flag.
//
// The text/template render is tried first, then the unsafe conversion, then the raw write; with no match it gives an empty reason and false.
// Sanitizer matching can panic when lowercasing a call name shortens it past an original token offset, as with the Kelvin sign U+212A.
func templateXSSHit(call *ast.CallExpr, ctx templateXSSContext) (string, token.Pos, bool) {
	switch {
	case textTemplateXSSHit(call, ctx.scope, ctx.writers, ctx.pkgs, ctx.templateValues):
		return "text-template-response", call.Pos(), true
	case htmlConversionXSSHit(call, ctx.scope, ctx.pkgs):
		return "raw-html-conversion", call.Pos(), true
	case rawWriteXSSHit(call, ctx.scope, ctx.writers, ctx.pkgs, ctx.htmlContentType):
		return "unescaped-response-write", call.Pos(), true
	default:
		return "", call.Pos(), false
	}
}

// textTemplateXSSHit reports whether call renders request-controlled data into a response writer through text/template, which does not escape.
//
// It needs same-file evidence that the Execute receiver came from text/template; a parameter shadowing a known template variable can still match.
//
// scope is the request taint scope and pkgs the import aliases; a nil scope, no text/template import or inline sanitizer evidence gives false.
// writers names the response writers that Execute or ExecuteTemplate must target as their first argument.
// templateValues holds the function and file template value kinds that decide whether the receiver is a text/template value.
//
// Sanitizer matching can panic when lowercasing a call name shortens it past an original token offset, as with the Kelvin sign U+212A.
func textTemplateXSSHit(call *ast.CallExpr, scope *requestTaintScope, writers map[string]bool, pkgs templateXSSPackages, templateValues templateValueKinds) bool {
	if scope == nil || len(pkgs.textTemplate) == 0 {
		return false
	}
	dataArg, ok := templateExecuteDataArg(call, writers)
	if !ok {
		return false
	}
	// Skip an Execute receiver not traced to text/template, even when html/template is also imported, so most custom Execute methods are not flagged.
	// Tracing goes by name, so a parameter shadowing a known template variable inherits that variable's origin.
	if templateExecuteReceiverKind(call, pkgs, templateValues) != templateKindText {
		return false
	}
	_, ok = scope.exprHasRequest(dataArg, call.Pos())
	return ok && !scope.argHasInlineSanitizer(dataArg, templateXSSEscapeWords)
}

// htmlConversionXSSHit reports whether call wraps a request-controlled value in an html/template conversion that bypasses auto-escaping.
//
// It fires on the conversion alone, so template.HTML(r.FormValue(name)) is flagged even if the result never reaches a response.
// scope is the request taint scope and pkgs holds the html/template aliases; a nil scope or inline sanitizer evidence on the argument gives false.
//
// Sanitizer matching can panic when lowercasing a call name shortens it past an original token offset, as with the Kelvin sign U+212A.
func htmlConversionXSSHit(call *ast.CallExpr, scope *requestTaintScope, pkgs templateXSSPackages) bool {
	if scope == nil {
		return false
	}
	arg, ok := unsafeTemplateConversion(call, pkgs.htmlTemplate)
	if !ok {
		return false
	}
	_, ok = scope.exprHasRequest(arg, call.Pos())
	return ok && !scope.argHasInlineSanitizer(arg, templateXSSEscapeWords)
}

// rawWriteXSSHit reports whether call writes a request-controlled value to a response writer in a function that sets an HTML Content-Type.
//
// scope is the function's request taint scope, nil giving false, and htmlContentType must be true, meaning an HTML Content-Type header is set.
// writers names the response-writer parameters and pkgs the fmt and io aliases, which identify w.Write, fmt.Fprint* and io.WriteString calls.
// It fires when a written argument is request-controlled and argHasInlineSanitizer, given the escape and sanit stems, finds no sanitizer in it.
//
// Sanitizer matching can panic when lowercasing a call name shortens it past an original token offset, as with the Kelvin sign U+212A.
func rawWriteXSSHit(call *ast.CallExpr, scope *requestTaintScope, writers map[string]bool, pkgs templateXSSPackages, htmlContentType bool) bool {
	if scope == nil || !htmlContentType {
		return false
	}
	dataArgs, ok := rawResponseWriteArgs(call, writers, pkgs)
	if !ok {
		return false
	}
	for _, dataArg := range dataArgs {
		if _, ok := scope.exprHasRequest(dataArg, call.Pos()); ok && !scope.argHasInlineSanitizer(dataArg, templateXSSEscapeWords) {
			return true
		}
	}
	return false
}

// responseWriterParamNames returns the names of the http.ResponseWriter parameters declared on a function type.
//
// funcType is the function type to scan, and httpPackages holds the local names net/http is imported under.
// Blank names are skipped, and the result is an empty map, never nil, when funcType is nil, has no parameters or none is a writer.
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

// isHTTPResponseWriter reports whether expr is the http.ResponseWriter type written through an imported net/http name.
//
// httpPackages holds the local names net/http is imported under, and the selector's package name must be one of them.
// A dot-imported ResponseWriter is not recognised, so renders and raw writes through it are not checked.
func isHTTPResponseWriter(expr ast.Expr, httpPackages map[string]bool) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "ResponseWriter" {
		return false
	}
	receiver, ok := selector.X.(*ast.Ident)
	return ok && httpPackages[receiver.Name]
}

// functionSetsHTMLContentType reports whether body sets an HTML Content-Type header, which arms the raw-write shape.
//
// Only Header().Set with a literal Content-Type key and a literal value containing html counts, compared in any letter case.
// Without such a header in the function, raw writes of request data are not flagged.
func functionSetsHTMLContentType(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		// A Content-Type set in a nested closure is checked with that closure alone, so it never arms raw writes in the outer function.
		if _, nested := node.(*ast.FuncLit); nested {
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
		if !isHeaderMethodCallReceiver(selector.X) {
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

// templateExecuteDataArg returns the data argument of Execute(w, data) or ExecuteTemplate(w, name, data) when w is a response writer.
//
// call must be a selector call named Execute or ExecuteTemplate whose first argument is a plain identifier listed in writers.
// Otherwise, or when the data argument is missing, the result is nil and false.
// The caller then requires that data to be request-controlled, so a text/template render of trusted data is not flagged.
func templateExecuteDataArg(call *ast.CallExpr, writers map[string]bool) (ast.Expr, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	dataIndex := 0
	switch selector.Sel.Name {
	case "Execute":
		dataIndex = 1
	case "ExecuteTemplate":
		dataIndex = 2
	default:
		return nil, false
	}
	if len(call.Args) <= dataIndex {
		return nil, false
	}
	ident, ok := call.Args[0].(*ast.Ident)
	if !ok || !writers[ident.Name] {
		return nil, false
	}
	return call.Args[dataIndex], true
}

// unsafeTemplateConversion returns the converted argument when call is an html/template conversion that bypasses auto-escaping.
//
// htmlTemplatePackages holds the local html/template import names; other packages or a call without exactly one argument give nil and false.
// The conversion names are those in unsafeTemplateConversions, such as HTML, JS, URL and CSS.
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

// rawResponseWriteArgs returns the data arguments a call writes straight to a response writer through w.Write, fmt.Fprint* or io.WriteString.
//
// call is the call expression to classify; writers names the response-writer parameters, and pkgs supplies the fmt and io import aliases.
// w.Write on a writer yields all its arguments; fmt Fprint, Fprintf and Fprintln and io.WriteString yield the arguments after the writer.
// Any other call gives nil and false.
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
