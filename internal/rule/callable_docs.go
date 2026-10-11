// Package rule defines gruff-go's rule registry and analysers.
// This file holds the opt-in docs.missing-param-doc and docs.missing-return-doc rules, which read a
// callable's doc comment as natural prose and ask it to name each parameter the caller supplies and to
// explain the returned values and when an error is returned.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// MissingParamDocRule flags documented callables whose doc comment does not name every parameter.
type MissingParamDocRule struct{}

// Definition declares the opt-in docs.missing-param-doc rule.
func (MissingParamDocRule) Definition() Definition {
	return Definition{
		ID:             "docs.missing-param-doc",
		Title:          "Missing parameter doc",
		Description:    "Flags documented functions, methods, and package-level vars holding a function literal whose doc comment does not name each parameter; context, HTTP request and response, and testing handles are skipped.",
		Pillar:         finding.PillarDocumentation,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: false,
		Remediation:    "Name each listed parameter in the doc comment and say what it carries; plain prose is enough and no tag format is required.",
	}
}

// AnalyzeUnit emits one finding per documented callable whose doc comment leaves a parameter unnamed.
func (MissingParamDocRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	findings := []finding.Finding{}
	for _, callable := range documentedCallables(unit.AST) {
		missing := unnamedParameters(callable.fnType, callable.doc)
		if len(missing) == 0 {
			continue
		}
		findings = append(findings, missingParamFinding(unit, callable, missing))
	}
	return findings
}

// documentedCallable is a top-level callable paired with the doc comment that describes it.
type documentedCallable struct {
	// kind is the noun used in messages: function, method, or function variable.
	kind string
	// symbol is the reported name; methods use Type.Method.
	symbol string
	// pos anchors the finding line.
	pos token.Pos
	// doc is the comment read for parameter prose.
	doc *ast.CommentGroup
	// fnType is the callable's signature.
	fnType *ast.FuncType
}

// documentedCallables returns the file's functions, methods, and package-level vars holding a
// function literal whose doc comment passes hasUsefulDeclarationComment. Local closures are out of scope.
func documentedCallables(file *ast.File) []documentedCallable {
	documented := []documentedCallable{}
	for _, decl := range file.Decls {
		candidates := []documentedCallable{}
		switch d := decl.(type) {
		case *ast.FuncDecl:
			candidates = append(candidates, documentedCallable{kind: funcKind(d), symbol: functionName(d), pos: d.Pos(), doc: d.Doc, fnType: d.Type})
		case *ast.GenDecl:
			candidates = funcLiteralVars(d)
		}
		for _, candidate := range candidates {
			if hasUsefulDeclarationComment(candidate.doc, candidate.symbol, 0) {
				documented = append(documented, candidate)
			}
		}
	}
	return documented
}

// funcLiteralVars returns package-level vars bound to a function literal. Each is read through its own
// doc comment, or through the declaration's doc comment when the var is not in a parenthesised group.
func funcLiteralVars(decl *ast.GenDecl) []documentedCallable {
	if decl.Tok != token.VAR {
		return nil
	}
	callables := []documentedCallable{}
	for _, spec := range decl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok || len(valueSpec.Values) != len(valueSpec.Names) {
			continue
		}
		doc := valueSpec.Doc
		if doc == nil && !decl.Lparen.IsValid() {
			doc = decl.Doc
		}
		for index, name := range valueSpec.Names {
			literal, isLiteral := valueSpec.Values[index].(*ast.FuncLit)
			if !isLiteral || name.Name == "_" {
				continue
			}
			callables = append(callables, documentedCallable{kind: "function variable", symbol: name.Name, pos: name.Pos(), doc: doc, fnType: literal.Type})
		}
	}
	return callables
}

// unnamedParameters returns, in signature order, the named parameters the doc comment never mentions.
// Blank and unnamed parameters and context, HTTP request and response, and testing handles are skipped.
func unnamedParameters(fnType *ast.FuncType, doc *ast.CommentGroup) []string {
	if fnType == nil || fnType.Params == nil {
		return nil
	}
	words := docWordSet(doc)
	missing := []string{}
	for _, field := range fnType.Params.List {
		if isHandleParameter(field.Type) {
			continue
		}
		for _, name := range field.Names {
			if name.Name == "_" || words[strings.ToLower(name.Name)] {
				continue
			}
			missing = append(missing, name.Name)
		}
	}
	return missing
}

// docWordSet returns the lower-cased identifier-like words of a doc comment, so a parameter counts as
// named wherever it appears in plain prose, backticks, or brackets.
func docWordSet(doc *ast.CommentGroup) map[string]bool {
	words := map[string]bool{}
	for _, word := range proseWords(doc.Text()) {
		words[strings.ToLower(word)] = true
	}
	return words
}

// proseWords splits comment text into identifier-like words, dropping punctuation, backticks, and brackets.
func proseWords(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' })
}

// isHandleParameter reports whether a parameter type is a context, HTTP request or response, or testing
// handle. It reads the type expression alone because the parser has no type information.
func isHandleParameter(expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch pkg.Name + "." + selector.Sel.Name {
	case "context.Context", "http.Request", "http.ResponseWriter",
		"testing.T", "testing.B", "testing.F", "testing.M", "testing.TB", "testing.PB":
		return true
	}
	return false
}

// missingParamFinding builds one finding that names every parameter the doc comment leaves out.
func missingParamFinding(unit parser.Unit, callable documentedCallable, missing []string) finding.Finding {
	position := unit.FileSet.Position(callable.pos)
	return finding.Finding{
		Message:  fmt.Sprintf("doc comment on %s %q does not name %s", callable.kind, callable.symbol, parameterPhrase(missing)),
		File:     unit.File.Path,
		Location: &finding.Location{Line: position.Line},
		Symbol:   callable.symbol,
		Metadata: map[string]any{"symbol": callable.symbol, "kind": callable.kind, "missingParameters": strings.Join(missing, ", ")},
	}
}

// parameterPhrase renders parameter names for a message, as parameter "a" or parameters "a", "b".
func parameterPhrase(names []string) string {
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		quoted = append(quoted, fmt.Sprintf("%q", name))
	}
	if len(names) > 1 {
		return "parameters " + strings.Join(quoted, ", ")
	}
	return "parameter " + strings.Join(quoted, ", ")
}

// MissingReturnDocRule flags documented callables whose doc comment does not explain what they return or
// when they return an error.
type MissingReturnDocRule struct{}

// Definition declares the opt-in docs.missing-return-doc rule.
func (MissingReturnDocRule) Definition() Definition {
	return Definition{
		ID:             "docs.missing-return-doc",
		Title:          "Missing return doc",
		Description:    "Flags documented functions, methods, and package-level vars holding a function literal whose doc comment does not explain the returned values or, when an error is returned, when that happens; callables that return nothing are skipped.",
		Pillar:         finding.PillarDocumentation,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: false,
		Remediation:    "Say in the doc comment what the callable returns and, when it returns an error, when that happens; plain prose is enough and no tag format is required.",
	}
}

// AnalyzeUnit emits one finding per documented callable whose doc comment leaves its returned value or its
// error case unexplained.
func (MissingReturnDocRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	findings := []finding.Finding{}
	for _, callable := range documentedCallables(unit.AST) {
		gap := undocumentedReturns(callable.fnType, callable.doc)
		if !gap.value && !gap.failure {
			continue
		}
		findings = append(findings, missingReturnFinding(unit, callable, gap))
	}
	return findings
}

// returnDocGap records which parts of a callable's results its doc comment leaves unexplained.
type returnDocGap struct {
	// values counts the non-error results; it picks the singular or plural noun in messages.
	values int
	// value is true when a non-error result exists and the prose never describes it.
	value bool
	// failure is true when an error result exists and the prose never says when it is returned.
	failure bool
}

// returnWords introduce what a callable hands back in natural prose.
var returnWords = map[string]bool{
	"return": true, "returns": true, "returned": true, "returning": true, "result": true, "results": true,
	"reports": true, "yields": true, "gives": true,
}

// failureWords explain when a callable fails in natural prose.
var failureWords = map[string]bool{
	"error": true, "errors": true, "err": true, "fail": true, "fails": true, "failed": true, "failing": true,
	"failure": true, "failures": true,
}

// returnLeadWords are skipped between a return word and its object, so "returns a non-nil error" reads as
// error prose and "returns the count" reads as value prose.
var returnLeadWords = map[string]bool{"a": true, "an": true, "any": true, "the": true, "non": true, "nil": true}

// undocumentedReturns compares a callable's results with its doc comment. A callable that returns nothing
// needs no return prose, and error prose is asked for only when a result has the type error.
func undocumentedReturns(fnType *ast.FuncType, doc *ast.CommentGroup) returnDocGap {
	gap := returnDocGap{}
	if fnType == nil || fnType.Results == nil {
		return gap
	}
	words := docWordSet(doc)
	canFail, valueNamed, errorNamed := false, false, false
	for _, field := range fnType.Results.List {
		isError := isErrorType(field.Type)
		switch {
		case isError:
			canFail = true
		case len(field.Names) == 0:
			gap.values++
		default:
			gap.values += len(field.Names)
		}
		for _, name := range field.Names {
			if name.Name == "_" || !words[strings.ToLower(name.Name)] {
				continue
			}
			if isError {
				errorNamed = true
			} else {
				valueNamed = true
			}
		}
	}
	gap.value = gap.values > 0 && !valueNamed && !describesReturnedValue(doc)
	gap.failure = canFail && !errorNamed && !mentionsFailure(words)
	return gap
}

// isErrorType reports whether a result type expression is the predeclared error interface.
func isErrorType(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "error"
}

// describesReturnedValue reports whether a sentence of the doc comment uses a return word for something other
// than an error, as in "returns the parsed config" or "reports whether the key exists".
func describesReturnedValue(doc *ast.CommentGroup) bool {
	terminator := func(r rune) bool { return r == '.' || r == '!' || r == '?' || r == ';' }
	for _, sentence := range strings.FieldsFunc(doc.Text(), terminator) {
		words := proseWords(strings.ToLower(sentence))
		for index, word := range words {
			if returnWords[word] && !leadsToError(words[index+1:]) {
				return true
			}
		}
	}
	return false
}

// leadsToError reports whether the first word after a return word, skipping articles and nil, names an error.
func leadsToError(rest []string) bool {
	for _, word := range rest {
		if returnLeadWords[word] {
			continue
		}
		return failureWords[word]
	}
	return false
}

// mentionsFailure reports whether the doc comment uses a word that explains a failure, such as "error" or "fails".
func mentionsFailure(words map[string]bool) bool {
	for word := range failureWords {
		if words[word] {
			return true
		}
	}
	return false
}

// missingReturnFinding builds one finding that asks for the returned value, the error case, or both, as the
// callable's signature requires.
func missingReturnFinding(unit parser.Unit, callable documentedCallable, gap returnDocGap) finding.Finding {
	asks := []string{}
	missing := []string{}
	if gap.value {
		asks = append(asks, "describe "+returnedValuePhrase(gap.values))
		missing = append(missing, "value")
	}
	if gap.failure {
		asks = append(asks, "say when an error is returned")
		missing = append(missing, "error")
	}
	position := unit.FileSet.Position(callable.pos)
	return finding.Finding{
		Message:  fmt.Sprintf("doc comment on %s %q does not %s", callable.kind, callable.symbol, strings.Join(asks, " or ")),
		File:     unit.File.Path,
		Location: &finding.Location{Line: position.Line},
		Symbol:   callable.symbol,
		Metadata: map[string]any{"symbol": callable.symbol, "kind": callable.kind, "missingReturnDoc": strings.Join(missing, ", ")},
	}
}

// returnedValuePhrase renders the returned-value noun for a message, plural when the callable returns more
// than one non-error result.
func returnedValuePhrase(values int) string {
	if values > 1 {
		return "the returned values"
	}
	return "the returned value"
}
