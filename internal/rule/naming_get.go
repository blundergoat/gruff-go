// Package rule defines gruff-go's rule registry and analysers.
// This file implements the get-prefix rule for accessor-style methods.
package rule

import (
	"fmt"
	"go/ast"
	"strings"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/pathfilter"
)

// GetPrefixRule flags receiver methods that use a Go-style discouraged Get prefix.
type GetPrefixRule struct {
	// ExcludePaths skips enforcement for file paths matching any of the supplied globs.
	ExcludePaths []string
	// ExcludeNames lists method names that are exempt from the Get-prefix check by exact match.
	ExcludeNames []string
}

// Definition declares the naming.get-prefix rule that flags zero-argument accessor methods whose names begin with Get.
func (r GetPrefixRule) Definition() Definition {
	return Definition{
		ID:             "naming.get-prefix",
		Title:          "Get prefix",
		Description:    "Flags receiver accessor methods that use a Get prefix instead of a direct noun phrase.",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Tags:           []string{"go-style", "naming", "opt-in"},
		Options:        map[string]any{"excludePaths": []string{}, "excludeNames": []string{}},
		Remediation:    "Rename accessor-style methods from GetThing to Thing unless parameters make the lookup action explicit.",
	}
}

// AnalyzeUnit walks function declarations and reports accessor methods using a Get prefix.
func (r GetPrefixRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || hasGeneratedHeader(unit.Source) || pathfilter.MatchesAny(r.ExcludePaths, unit.File.Path) {
		return nil
	}
	excludeNames := exactStringSet(r.ExcludeNames)
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !isGetterPrefixCandidate(fn) || excludeNames[fn.Name.Name] {
			continue
		}
		position := unit.FileSet.Position(fn.Name.Pos())
		kind := "receiver method"
		if fn.Recv == nil {
			kind = "context accessor"
		}
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("function %q uses Get prefix for an accessor-style %s", fn.Name.Name, kind),
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Symbol:   fn.Name.Name,
			Metadata: map[string]any{"method": fn.Name.Name, "kind": kind},
		})
	}
	return findings
}

// isGetterPrefixCandidate reports whether a function declaration is an
// accessor-shaped Get* function. The rule covers two shapes:
//
//  1. Receiver method with no parameters and a single result (or value + error).
//     This is the classic Go convention violation.
//  2. Free function whose only parameter is context.Context and that returns
//     a single value (or value + error). This covers the common context-value
//     accessor pattern (`GetLogger(ctx)`, `GetRequestID(ctx)`) where the Get
//     prefix is just as redundant as on a method.
func isGetterPrefixCandidate(fn *ast.FuncDecl) bool {
	if !hasGetPrefix(fn.Name.Name) {
		return false
	}
	if !hasGetterResultShape(fn.Type.Results) {
		return false
	}
	if fn.Recv != nil {
		return fieldListCount(fn.Type.Params) == 0
	}
	return paramListIsSingleContext(fn.Type.Params)
}

// hasGetterResultShape reports whether the result list matches the
// "single value" or "value + error" accessor convention.
func hasGetterResultShape(results *ast.FieldList) bool {
	count := fieldListCount(results)
	if count == 1 {
		return true
	}
	return count == 2 && resultListEndsWithError(results)
}

// paramListIsSingleContext reports whether the parameter list is a single
// context.Context argument (with any name). We require exactly one field with
// one name so things like `(ctx, foo context.Context)` don't match.
func paramListIsSingleContext(params *ast.FieldList) bool {
	if params == nil || len(params.List) != 1 {
		return false
	}
	field := params.List[0]
	if len(field.Names) != 1 {
		return false
	}
	selector, ok := field.Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkg.Name == "context" && selector.Sel.Name == "Context"
}

// hasGetPrefix reports whether name starts with Get followed by an uppercase letter.
func hasGetPrefix(name string) bool {
	if !strings.HasPrefix(name, "Get") {
		return false
	}
	runes := []rune(name)
	return len(runes) > 3 && unicode.IsUpper(runes[3])
}

// fieldListCount returns the total number of fields across all entries in a FieldList.
func fieldListCount(list *ast.FieldList) int {
	if list == nil {
		return 0
	}
	count := 0
	for _, field := range list.List {
		if len(field.Names) == 0 {
			count++
			continue
		}
		count += len(field.Names)
	}
	return count
}

// resultListEndsWithError reports whether the final result of a function signature is the built-in error type.
func resultListEndsWithError(list *ast.FieldList) bool {
	if list == nil || len(list.List) == 0 {
		return false
	}
	last := list.List[len(list.List)-1]
	ident, ok := last.Type.(*ast.Ident)
	return ok && ident.Name == "error"
}
