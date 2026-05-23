// Package rule defines gruff-go's rule registry and analysers.
// Get-prefix detection stays parser-only by matching method names and result shapes without type information.
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
		Tags:           []string{"go-style", "naming"},
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
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("function %q uses Get prefix for an accessor-style receiver method", fn.Name.Name),
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Symbol:   fn.Name.Name,
			Metadata: map[string]any{"method": fn.Name.Name, "kind": "receiver method"},
		})
	}
	return findings
}

// isGetterPrefixCandidate reports whether a function declaration is an
// accessor-shaped Get* receiver method. Free functions are deliberately skipped:
// package-level helpers such as `GetLogger(ctx)` often encode context lookup
// semantics rather than simple field-style access.
func isGetterPrefixCandidate(fn *ast.FuncDecl) bool {
	if !hasGetPrefix(fn.Name.Name) {
		return false
	}
	if !hasGetterResultShape(fn.Type.Results) {
		return false
	}
	return fn.Recv != nil && fieldListCount(fn.Type.Params) == 0
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
