// Package rule defines gruff-go's rule registry and analysers.
//
// This file holds naming.get-prefix, an opt-in rule that flags Get-prefixed receiver methods with accessor-shaped signatures.
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
//
// Its fields mirror the excludePaths and excludeNames options; with both empty, no file path or method name is exempt.
type GetPrefixRule struct {
	// ExcludePaths skips enforcement for file paths matching any of the supplied globs.
	ExcludePaths []string
	// ExcludeNames lists method names that are exempt from the Get-prefix check by exact match.
	ExcludeNames []string
}

// Definition declares the naming.get-prefix rule that flags zero-argument accessor methods whose names begin with Get.
// It returns the fixed definition: opt-in, advisory, medium confidence, with excludePaths and excludeNames options defaulting to empty lists.
func (r GetPrefixRule) Definition() Definition {
	return Definition{
		ID:             "naming.get-prefix",
		Title:          "Get prefix",
		Description:    "Flags receiver accessor methods that use a Get prefix instead of a direct noun phrase.",
		Pillar:         finding.PillarModernisation,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Tags:           []string{"go-style", "naming"},
		Options:        map[string]any{"excludePaths": []string{}, "excludeNames": []string{}},
		Remediation:    "Rename accessor-style methods from GetThing to Thing unless parameters make the lookup action explicit.",
	}
}

// AnalyzeUnit walks the top-level function declarations in unit and reports each Get-prefixed accessor method isGetterPrefixCandidate accepts.
//
// It returns nil when unit lacks an AST or file set, when an ExcludePaths glob matches its path, or when shouldSkipGeneratedUnit skips it.
// Otherwise it returns one finding per qualifying method at its name, skipping ExcludeNames entries; an empty slice means none qualified.
// The ctx value only feeds that generated-unit check.
func (r GetPrefixRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || shouldSkipGeneratedUnit(unit, ctx) || pathfilter.MatchesAny(r.ExcludePaths, unit.File.Path) {
		return nil
	}
	excludeNames := exactStringSet(r.ExcludeNames)
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		// An excludeNames entry must equal the method name exactly, so GetName exempts that name on every receiver type but not GetNames.
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

// isGetterPrefixCandidate reports whether fn is an accessor-shaped Get receiver method; false means no naming.get-prefix finding.
//
// Free functions are skipped on purpose: package-level helpers such as GetLogger(ctx) often encode context lookup, not field-style access.
// The fn declaration qualifies only with a receiver, no parameters, a name that is Get plus an uppercase letter, and a getter result shape.
func isGetterPrefixCandidate(fn *ast.FuncDecl) bool {
	if !hasGetPrefix(fn.Name.Name) {
		return false
	}
	if !hasGetterResultShape(fn.Type.Results) {
		return false
	}
	return fn.Recv != nil && fieldListCount(fn.Type.Params) == 0
}

// hasGetterResultShape reports whether results matches the single-value or value-plus-error accessor convention.
//
// The results list is counted per name, so one result passes, two pass only when the last type is error, and nil, empty, or longer lists fail.
func hasGetterResultShape(results *ast.FieldList) bool {
	count := fieldListCount(results)
	if count == 1 {
		return true
	}
	return count == 2 && resultListEndsWithError(results)
}

// hasGetPrefix reports whether name starts with Get followed by an uppercase letter.
// False for a bare Get or words like Getter and Getaway, so methods with those names are never flagged.
func hasGetPrefix(name string) bool {
	if !strings.HasPrefix(name, "Get") {
		return false
	}
	runes := []rune(name)
	return len(runes) > 3 && unicode.IsUpper(runes[3])
}

// fieldListCount returns the total number of fields across all entries in a FieldList.
// A nil list gives zero; each field counts once per declared name, or once when it is unnamed, such as a bare result type.
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

// resultListEndsWithError reports whether the final result type of a function signature is written as the plain identifier error.
//
// The list argument is a signature's result list; it reports false when list is nil or has no fields.
// Without type information, a shadowing type named error also matches, while a qualified or composite last type reports false.
func resultListEndsWithError(list *ast.FieldList) bool {
	if list == nil || len(list.List) == 0 {
		return false
	}
	last := list.List[len(list.List)-1]
	ident, ok := last.Type.(*ast.Ident)
	return ok && ident.Name == "error"
}
