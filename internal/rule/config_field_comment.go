// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements docs.config-field-comment, which reports exported struct fields that have no useful doc comment.
// It checks only files matched by includePaths, so users usually scope it to their configuration schema types.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/pathfilter"
)

// ConfigFieldCommentRule flags exported struct fields without a useful doc comment in files matched by IncludePaths and not by ExcludePaths.
//
// It is enabled by default but reports nothing until IncludePaths is set, since every struct would be noisy on obvious fields like Name or Path.
// Scope it to user-facing configuration schema types when maintainers want every config knob documented.
type ConfigFieldCommentRule struct {
	// IncludePaths restricts enforcement to file paths matching at least one of the supplied globs.
	IncludePaths []string
	// ExcludePaths skips enforcement for file paths matching any of the supplied globs.
	ExcludePaths []string
}

// Definition declares the docs.config-field-comment rule that requires doc comments on exported struct fields.
//
// It returns the fixed rule metadata: advisory severity, medium confidence, parser capability and enabled by default.
// Its includePaths and excludePaths options default to empty lists, and AnalyzeUnit reports nothing while IncludePaths is empty.
func (r ConfigFieldCommentRule) Definition() Definition {
	return Definition{
		ID:             "docs.config-field-comment",
		Title:          "Config field comment",
		Description:    "Flags exported fields on struct types in configured includePaths that have no useful doc comment. Embedded and unexported fields are out of scope.",
		Pillar:         finding.PillarDocumentation,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Options: map[string]any{
			"excludePaths": []string{},
			"includePaths": []string{},
		},
		Tags:        []string{"comments", "documentation", "struct-fields"},
		Remediation: "Add a doc comment to every exported field of structs declared in the configured includePaths.",
	}
}

// AnalyzeUnit emits a finding for each exported struct field in scope that lacks a useful doc comment.
//
// unit is the parsed source file; only top-level type declarations whose type is an unparenthesized struct literal are checked.
// It returns the findings in source order, or an empty slice when every exported field in scope is documented.
// The result is nil when unit has no AST or FileSet, or when its path misses IncludePaths or matches ExcludePaths.
func (r ConfigFieldCommentRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !r.appliesToPath(unit.File.Path) {
		return nil
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok || structType.Fields == nil {
				continue
			}
			findings = append(findings, r.structFieldFindings(unit, typeSpec, structType)...)
		}
	}
	return findings
}

// appliesToPath reports whether the rule should analyse the file at path under its IncludePaths and ExcludePaths globs.
//
// It reports false when IncludePaths is empty or misses path, or when ExcludePaths matches it, so that file gives no config-field findings.
func (r ConfigFieldCommentRule) appliesToPath(path string) bool {
	if len(r.IncludePaths) == 0 || !pathfilter.MatchesAny(r.IncludePaths, path) {
		return false
	}
	if len(r.ExcludePaths) > 0 && pathfilter.MatchesAny(r.ExcludePaths, path) {
		return false
	}
	return true
}

// structFieldFindings emits one finding per exported, undocumented field inside the struct type.
//
// Embedded fields (no Names) and unexported fields are skipped without producing findings.
// A field counts as documented when either its doc comment or its trailing same-line comment is useful for that field name.
//
// unit supplies the file path and positions, typeSpec names the struct in each message and symbol, and structType holds the fields checked.
// It returns one finding per undocumented exported name in field order, or an empty, non-nil slice when every exported field is documented.
func (r ConfigFieldCommentRule) structFieldFindings(unit parser.Unit, typeSpec *ast.TypeSpec, structType *ast.StructType) []finding.Finding {
	findings := []finding.Finding{}
	for _, field := range structType.Fields.List {
		if len(field.Names) == 0 {
			continue
		}
		for _, name := range field.Names {
			if !ast.IsExported(name.Name) {
				continue
			}
			if hasUsefulDeclarationComment(field.Doc, name.Name, 0) {
				continue
			}
			// A comment after the field on the same line lives in field.Comment, not field.Doc.
			// Either form counts; checking only field.Doc would misreport every project that documents its fields on the same line.
			if hasUsefulDeclarationComment(field.Comment, name.Name, 0) {
				continue
			}
			position := unit.FileSet.Position(name.NamePos)
			symbol := typeSpec.Name.Name + "." + name.Name
			findings = append(findings, finding.Finding{
				Message:  fmt.Sprintf("struct field %q on %q has no doc comment", name.Name, typeSpec.Name.Name),
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   symbol,
				Metadata: map[string]any{
					"kind":   "field",
					"field":  name.Name,
					"symbol": symbol,
					"type":   typeSpec.Name.Name,
				},
			})
		}
	}
	return findings
}
