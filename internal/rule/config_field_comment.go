// Package rule defines gruff-go's rule registry and analysers.
// This file implements the config-field-comment rule that requires doc comments
// on exported struct fields inside opt-in paths (typically configuration types).
package rule

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/pathfilter"
)

// ConfigFieldCommentRule flags exported struct fields without a doc comment within configured paths.
// It is default-disabled and only scopes via includePaths/excludePaths because broad enforcement on
// every struct produces noise on obvious fields (`Name string`, `Path string`). The rule is meant to
// be opted-in for user-facing configuration schema types so maintainers document each knob.
type ConfigFieldCommentRule struct {
	// IncludePaths restricts enforcement to file paths matching at least one of the supplied globs.
	IncludePaths []string
	// ExcludePaths skips enforcement for file paths matching any of the supplied globs.
	ExcludePaths []string
}

// Definition declares the docs.config-field-comment opt-in rule that requires doc comments on exported struct fields inside includePaths.
func (r ConfigFieldCommentRule) Definition() Definition {
	return Definition{
		ID:             "docs.config-field-comment",
		Title:          "Config field comment",
		Description:    "Flags exported fields on struct types declared inside configured includePaths that have no useful doc comment. Embedded and unexported fields are out of scope. Default-disabled and intended for user-facing configuration schema types.",
		Pillar:         finding.PillarDocumentation,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: false,
		Options: map[string]any{
			"excludePaths": []string{},
			"includePaths": []string{},
		},
		Tags:        []string{"comments", "documentation", "opt-in", "struct-fields"},
		Remediation: "Add a doc comment to every exported field of structs declared in the configured includePaths.",
	}
}

// AnalyzeUnit emits a finding for each exported struct field in scope that lacks a useful doc comment.
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

// appliesToPath reports whether the rule should analyse the given file path under its include/exclude config.
func (r ConfigFieldCommentRule) appliesToPath(path string) bool {
	if len(r.IncludePaths) > 0 && !pathfilter.MatchesAny(r.IncludePaths, path) {
		return false
	}
	if len(r.ExcludePaths) > 0 && pathfilter.MatchesAny(r.ExcludePaths, path) {
		return false
	}
	return true
}

// structFieldFindings emits one finding per exported, undocumented field inside the struct type.
// Embedded fields (no Names) and unexported fields are skipped without producing findings.
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
			// Trailing inline comments live in field.Comment, not field.Doc:
			//   Port int // TCP port used by the server
			// Treat either form as sufficient documentation; otherwise the
			// rule misreports every project that prefers same-line field docs.
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
