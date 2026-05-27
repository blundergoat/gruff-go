// Package rule defines gruff-go's rule registry and analysers.
// This file implements the identifier-quality placeholder rule.
package rule

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// defaultPlaceholderNames is a conservative list of identifiers that almost
// always indicate hurried code. Project configs override the list via
// rules.<id>.options.placeholderNames.
var defaultPlaceholderNames = []string{
	"foo",
	"bar",
	"baz",
	"tmp",
	"temp",
	"obj",
	"todo",
	"thing",
	"stuff",
}

// IdentifierQualityRule flags local identifiers whose names match a configured placeholder list.
type IdentifierQualityRule struct {
	// PlaceholderNames overrides the default placeholder list (foo, bar, tmp, ...) the rule treats as low-quality identifiers.
	PlaceholderNames []string
}

// Definition declares the naming.identifier-quality rule that fires when local variables match the configured placeholderNames list.
func (r IdentifierQualityRule) Definition() Definition {
	return Definition{
		ID:             "naming.identifier-quality",
		Title:          "Identifier quality",
		Description:    "Flags local variables and constants whose names match a list of placeholder tokens that rarely survive a careful review.",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Tags:           []string{"naming"},
		Options:        map[string]any{"placeholderNames": defaultPlaceholderNames},
		Remediation:    "Rename the identifier to something that names its role, or remove it if it is no longer needed.",
	}
}

// AnalyzeUnit walks a parsed unit and emits findings for placeholder-named local identifiers.
func (r IdentifierQualityRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || strings.HasSuffix(unit.File.Path, "_test.go") {
		return nil
	}
	placeholders := r.placeholderSet()
	if len(placeholders) == 0 {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		switch decl := node.(type) {
		case *ast.AssignStmt:
			if decl.Tok.String() != ":=" {
				return true
			}
			for _, lhs := range decl.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || ident.Name == "_" {
					continue
				}
				if !placeholders[strings.ToLower(ident.Name)] {
					continue
				}
				findings = append(findings, makeNamingFinding(unit, ident))
			}
		case *ast.ValueSpec:
			for _, ident := range decl.Names {
				if ident.Name == "_" || !placeholders[strings.ToLower(ident.Name)] {
					continue
				}
				findings = append(findings, makeNamingFinding(unit, ident))
			}
		}
		return true
	})
	return findings
}

// placeholderSet returns the lowercased placeholder names the rule will match against.
func (r IdentifierQualityRule) placeholderSet() map[string]bool {
	source := r.PlaceholderNames
	if len(source) == 0 {
		source = defaultPlaceholderNames
	}
	out := make(map[string]bool, len(source))
	for _, name := range source {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		out[strings.ToLower(trimmed)] = true
	}
	return out
}

// makeNamingFinding builds a placeholder-identifier finding anchored at the identifier's position.
func makeNamingFinding(unit parser.Unit, ident *ast.Ident) finding.Finding {
	position := unit.FileSet.Position(ident.NamePos)
	return finding.Finding{
		Message:  fmt.Sprintf("identifier %q matches placeholder list; rename to describe the role", ident.Name),
		File:     unit.File.Path,
		Location: &finding.Location{Line: position.Line, Column: position.Column},
		Symbol:   ident.Name,
		Metadata: map[string]any{"identifier": ident.Name},
	}
}
