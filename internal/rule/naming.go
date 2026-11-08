// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements naming.identifier-quality, the rule that flags variables and constants named like foo, tmp or stuff.
// Each match is an advisory finding at the identifier, asking the author to rename it to describe its role.
package rule

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// defaultPlaceholderNames is a conservative list of identifiers that almost always indicate hurried code.
//
// Project configs override the list via rules.<id>.options.placeholderNames; the override replaces this list rather than extending it.
// When PlaceholderNames is empty, the rule matches against this list.
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

// IdentifierQualityRule flags variables and constants whose names match a configured placeholder list.
//
// It checks names bound by := and by var or const declarations, package-level ones included, and skips _test.go files.
// Range variables, function parameters and struct fields are not checked, so a tmp loop variable passes.
type IdentifierQualityRule struct {
	// PlaceholderNames overrides the default placeholder list (foo, bar, tmp, ...) the rule treats as low-quality identifiers.
	// A nil or empty list keeps the defaults; a list of only blank entries matches nothing and turns the rule off.
	PlaceholderNames []string
}

// Definition declares the naming.identifier-quality rule that fires when variable or constant names match the configured placeholderNames list.
//
// It returns a fixed Definition with advisory severity, medium confidence and DefaultEnabled true.
// Its placeholderNames option always holds defaultPlaceholderNames, even when the receiver sets PlaceholderNames.
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

// AnalyzeUnit walks a parsed unit and emits findings for placeholder-named variables and constants.
//
// It returns one finding per name, matched ignoring case, bound by a := assignment or a var or const spec, package-level specs included.
// It returns nil for a unit without an AST or file set, a _test.go file, or an empty placeholder set, and an empty slice when no name matches.
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
		switch binding := node.(type) {
		case *ast.AssignStmt:
			// Plain = assignments are skipped, so assigning to an existing tmp again adds no second finding.
			if binding.Tok.String() != ":=" {
				return true
			}
			for _, lhs := range binding.Lhs {
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
			for _, ident := range binding.Names {
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

// placeholderSet returns the lowercased placeholder names the rule will match against, as a set keyed by name.
//
// It uses PlaceholderNames when non-empty and defaultPlaceholderNames otherwise, trimming surrounding whitespace and skipping blank entries.
// An empty result, from a list of only blank entries, makes AnalyzeUnit report nothing for every file.
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
//
// The unit supplies the file path and the FileSet that turns the NamePos of ident into a line and column.
// It returns a Finding with only Message, File, Location, Symbol and the identifier metadata set from ident; other fields stay zero.
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
