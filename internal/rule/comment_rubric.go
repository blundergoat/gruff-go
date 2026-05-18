package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/pathfilter"
)

const (
	commentRubricMinPackageCommentLines = 2
)

type CommentRubricRule struct {
	MinPackageCommentLines   int
	IncludePaths             []string
	ExcludePaths             []string
	RequirePackageSummary    bool
	RequireFunctionComments  bool
	RequireNamedTypeComments bool
	RequireStructComments    bool
	RequireInterfaceComments bool
	RequireConstComments     bool
	RequireVarComments       bool
	IgnoreTests              bool
}

func (r CommentRubricRule) minPackageCommentLines() int {
	if r.MinPackageCommentLines <= 0 {
		return commentRubricMinPackageCommentLines
	}
	return r.MinPackageCommentLines
}

func (r CommentRubricRule) Definition() Definition {
	return Definition{
		ID:             "docs.comment-rubric",
		Title:          "Comment rubric",
		Description:    "Flags files that opt into stricter maintainer comments for package summaries, functions, named types, and package-scope values.",
		Pillar:         finding.PillarDocumentation,
		Severity:       finding.SeverityLow,
		Confidence:     finding.ConfidenceMedium,
		DefaultEnabled: true,
		Thresholds: map[string]float64{
			"minPackageCommentLines": float64(r.minPackageCommentLines()),
		},
		Options: map[string]any{
			"excludePaths":             []string{},
			"ignoreTests":              false,
			"includePaths":             []string{},
			"requireConstComments":     false,
			"requireFunctionComments":  false,
			"requireInterfaceComments": false,
			"requireNamedTypeComments": false,
			"requirePackageSummary":    false,
			"requireStructComments":    false,
			"requireVarComments":       false,
		},
		Tags:        []string{"comments", "documentation", "opt-in", "rubric"},
		Remediation: "Add maintainer-oriented package summaries and directly attached comments for the selected declaration kinds.",
	}
}

func (r CommentRubricRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !r.appliesToPath(unit.File.Path) {
		return nil
	}
	if r.IgnoreTests && isGoTestFile(unit.File.Path) {
		return nil
	}
	findings := []finding.Finding{}
	if r.RequirePackageSummary {
		findings = append(findings, r.packageSummaryFindings(unit)...)
	}
	for _, decl := range unit.AST.Decls {
		switch current := decl.(type) {
		case *ast.FuncDecl:
			if r.RequireFunctionComments {
				findings = append(findings, r.funcCommentFindings(unit, current)...)
			}
		case *ast.GenDecl:
			findings = append(findings, r.genDeclCommentFindings(unit, current)...)
		}
	}
	return findings
}

func (r CommentRubricRule) appliesToPath(path string) bool {
	if len(r.IncludePaths) > 0 && !pathfilter.MatchesAny(r.IncludePaths, path) {
		return false
	}
	if len(r.ExcludePaths) > 0 && pathfilter.MatchesAny(r.ExcludePaths, path) {
		return false
	}
	return true
}

func (r CommentRubricRule) packageSummaryFindings(unit parser.Unit) []finding.Finding {
	stats := commentStats(unit.AST.Doc)
	minLines := r.minPackageCommentLines()
	if stats.lines >= minLines {
		return nil
	}
	message := "package summary is missing"
	if stats.lines > 0 {
		message = fmt.Sprintf("package summary has %d non-empty lines, below required %d lines", stats.lines, minLines)
	}
	return []finding.Finding{{
		Message:  message,
		File:     unit.File.Path,
		Location: &finding.Location{Line: 1},
		Metadata: map[string]any{
			"kind":      "package",
			"lines":     stats.lines,
			"threshold": minLines,
		},
	}}
}

func (r CommentRubricRule) funcCommentFindings(unit parser.Unit, fn *ast.FuncDecl) []finding.Finding {
	if hasUsefulDeclarationComment(fn.Doc, fn.Name.Name) {
		return nil
	}
	position := unit.FileSet.Position(fn.Name.NamePos)
	symbol := functionName(fn)
	return []finding.Finding{{
		Message:  fmt.Sprintf("%s %q has no attached comment", funcKind(fn), symbol),
		File:     unit.File.Path,
		Location: &finding.Location{Line: position.Line, Column: position.Column},
		Symbol:   symbol,
		Metadata: map[string]any{"kind": funcKind(fn), "symbol": symbol},
	}}
}

func (r CommentRubricRule) genDeclCommentFindings(unit parser.Unit, decl *ast.GenDecl) []finding.Finding {
	switch decl.Tok {
	case token.TYPE:
		return r.typeCommentFindings(unit, decl)
	case token.CONST:
		if r.RequireConstComments {
			return r.valueCommentFindings(unit, decl, "const")
		}
	case token.VAR:
		if r.RequireVarComments {
			return r.valueCommentFindings(unit, decl, "var")
		}
	}
	return nil
}

func (r CommentRubricRule) typeCommentFindings(unit parser.Unit, decl *ast.GenDecl) []finding.Finding {
	findings := []finding.Finding{}
	for _, spec := range decl.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok || !r.requiresTypeComment(typeSpec) || hasUsefulTypeComment(decl, typeSpec) {
			continue
		}
		position := unit.FileSet.Position(typeSpec.Name.NamePos)
		kind := typeCommentKind(typeSpec)
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("%s %q has no attached comment", kind, typeSpec.Name.Name),
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Symbol:   typeSpec.Name.Name,
			Metadata: map[string]any{"kind": kind, "symbol": typeSpec.Name.Name},
		})
	}
	return findings
}

func (r CommentRubricRule) requiresTypeComment(spec *ast.TypeSpec) bool {
	if r.RequireNamedTypeComments {
		return true
	}
	switch spec.Type.(type) {
	case *ast.StructType:
		return r.RequireStructComments
	case *ast.InterfaceType:
		return r.RequireInterfaceComments
	default:
		return false
	}
}

func (r CommentRubricRule) valueCommentFindings(unit parser.Unit, decl *ast.GenDecl, kind string) []finding.Finding {
	findings := []finding.Finding{}
	for _, spec := range decl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, name := range valueSpec.Names {
			if hasUsefulValueComment(decl, valueSpec, name.Name) {
				continue
			}
			position := unit.FileSet.Position(name.NamePos)
			findings = append(findings, finding.Finding{
				Message:  fmt.Sprintf("package-scope %s %q has no attached comment", kind, name.Name),
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   name.Name,
				Metadata: map[string]any{"kind": kind, "symbol": name.Name},
			})
		}
	}
	return findings
}

type commentStatsResult struct {
	lines int
	words int
}

func commentStats(group *ast.CommentGroup) commentStatsResult {
	if group == nil {
		return commentStatsResult{}
	}
	text := group.Text()
	lines := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			lines++
		}
	}
	return commentStatsResult{lines: lines, words: len(strings.Fields(text))}
}

func hasUsefulComment(group *ast.CommentGroup) bool {
	stats := commentStats(group)
	return stats.lines > 0 && stats.words > 0
}

func hasUsefulDeclarationComment(group *ast.CommentGroup, symbol string) bool {
	if !hasUsefulComment(group) {
		return false
	}
	return normalizeCommentText(group.Text()) != normalizeCommentText(symbol)
}

func hasUsefulTypeComment(decl *ast.GenDecl, spec *ast.TypeSpec) bool {
	if hasUsefulDeclarationComment(spec.Doc, spec.Name.Name) {
		return true
	}
	if len(decl.Specs) > 1 {
		return hasUsefulComment(decl.Doc)
	}
	return hasUsefulDeclarationComment(decl.Doc, spec.Name.Name)
}

func hasUsefulValueComment(decl *ast.GenDecl, spec *ast.ValueSpec, symbol string) bool {
	if hasUsefulDeclarationComment(spec.Doc, symbol) {
		return true
	}
	if len(decl.Specs) > 1 || len(spec.Names) > 1 {
		return hasUsefulComment(decl.Doc)
	}
	return hasUsefulDeclarationComment(decl.Doc, symbol)
}

func normalizeCommentText(value string) string {
	mapped := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return ' '
	}, value)
	return strings.Join(strings.Fields(mapped), " ")
}

func typeCommentKind(spec *ast.TypeSpec) string {
	switch spec.Type.(type) {
	case *ast.StructType:
		return "struct type"
	case *ast.InterfaceType:
		return "interface type"
	default:
		return "named type"
	}
}
