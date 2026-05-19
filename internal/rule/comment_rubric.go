// Package rule defines gruff-go's rule registry and analysers.
// This file implements the comment-rubric rule and its supporting helpers.
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

// commentRubricMinPackageCommentLines is the default minimum line count for package summaries.
// A one-line `// Package foo …` summary passes when the rule's `requirePackageSummary` is enabled
// and no threshold is configured. Projects that want the stricter floor opt in via `threshold: 2`.
const (
	commentRubricMinPackageCommentLines = 1
)

// commentRubricStopwords lists common English fillers that do not count toward
// `minWordsBeyondSymbol`. The set is intentionally minimal: articles, low-content prepositions,
// and basic copulas. Verbs like "returns", "describes", and "reports" are NOT stopwords because
// they carry the intent of a doc comment.
var commentRubricStopwords = map[string]bool{
	"a": true, "an": true, "the": true,
	"and": true, "or": true, "but": true,
	"of": true, "in": true, "on": true, "at": true, "by": true, "for": true,
	"to": true, "from": true, "with": true, "as": true, "into": true, "onto": true,
	"is": true, "are": true, "was": true, "were": true, "be": true, "been": true, "being": true,
	"it": true, "its": true, "this": true, "that": true, "these": true, "those": true,
	"not": true, "no": true,
}

// CommentRubricRule enforces maintainer-oriented comments for selected declaration kinds.
type CommentRubricRule struct {
	MinPackageCommentLines   int
	MinWordsBeyondSymbol     int
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

// minPackageCommentLines returns the configured minimum package summary lines, falling back to the default.
func (r CommentRubricRule) minPackageCommentLines() int {
	if r.MinPackageCommentLines <= 0 {
		return commentRubricMinPackageCommentLines
	}
	return r.MinPackageCommentLines
}

// Definition declares the docs.comment-rubric opt-in policy bundle covering package summaries, function comments, named types, and the minWordsBeyondSymbol substantive-token threshold.
func (r CommentRubricRule) Definition() Definition {
	return Definition{
		ID:             "docs.comment-rubric",
		Title:          "Comment rubric",
		Description:    "Flags files that opt into stricter maintainer comments for package summaries, functions, named types, and package-scope values. With minWordsBeyondSymbol set, the rule additionally requires the comment to carry that many tokens beyond the symbol's own name (rejects name-restatement boilerplate). On _test.go files the rule does not enforce requireConstComments or requireVarComments even when ignoreTests is false; function, type, and package-summary checks still apply.",
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
			"minWordsBeyondSymbol":     0,
			"requireConstComments":     false,
			"requireFunctionComments":  false,
			"requireInterfaceComments": false,
			"requireNamedTypeComments": false,
			"requirePackageSummary":    false,
			"requireStructComments":    false,
			"requireVarComments":       false,
		},
		Tags:        []string{"comments", "documentation", "opt-in", "rubric"},
		Remediation: "Add maintainer-oriented package summaries and directly attached comments for the selected declaration kinds. When minWordsBeyondSymbol is set, the comment must add at least that many tokens beyond the symbol's own identifier tokens; replace name-restatement summaries with substantive context.",
	}
}

// AnalyzeUnit walks a parsed unit and emits findings for missing rubric comments.
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

// appliesToPath reports whether the rule should analyse the given file path under its include/exclude config.
func (r CommentRubricRule) appliesToPath(path string) bool {
	if len(r.IncludePaths) > 0 && !pathfilter.MatchesAny(r.IncludePaths, path) {
		return false
	}
	if len(r.ExcludePaths) > 0 && pathfilter.MatchesAny(r.ExcludePaths, path) {
		return false
	}
	return true
}

// packageSummaryFindings emits a finding when the package summary fails to meet the minimum line threshold.
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

// funcCommentFindings emits a finding when a top-level function or method has no useful attached comment.
// The symbol passed to hasUsefulDeclarationComment is the qualified function name (Receiver.Method for
// methods, plain name otherwise) so that minWordsBeyondSymbol counts comment tokens against the full
// identifier set, which is what catches paraphrase boilerplate like
// "// Definition returns the rule metadata for FooRule." on receiver methods.
func (r CommentRubricRule) funcCommentFindings(unit parser.Unit, fn *ast.FuncDecl) []finding.Finding {
	symbol := functionName(fn)
	if hasUsefulDeclarationComment(fn.Doc, symbol, r.MinWordsBeyondSymbol) {
		return nil
	}
	position := unit.FileSet.Position(fn.Name.NamePos)
	return []finding.Finding{{
		Message:  fmt.Sprintf("%s %q has no attached comment", funcKind(fn), symbol),
		File:     unit.File.Path,
		Location: &finding.Location{Line: position.Line, Column: position.Column},
		Symbol:   symbol,
		Metadata: map[string]any{"kind": funcKind(fn), "symbol": symbol},
	}}
}

// genDeclCommentFindings dispatches to per-kind helpers for type, const, and var declarations.
// Const and var enforcement is unconditionally suppressed on Go test files because fixture-scope
// values rarely benefit from required comments even when the rest of the rubric stays strict.
// IgnoreTests (whole-file exemption) is still honoured by AnalyzeUnit before this method runs.
func (r CommentRubricRule) genDeclCommentFindings(unit parser.Unit, decl *ast.GenDecl) []finding.Finding {
	switch decl.Tok {
	case token.TYPE:
		return r.typeCommentFindings(unit, decl)
	case token.CONST:
		if r.RequireConstComments && !isGoTestFile(unit.File.Path) {
			return r.valueCommentFindings(unit, decl, "const")
		}
	case token.VAR:
		if r.RequireVarComments && !isGoTestFile(unit.File.Path) {
			return r.valueCommentFindings(unit, decl, "var")
		}
	}
	return nil
}

// typeCommentFindings emits findings for type specs that need comments under the configured policy.
func (r CommentRubricRule) typeCommentFindings(unit parser.Unit, decl *ast.GenDecl) []finding.Finding {
	findings := []finding.Finding{}
	for _, spec := range decl.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok || !r.requiresTypeComment(typeSpec) || hasUsefulTypeComment(decl, typeSpec, r.MinWordsBeyondSymbol) {
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

// requiresTypeComment reports whether the rule's policy demands a comment for the given type spec.
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

// valueCommentFindings emits findings for package-scope const or var specs with no useful comment.
func (r CommentRubricRule) valueCommentFindings(unit parser.Unit, decl *ast.GenDecl, kind string) []finding.Finding {
	findings := []finding.Finding{}
	for _, spec := range decl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, name := range valueSpec.Names {
			if hasUsefulValueComment(decl, valueSpec, name.Name, r.MinWordsBeyondSymbol) {
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

// commentStatsResult records how many non-empty lines and whitespace-separated words a comment group contains.
type commentStatsResult struct {
	lines int
	words int
}

// commentStats summarises a comment group as line and word counts after trimming trailing whitespace.
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

// hasUsefulComment reports whether the comment group has at least one non-empty line and word.
func hasUsefulComment(group *ast.CommentGroup) bool {
	stats := commentStats(group)
	return stats.lines > 0 && stats.words > 0
}

// hasUsefulDeclarationComment reports whether the comment adds context beyond the symbol name itself.
// When minWordsBeyondSymbol is positive, the comment must additionally contribute at least that many
// unique tokens that are not part of the symbol's own tokenised identifier set.
func hasUsefulDeclarationComment(group *ast.CommentGroup, symbol string, minWordsBeyondSymbol int) bool {
	if !hasUsefulComment(group) {
		return false
	}
	if normalizeCommentText(group.Text()) == normalizeCommentText(symbol) {
		return false
	}
	if minWordsBeyondSymbol > 0 && commentTokensBeyondSymbol(group.Text(), symbol) < minWordsBeyondSymbol {
		return false
	}
	return true
}

// hasUsefulTypeComment reports whether a type spec or its containing GenDecl supplies a useful comment.
func hasUsefulTypeComment(decl *ast.GenDecl, spec *ast.TypeSpec, minWordsBeyondSymbol int) bool {
	if hasUsefulDeclarationComment(spec.Doc, spec.Name.Name, minWordsBeyondSymbol) {
		return true
	}
	if len(decl.Specs) > 1 {
		return hasUsefulComment(decl.Doc)
	}
	return hasUsefulDeclarationComment(decl.Doc, spec.Name.Name, minWordsBeyondSymbol)
}

// hasUsefulValueComment reports whether a const or var spec or its containing GenDecl supplies a useful comment.
func hasUsefulValueComment(decl *ast.GenDecl, spec *ast.ValueSpec, symbol string, minWordsBeyondSymbol int) bool {
	if hasUsefulDeclarationComment(spec.Doc, symbol, minWordsBeyondSymbol) {
		return true
	}
	if len(decl.Specs) > 1 || len(spec.Names) > 1 {
		return hasUsefulComment(decl.Doc)
	}
	return hasUsefulDeclarationComment(decl.Doc, symbol, minWordsBeyondSymbol)
}

// commentTokensBeyondSymbol returns the count of unique substantive comment tokens that do not
// appear in the symbol's tokenised identifier set. Common English stopwords (see
// commentRubricStopwords) are excluded so that filler words like "the" and "for" cannot push a
// paraphrase comment over the `minWordsBeyondSymbol` bar. Both inputs are first split on
// non-alphanumeric runs (so a qualified method name like "Receiver.Method" contributes both sides
// to the symbol set), then each word is routed through splitIdentifierTokens for camel-case-aware
// sub-token matching.
func commentTokensBeyondSymbol(comment, symbol string) int {
	symbolTokens := identifierTokenSet(symbol)
	seen := map[string]bool{}
	count := 0
	for _, token := range identifierTokens(comment) {
		if commentRubricStopwords[token] || symbolTokens[token] || seen[token] {
			continue
		}
		seen[token] = true
		count++
	}
	return count
}

// identifierTokenSet returns the lowercased camel-case-split token set for the supplied identifier
// (or identifier-like string). Non-alphanumeric characters are treated as word boundaries so that
// qualified names like "Receiver.Method" contribute both halves.
func identifierTokenSet(identifier string) map[string]bool {
	out := map[string]bool{}
	for _, token := range identifierTokens(identifier) {
		out[token] = true
	}
	return out
}

// identifierTokens returns the ordered list of lowercased sub-tokens from an identifier or free-form
// text. The string is first split on non-alphanumeric runs, then each word is routed through
// splitIdentifierTokens so camel-case sub-tokens contribute separately.
func identifierTokens(text string) []string {
	mapped := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return ' '
	}, text)
	tokens := []string{}
	for _, word := range strings.Fields(mapped) {
		for _, token := range splitIdentifierTokens(word) {
			lower := strings.ToLower(strings.TrimSpace(token))
			if lower == "" {
				continue
			}
			tokens = append(tokens, lower)
		}
	}
	return tokens
}

// normalizeCommentText lowercases a comment, replaces non-alphanumeric characters with spaces, and collapses whitespace.
func normalizeCommentText(value string) string {
	mapped := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return ' '
	}, value)
	return strings.Join(strings.Fields(mapped), " ")
}

// typeCommentKind names the high-level shape (struct, interface, or named type) of a type spec.
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
