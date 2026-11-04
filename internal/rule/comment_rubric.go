// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements the docs.comment-rubric rule and its supporting helpers.
// Every check is off until the config file turns on an option such as requirePackageSummary or requireFunctionComments.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"path"
	"strings"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/pathfilter"
)

// commentRubricMinPackageCommentLines is the default minimum line count for package summaries.
//
// A one-line package summary passes when requirePackageSummary is on and no threshold is configured.
// Projects that want the stricter floor opt in via threshold: 2.
const (
	commentRubricMinPackageCommentLines = 1
)

// commentRubricStopwords lists common English fillers that do not count toward minWordsBeyondSymbol.
//
// The set is intentionally minimal: articles, conjunctions, low-content prepositions, basic copulas, pronouns like it and this, and not or no.
// Verbs like returns, describes and reports are not stopwords because they carry the intent of a doc comment.
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
//
// Its fields carry the docs.comment-rubric options listed in Definition, and with every Require flag off the rule reports nothing.
// Each finding names a declaration with no useful attached comment, or a package whose best summary is too short.
type CommentRubricRule struct {
	// MinPackageCommentLines sets the minimum non-empty line count required on each package summary; zero or less means 1.
	MinPackageCommentLines int
	// MinWordsBeyondSymbol is how many substantive tokens a comment must add beyond the symbol's own identifier tokens.
	// It rejects paraphrase boilerplate; zero or less turns the check off.
	MinWordsBeyondSymbol int
	// IncludePaths restricts enforcement to file paths matching at least one of the supplied globs.
	IncludePaths []string
	// ExcludePaths skips enforcement for file paths matching any of the supplied globs.
	ExcludePaths []string
	// RequirePackageSummary turns on the per-package summary check that fires when the package doc is missing or too short.
	RequirePackageSummary bool
	// RequireFunctionComments turns on doc-comment enforcement for every top-level function and method.
	RequireFunctionComments bool
	// RequireNamedTypeComments turns on doc-comment enforcement for every top-level named type declaration.
	RequireNamedTypeComments bool
	// RequireStructComments turns on doc-comment enforcement for struct types specifically.
	RequireStructComments bool
	// RequireInterfaceComments turns on doc-comment enforcement for interface types specifically.
	RequireInterfaceComments bool
	// RequireConstComments turns on doc-comment enforcement for package-scope const declarations.
	RequireConstComments bool
	// RequireVarComments turns on doc-comment enforcement for package-scope var declarations.
	RequireVarComments bool
	// IgnoreTests skips the entire rubric on Go test files (_test.go suffix) when true.
	IgnoreTests bool
}

// minPackageCommentLines returns the configured minimum package summary lines, falling back to the default.
// A zero or negative MinPackageCommentLines gives commentRubricMinPackageCommentLines, which is 1.
func (r CommentRubricRule) minPackageCommentLines() int {
	if r.MinPackageCommentLines <= 0 {
		return commentRubricMinPackageCommentLines
	}
	return r.MinPackageCommentLines
}

// Definition declares the docs.comment-rubric path-scoped policy bundle for package summaries, functions, named types and package-scope values.
//
// Its minWordsBeyondSymbol option sets the substantive-token threshold that rejects name-restatement comments.
// It returns the metadata with every option off, empty or zero, and the minPackageCommentLines threshold from the receiver, 1 when not positive.
func (r CommentRubricRule) Definition() Definition {
	return Definition{
		ID:             "docs.comment-rubric",
		Title:          "Comment rubric",
		Description:    "Flags files that opt into stricter maintainer comments for package summaries, functions, named types, and package-scope values. With minWordsBeyondSymbol set, the rule additionally requires the comment to carry that many tokens beyond the symbol's own name (rejects name-restatement boilerplate). On _test.go files the rule does not enforce requireConstComments or requireVarComments even when ignoreTests is false; function, type, and package-summary checks still apply.",
		Pillar:         finding.PillarDocumentation,
		Severity:       finding.SeverityAdvisory,
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
		Tags:        []string{"comments", "documentation", "rubric"},
		Remediation: "Add maintainer-oriented package summaries and directly attached comments for the selected declaration kinds. When minWordsBeyondSymbol is set, the comment must add at least that many tokens beyond the symbol's own identifier tokens; replace name-restatement summaries with substantive context.",
	}
}

// AnalyzeProject walks every parsed unit and emits rubric findings for the whole scan.
//
// The package-summary check runs once per package, so a summary in an in-scope doc.go covers the package's other in-scope files.
// The function, type, const and var checks stay strictly per unit.
//
// units is every parsed file in the project; package-summary findings come first, and only when RequirePackageSummary is set.
// It returns a non-nil slice, empty when no unit breaks an enabled check.
func (r CommentRubricRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	findings := []finding.Finding{}
	if r.RequirePackageSummary {
		findings = append(findings, r.aggregatedPackageSummaryFindings(units)...)
	}
	for _, unit := range units {
		findings = append(findings, r.analyzeUnitDecls(unit)...)
	}
	return findings
}

// analyzeUnitDecls runs the function, type, const and var checks for a single unit.
//
// Path scope, IgnoreTests and nil-AST guards live here so AnalyzeProject can pass every unit through uniformly.
// It returns nil when unit has no AST or file set, falls outside the configured path scope, or is a test file while IgnoreTests is set.
// Otherwise it returns a non-nil slice of the enabled function, type, const and var findings, empty when every declaration passes.
func (r CommentRubricRule) analyzeUnitDecls(unit parser.Unit) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !r.appliesToPath(unit.File.Path) {
		return nil
	}
	if r.IgnoreTests && isGoTestFile(unit.File.Path) {
		return nil
	}
	findings := []finding.Finding{}
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

// appliesToPath reports whether the rule should analyse path under its IncludePaths and ExcludePaths config.
// It reports false when IncludePaths is set and path matches none of its globs, or when path matches any ExcludePaths glob.
func (r CommentRubricRule) appliesToPath(path string) bool {
	if len(r.IncludePaths) > 0 && !pathfilter.MatchesAny(r.IncludePaths, path) {
		return false
	}
	if len(r.ExcludePaths) > 0 && pathfilter.MatchesAny(r.ExcludePaths, path) {
		return false
	}
	return true
}

// aggregatedPackageSummaryFindings emits at most one package-summary finding per package directory and package name.
//
// The best summary across the package's in-scope files wins, and a finding lands on the lexicographically first file for a stable location.
// IgnoreTests still applies, and a _test-suffixed package whose files are all tests never gets a finding.
//
// units is every parsed file in the project; units without an AST or file set are skipped.
// It returns one finding per package whose best summary is too short, or an empty, non-nil slice when every package passes.
func (r CommentRubricRule) aggregatedPackageSummaryFindings(units []parser.Unit) []finding.Finding {
	packages := r.collectPackageSummaryStates(units)
	return r.packageSummaryFindings(packages)
}

// packageSummaryState records the best package-summary evidence found for one package directory and package name.
// file is the lexicographically first in-scope file, where any finding lands, and bestLines is the longest summary's non-empty line count.
type packageSummaryState struct {
	name       string
	file       string
	bestLines  int
	hasInScope bool
	hasNonTest bool
}

// collectPackageSummaryStates scans in-scope units for package comments and stores the best summary evidence per package.
// It returns a map keyed by directory, a colon and package name, empty when no unit passes the AST, path scope and IgnoreTests filters.
func (r CommentRubricRule) collectPackageSummaryStates(units []parser.Unit) map[string]*packageSummaryState {
	packages := map[string]*packageSummaryState{}
	for _, unit := range units {
		if unit.AST == nil || unit.FileSet == nil {
			continue
		}
		if !r.appliesToPath(unit.File.Path) {
			continue
		}
		if r.IgnoreTests && isGoTestFile(unit.File.Path) {
			continue
		}
		// An external foo_test package in the same directory is tracked apart from foo, so its test files cannot supply foo's summary.
		key := path.Dir(unit.File.Path) + ":" + unit.AST.Name.Name
		state := packages[key]
		if state == nil {
			state = &packageSummaryState{name: unit.AST.Name.Name}
			packages[key] = state
		}
		updatePackageSummaryState(state, unit)
	}
	return packages
}

// updatePackageSummaryState folds the package comment of unit into state.
// It keeps the longest summary's line count and the lexicographically first file path, and notes when unit is not a test file.
func updatePackageSummaryState(state *packageSummaryState, unit parser.Unit) {
	state.hasInScope = true
	if !isGoTestFile(unit.File.Path) {
		state.hasNonTest = true
	}
	stats := commentStats(unit.AST.Doc)
	if stats.lines > state.bestLines {
		state.bestLines = stats.lines
	}
	if state.file == "" || unit.File.Path < state.file {
		state.file = unit.File.Path
	}
}

// packageSummaryFindings emits one finding for each package whose best in-scope summary falls below the configured line threshold.
//
// A _test-suffixed package with only test files is skipped.
// With no summary at all the message reads "package summary is missing"; a short one names its line count and the required count.
// packages comes from collectPackageSummaryStates; it returns the findings in no fixed order, or an empty slice when none is needed.
func (r CommentRubricRule) packageSummaryFindings(packages map[string]*packageSummaryState) []finding.Finding {
	minLines := r.minPackageCommentLines()
	findings := []finding.Finding{}
	for _, state := range packages {
		if !state.hasInScope || state.bestLines >= minLines {
			continue
		}
		if !state.hasNonTest && strings.HasSuffix(state.name, "_test") {
			continue
		}
		message := "package summary is missing"
		if state.bestLines > 0 {
			message = fmt.Sprintf("package summary has %d non-empty lines, below required %d lines", state.bestLines, minLines)
		}
		findings = append(findings, finding.Finding{
			Message:  message,
			File:     state.file,
			Location: &finding.Location{Line: 1},
			Metadata: map[string]any{
				"kind":      "package",
				"lines":     state.bestLines,
				"threshold": minLines,
			},
		})
	}
	return findings
}

// funcCommentFindings emits a finding when a top-level function or method has no useful attached comment.
//
// The symbol checked is Receiver.Method for methods or the plain name, and MinWordsBeyondSymbol counts only tokens outside that name.
// For FooRule.Definition, Definition returns the rule metadata for FooRule adds only returns and metadata, so it fails a minimum above two.
//
// fn is the declaration to check, and unit supplies its file path and the file set for the finding position.
// It returns nil when the comment passes, otherwise one finding at the name of fn.
// That finding says "has no attached comment" even when a comment exists but restates the name or adds too few words.
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

// genDeclCommentFindings dispatches type, const and var declarations to their per-kind helpers.
//
// Const and var checks are always off on Go test files, even with IgnoreTests false, since fixture values rarely need required comments.
// IgnoreTests, the whole-file exemption, is still honoured by analyzeUnitDecls before this method runs.
//
// decl is the general declaration to check, and unit supplies its file path and positions.
// It returns the per-kind findings, or nil for an import, or for a const or var decl when its check is off or the file is a test.
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
//
// decl is a type declaration whose specs are checked, and unit supplies the file path and positions for each finding.
// It returns one finding per required spec lacking a useful comment, or an empty, non-nil slice when there is none.
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
// RequireNamedTypeComments covers every type; otherwise only a struct or interface with its own flag on reports true.
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
//
// decl is the const or var declaration, kind is const or var for the message and metadata, and unit supplies the file path and positions.
// It returns one finding per declared name lacking a useful comment, blank names included, or an empty, non-nil slice when there is none.
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
// It returns the count of non-blank lines and of whitespace-separated words in the group's text, both zero for a nil group.
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
// It reports false for a nil group or one whose text is empty, such as a group of only directive lines like go:generate, which Text drops.
func hasUsefulComment(group *ast.CommentGroup) bool {
	stats := commentStats(group)
	return stats.lines > 0 && stats.words > 0
}

// hasUsefulDeclarationComment reports whether the comment adds context beyond the symbol name itself.
//
// When minWordsBeyondSymbol is positive, the comment must also add that many unique non-stopword tokens outside the symbol's own identifier set.
// group is the attached comment and symbol the documented name; a nil or blank group, or one matching symbol after normalizing, reports false.
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
//
// spec's own comment is tried first; only a decl with several specs accepts any non-blank decl comment, otherwise it must pass the same test.
// A parenthesised decl holding a single spec gets no group exemption.
// minWordsBeyondSymbol is the substantive-token floor applied through hasUsefulDeclarationComment; zero or less disables it.
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
//
// symbol is the declared name being checked, tried first against the comment on spec.
// When decl groups several specs or spec has several names, any non-blank decl comment counts; else it must pass the same check.
// minWordsBeyondSymbol is the substantive-token floor, applied only when positive.
func hasUsefulValueComment(decl *ast.GenDecl, spec *ast.ValueSpec, symbol string, minWordsBeyondSymbol int) bool {
	if hasUsefulDeclarationComment(spec.Doc, symbol, minWordsBeyondSymbol) {
		return true
	}
	if len(decl.Specs) > 1 || len(spec.Names) > 1 {
		return hasUsefulComment(decl.Doc)
	}
	return hasUsefulDeclarationComment(decl.Doc, symbol, minWordsBeyondSymbol)
}

// commentTokensBeyondSymbol counts the unique substantive tokens of comment that do not appear among the identifier tokens of symbol.
//
// Stopwords in commentRubricStopwords are skipped, so fillers like the and for cannot push a paraphrase over minWordsBeyondSymbol.
// Both inputs split on non-alphanumeric runs, so Receiver.Method adds both sides, then each word splits into lowercased camel-case sub-tokens.
//
// It returns that count, zero when every comment token is a stopword, part of symbol, or a repeat.
func commentTokensBeyondSymbol(comment, symbol string) int {
	symbolTokens := identifierTokenSet(symbol)
	seen := map[string]bool{}
	count := 0
	for _, commentToken := range identifierTokens(comment) {
		if commentRubricStopwords[commentToken] || symbolTokens[commentToken] || seen[commentToken] {
			continue
		}
		seen[commentToken] = true
		count++
	}
	return count
}

// identifierTokenSet returns the lowercased camel-case-split token set for identifier, which may be any identifier-like string.
//
// Non-alphanumeric characters split words, so a qualified name like Receiver.Method contributes both halves.
// An identifier with no letter or digit gives an empty map.
func identifierTokenSet(identifier string) map[string]bool {
	out := map[string]bool{}
	for _, token := range identifierTokens(identifier) {
		out[token] = true
	}
	return out
}

// identifierTokens returns the ordered, lowercased sub-tokens of text, which may be an identifier or free-form comment text.
//
// text is split on non-alphanumeric runs, then splitIdentifierTokens breaks each word so camel-case sub-tokens count separately.
// Repeats are kept, and text with no letter or digit gives an empty, non-nil slice.
func identifierTokens(text string) []string {
	mapped := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return ' '
	}, text)
	tokens := []string{}
	for _, word := range strings.Fields(mapped) {
		for _, subToken := range splitIdentifierTokens(word) {
			lower := strings.ToLower(strings.TrimSpace(subToken))
			if lower == "" {
				continue
			}
			tokens = append(tokens, lower)
		}
	}
	return tokens
}

// normalizeCommentText lowercases a comment, replaces non-alphanumeric characters with spaces, and collapses whitespace.
// It returns value in that form, words joined by single spaces, or an empty string when value holds no letter or digit.
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
// It returns struct type or interface type for those literals and named type for any other type expression, so it is never empty.
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
