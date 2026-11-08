// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements the naming.contextual-generic rule, which flags generic range and accumulator names such as item, value, out or result.
// It fires only when the loop body or function is long enough that the name no longer tells a reviewer what the value holds.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// defaultContextualGenericNames lists the generic range identifiers the rule watches for in long loops.
//
// It is the genericNames option default; a configured list with any non-empty entry replaces it, not extends it, and matching ignores case.
var defaultContextualGenericNames = []string{"item", "value", "entry", "elem", "v"}

// defaultContextualAccumulatorNames lists the accumulator identifiers the rule watches for in long functions.
//
// It is the accumulatorNames option default; a configured list with any non-empty entry replaces it rather than adding to it.
var defaultContextualAccumulatorNames = []string{"out", "result"}

// contextualGenericBodyLinesThreshold and contextualGenericFunctionLinesThreshold provide the default size gates.
//
// They are the minBodyLines and minFunctionLines defaults; a loop body or function must exceed its gate in code lines to be flagged.
// A zero or negative MinBodyLines or MinFunctionLines field falls back to these defaults through positiveOrDefault.
const (
	contextualGenericBodyLinesThreshold     = 15
	contextualGenericFunctionLinesThreshold = 50
)

// ContextualGenericRule flags generic range or accumulator names only when the surrounding context is large.
//
// Each field overrides one default; an empty name list, a zero or negative threshold, or a nil RequireMultiple keeps the default.
type ContextualGenericRule struct {
	// GenericNames overrides the default set of range identifiers (item, value, entry, ...) the rule watches for in long loops.
	GenericNames []string
	// MinBodyLines is the loop-body line threshold below which generic range names are tolerated.
	MinBodyLines int
	// AccumulatorNames overrides the default accumulator identifiers (out, result) the rule watches for in long functions.
	AccumulatorNames []string
	// MinFunctionLines is the function-length threshold below which generic accumulator names are tolerated.
	MinFunctionLines int
	// RequireMultiple, when non-nil, sets whether accumulator findings need two or more matching := identifiers per function; nil means true.
	RequireMultiple *bool
}

// contextualGenericContext carries the resolved configuration for one analyser invocation.
type contextualGenericContext struct {
	genericNames     map[string]bool
	minBodyLines     int
	accumulatorNames map[string]bool
	minFunctionLines int
	requireMultiple  bool
	// codeLines marks the unit's code-bearing lines, so both size gates count code lines only.
	codeLines map[int]bool
}

// accumulatorDecl records one accumulator identifier together with its enclosing function context.
type accumulatorDecl struct {
	ident         *ast.Ident
	functionName  string
	functionLines int
}

// Definition declares naming.contextual-generic, whose default gates flag names like item or out past 15 loop-body or 50 function code lines.
// It returns the advisory, default-enabled rule Definition with the default generic and accumulator names and requireMultiple true as options.
func (r ContextualGenericRule) Definition() Definition {
	return Definition{
		ID:             "naming.contextual-generic",
		Title:          "Contextual generic name",
		Description:    "Flags generic range variables and accumulator names only when surrounding context is large enough that the name loses meaning.",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceMedium,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Thresholds: map[string]float64{
			"minBodyLines":     contextualGenericBodyLinesThreshold,
			"minFunctionLines": contextualGenericFunctionLinesThreshold,
		},
		Options: map[string]any{
			"genericNames":     defaultContextualGenericNames,
			"accumulatorNames": defaultContextualAccumulatorNames,
			"requireMultiple":  true,
		},
		Tags:        []string{"naming"},
		Remediation: "Rename long-loop values and long-function accumulators to describe the data role they carry.",
	}
}

// AnalyzeUnit checks top-level function and method declarations with bodies, skipping names inside function literals.
//
// unit is the parsed file and runCtx feeds the generated-code skip check; _test.go files and units without an AST or file set are skipped too.
// It returns each function's range findings then its accumulator findings, nil for a skipped unit, and an empty slice when nothing fires.
func (r ContextualGenericRule) AnalyzeUnit(unit parser.Unit, runCtx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || strings.HasSuffix(unit.File.Path, "_test.go") || shouldSkipGeneratedUnit(unit, runCtx) {
		return nil
	}
	ctx := r.context()
	if len(ctx.genericNames) == 0 && len(ctx.accumulatorNames) == 0 {
		return nil
	}
	ctx.codeLines = codeBearingLines(unit.Source)
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		findings = append(findings, ctx.rangeFindings(unit, fn)...)
		findings = append(findings, ctx.accumulatorFindings(unit, fn)...)
	}
	return findings
}

// context resolves the rule's configuration into a per-invocation contextualGenericContext.
//
// It returns lowercased name sets, using the defaults only when a configured list is empty, and thresholds that fall back when zero or negative.
// RequireMultiple defaults to true when nil, and codeLines is left nil for AnalyzeUnit to fill.
func (r ContextualGenericRule) context() contextualGenericContext {
	requireMultiple := true
	if r.RequireMultiple != nil {
		requireMultiple = *r.RequireMultiple
	}
	return contextualGenericContext{
		genericNames:     lowerStringSetWithDefault(r.GenericNames, defaultContextualGenericNames),
		minBodyLines:     positiveOrDefault(r.MinBodyLines, contextualGenericBodyLinesThreshold),
		accumulatorNames: lowerStringSetWithDefault(r.AccumulatorNames, defaultContextualAccumulatorNames),
		minFunctionLines: positiveOrDefault(r.MinFunctionLines, contextualGenericFunctionLinesThreshold),
		requireMultiple:  requireMultiple,
	}
}

// rangeFindings collects findings for range statements inside a function body.
//
// unit supplies the file path and positions, and fn is the function whose body is walked; nested function literals are not entered.
// It returns one finding per flagged range statement in source order, or an empty slice when none qualify.
func (c contextualGenericContext) rangeFindings(unit parser.Unit, fn *ast.FuncDecl) []finding.Finding {
	findings := []finding.Finding{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch item := node.(type) {
		// Loops inside closures are skipped, so a generic name in a closure's long loop is never flagged.
		case *ast.FuncLit:
			return false
		case *ast.RangeStmt:
			finding, ok := c.rangeFinding(unit, item)
			if ok {
				findings = append(findings, finding)
			}
		}
		return true
	})
	return findings
}

// rangeFinding emits a finding when a range value identifier is generic in a long loop body.
//
// unit supplies the file path and positions, and stmt is the range statement whose value identifier and body are checked.
// It returns the finding and true when the value name is generic and the body exceeds minBodyLines code lines; otherwise a zero finding and false.
func (c contextualGenericContext) rangeFinding(unit parser.Unit, stmt *ast.RangeStmt) (finding.Finding, bool) {
	// Only the value variable is checked, so a lone key such as v in for v := range ch is never flagged.
	ident, ok := stmt.Value.(*ast.Ident)
	if !ok || ident.Name == "_" || !c.genericNames[strings.ToLower(ident.Name)] {
		return finding.Finding{}, false
	}
	bodyLines := c.blockBodyLines(unit, stmt.Body)
	if bodyLines <= c.minBodyLines {
		return finding.Finding{}, false
	}
	source := rangeExpressionName(stmt.X)
	position := unit.FileSet.Position(ident.NamePos)
	return finding.Finding{
		Message:  fmt.Sprintf("range variable %q is generic in a %d-line loop; rename it to describe elements from %q", ident.Name, bodyLines, source),
		File:     unit.File.Path,
		Location: &finding.Location{Line: position.Line, Column: position.Column},
		Symbol:   ident.Name,
		Metadata: map[string]any{
			"identifier":   ident.Name,
			"bodyLines":    bodyLines,
			"minBodyLines": c.minBodyLines,
			"range":        source,
		},
	}, true
}

// accumulatorFindings collects findings for generic accumulator identifiers inside long functions.
//
// unit supplies the file path and positions, and fn is the function whose code-line length and short variable declarations are checked.
//
// It returns one finding per matching := identifier, or nil when fn has no more than minFunctionLines code lines.
// With requireMultiple on, it also returns nil unless fn has at least two matching := identifiers, which may repeat one name or share one statement.
func (c contextualGenericContext) accumulatorFindings(unit parser.Unit, fn *ast.FuncDecl) []finding.Finding {
	functionLines := c.nodeLineCount(unit, fn)
	if functionLines <= c.minFunctionLines {
		return nil
	}
	decls := c.accumulatorDecls(fn, functionLines)
	// By default a long function with a single out or result passes; setting requireMultiple to false flags it too.
	if c.requireMultiple && len(decls) < 2 {
		return nil
	}
	findings := make([]finding.Finding, 0, len(decls))
	for _, decl := range decls {
		position := unit.FileSet.Position(decl.ident.NamePos)
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("accumulator %q is generic in %d-line function %q", decl.ident.Name, decl.functionLines, decl.functionName),
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
			Symbol:   decl.ident.Name,
			Metadata: map[string]any{
				"identifier":       decl.ident.Name,
				"function":         decl.functionName,
				"functionLines":    decl.functionLines,
				"minFunctionLines": c.minFunctionLines,
			},
		})
	}
	return findings
}

// accumulatorDecls inspects a function body for accumulator-style short variable declarations.
//
// fn is the function whose body is walked, skipping nested function literals, and functionLines is copied into every record.
// It returns one record per := identifier matching an accumulator name case-insensitively, in source order, or an empty slice when none match.
func (c contextualGenericContext) accumulatorDecls(fn *ast.FuncDecl, functionLines int) []accumulatorDecl {
	decls := []accumulatorDecl{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch item := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			// Only := declarations count, so a var out declaration or a plain result = x assignment is never flagged.
			if item.Tok != token.DEFINE {
				return true
			}
			for _, lhs := range item.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || ident.Name == "_" || !c.accumulatorNames[strings.ToLower(ident.Name)] {
					continue
				}
				decls = append(decls, accumulatorDecl{
					ident:         ident,
					functionName:  fn.Name.Name,
					functionLines: functionLines,
				})
			}
		}
		return true
	})
	return decls
}

// blockBodyLines counts the code lines strictly inside a block, excluding its braces.
//
// Blank and comment-only lines are free (FAMILY-CONTRACT section 12, search `Code lines in every line count`).
// unit supplies brace positions and block is the body to measure; it returns zero for a nil block or one whose braces share a line.
func (c contextualGenericContext) blockBodyLines(unit parser.Unit, block *ast.BlockStmt) int {
	if block == nil {
		return 0
	}
	start := unit.FileSet.Position(block.Lbrace).Line
	end := unit.FileSet.Position(block.Rbrace).Line
	if end <= start {
		return 0
	}
	return countLinesInRange(c.codeLines, start+1, end-1)
}

// nodeLineCount counts the code lines in a syntax node's inclusive line span; blank and comment-only lines are free.
// unit supplies line positions and node is the syntax node to measure; it returns zero when the span holds no code lines.
func (c contextualGenericContext) nodeLineCount(unit parser.Unit, node ast.Node) int {
	start := unit.FileSet.Position(node.Pos()).Line
	end := unit.FileSet.Position(node.End()).Line
	if end < start {
		return 0
	}
	return countLinesInRange(c.codeLines, start, end)
}

// rangeExpressionName extracts a readable name from a range expression for use in finding messages.
//
// expr is the expression being ranged over; it returns its identifier or selector name, unwrapping calls, indexes, pointers and parentheses.
// Any other form, such as a literal or composite literal, gives the placeholder "range expression".
func rangeExpressionName(expr ast.Expr) string {
	switch item := expr.(type) {
	case *ast.Ident:
		return item.Name
	case *ast.SelectorExpr:
		if item.Sel != nil {
			return item.Sel.Name
		}
	case *ast.CallExpr:
		return rangeExpressionName(item.Fun)
	case *ast.IndexExpr:
		return rangeExpressionName(item.X)
	case *ast.IndexListExpr:
		return rangeExpressionName(item.X)
	case *ast.StarExpr:
		return rangeExpressionName(item.X)
	case *ast.ParenExpr:
		return rangeExpressionName(item.X)
	}
	return "range expression"
}

// lowerStringSetWithDefault returns a lowercased set of values, falling back to fallback when values is empty.
// Entries are trimmed and blank ones dropped, so a list of only blank strings gives an empty set rather than the fallback.
func lowerStringSetWithDefault(values, fallback []string) map[string]bool {
	source := values
	if len(source) == 0 {
		source = fallback
	}
	names := make(map[string]bool, len(source))
	for _, value := range source {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			names[strings.ToLower(trimmed)] = true
		}
	}
	return names
}

// positiveOrDefault is the shared zero-as-unconfigured shim for configurable int knobs across the rule registry.
//
// A knob omitted from YAML arrives as Go's zero value, which could silently disable the check or make it fire on every input.
// It returns value when it is positive, and the rule's hardcoded fallback when value is zero or negative.
func positiveOrDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}
