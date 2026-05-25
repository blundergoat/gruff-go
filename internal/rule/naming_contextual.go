// Package rule defines gruff-go's rule registry and analysers.
// This file implements the contextual-generic naming rule for range and accumulator identifiers.
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
var defaultContextualGenericNames = []string{"item", "value", "entry", "elem", "v"}

// defaultContextualAccumulatorNames lists the accumulator identifiers the rule watches for in long functions.
var defaultContextualAccumulatorNames = []string{"out", "result"}

// contextualGenericBodyLinesThreshold and contextualGenericFunctionLinesThreshold provide the default size gates.
const (
	contextualGenericBodyLinesThreshold     = 15
	contextualGenericFunctionLinesThreshold = 50
)

// ContextualGenericRule flags generic range or accumulator names only when the surrounding context is large.
type ContextualGenericRule struct {
	// GenericNames overrides the default set of range identifiers (item, value, entry, ...) the rule watches for in long loops.
	GenericNames []string
	// MinBodyLines is the loop-body line threshold below which generic range names are tolerated.
	MinBodyLines int
	// AccumulatorNames overrides the default accumulator identifiers (out, result) the rule watches for in long functions.
	AccumulatorNames []string
	// MinFunctionLines is the function-length threshold below which generic accumulator names are tolerated.
	MinFunctionLines int
	// RequireMultiple, when non-nil, controls whether accumulator findings only emit if two or more generic names appear in the same function.
	RequireMultiple *bool
}

// contextualGenericContext carries the resolved configuration for one analyser invocation.
type contextualGenericContext struct {
	genericNames     map[string]bool
	minBodyLines     int
	accumulatorNames map[string]bool
	minFunctionLines int
	requireMultiple  bool
}

// accumulatorDecl records one accumulator identifier together with its enclosing function context.
type accumulatorDecl struct {
	ident         *ast.Ident
	functionName  string
	functionLines int
}

// Definition declares the naming.contextual-generic rule with default size gates of 15 body lines and 50 function lines before generic names like item or value are flagged.
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

// AnalyzeUnit walks each function in the unit and emits range and accumulator findings.
func (r ContextualGenericRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || strings.HasSuffix(unit.File.Path, "_test.go") || hasGeneratedHeader(unit.Source) {
		return nil
	}
	ctx := r.context()
	if len(ctx.genericNames) == 0 && len(ctx.accumulatorNames) == 0 {
		return nil
	}
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
func (c contextualGenericContext) rangeFindings(unit parser.Unit, fn *ast.FuncDecl) []finding.Finding {
	findings := []finding.Finding{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch item := node.(type) {
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
func (c contextualGenericContext) rangeFinding(unit parser.Unit, stmt *ast.RangeStmt) (finding.Finding, bool) {
	ident, ok := stmt.Value.(*ast.Ident)
	if !ok || ident.Name == "_" || !c.genericNames[strings.ToLower(ident.Name)] {
		return finding.Finding{}, false
	}
	bodyLines := blockBodyLines(unit, stmt.Body)
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
func (c contextualGenericContext) accumulatorFindings(unit parser.Unit, fn *ast.FuncDecl) []finding.Finding {
	functionLines := nodeLineCount(unit, fn)
	if functionLines <= c.minFunctionLines {
		return nil
	}
	decls := c.accumulatorDecls(fn, functionLines)
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
func (c contextualGenericContext) accumulatorDecls(fn *ast.FuncDecl, functionLines int) []accumulatorDecl {
	decls := []accumulatorDecl{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch item := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
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

// blockBodyLines counts the lines strictly inside a block, excluding its braces.
func blockBodyLines(unit parser.Unit, block *ast.BlockStmt) int {
	if block == nil {
		return 0
	}
	start := unit.FileSet.Position(block.Lbrace).Line
	end := unit.FileSet.Position(block.Rbrace).Line
	if end <= start {
		return 0
	}
	return end - start - 1
}

// nodeLineCount returns the inclusive line span of a syntax node in the unit's file set.
func nodeLineCount(unit parser.Unit, node ast.Node) int {
	start := unit.FileSet.Position(node.Pos()).Line
	end := unit.FileSet.Position(node.End()).Line
	if end < start {
		return 0
	}
	return end - start + 1
}

// rangeExpressionName extracts a readable name from a range expression for use in finding messages.
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
func lowerStringSetWithDefault(values, fallback []string) map[string]bool {
	source := values
	if len(source) == 0 {
		source = fallback
	}
	out := make(map[string]bool, len(source))
	for _, value := range source {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			out[strings.ToLower(trimmed)] = true
		}
	}
	return out
}

// positiveOrDefault is the shared zero-as-unconfigured shim used by
// configurable int knobs across the rule registry: when a knob is omitted
// from YAML it arrives as Go's zero value, and we swap in the rule's
// hardcoded fallback so an unset knob doesn't silently disable the check
// (or worse, fire on every input by treating 0 as the threshold).
func positiveOrDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}
