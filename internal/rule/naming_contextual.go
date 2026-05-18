package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

var defaultContextualGenericNames = []string{"item", "value", "entry", "elem", "v"}
var defaultContextualAccumulatorNames = []string{"out", "result"}

const (
	contextualGenericBodyLinesThreshold     = 15
	contextualGenericFunctionLinesThreshold = 50
)

type ContextualGenericRule struct {
	GenericNames     []string
	MinBodyLines     int
	AccumulatorNames []string
	MinFunctionLines int
	RequireMultiple  *bool
}

type contextualGenericContext struct {
	genericNames     map[string]bool
	minBodyLines     int
	accumulatorNames map[string]bool
	minFunctionLines int
	requireMultiple  bool
}

type accumulatorDecl struct {
	ident         *ast.Ident
	functionName  string
	functionLines int
}

func (r ContextualGenericRule) Definition() Definition {
	return Definition{
		ID:             "naming.contextual-generic",
		Title:          "Contextual generic name",
		Description:    "Flags generic range variables and accumulator names only when surrounding context is large enough that the name loses meaning.",
		Pillar:         finding.PillarNaming,
		Severity:       finding.SeverityLow,
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
		Tags:        []string{"naming", "opt-in"},
		Remediation: "Rename long-loop values and long-function accumulators to describe the data role they carry.",
	}
}

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

func nodeLineCount(unit parser.Unit, node ast.Node) int {
	start := unit.FileSet.Position(node.Pos()).Line
	end := unit.FileSet.Position(node.End()).Line
	if end < start {
		return 0
	}
	return end - start + 1
}

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

func positiveOrDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}
