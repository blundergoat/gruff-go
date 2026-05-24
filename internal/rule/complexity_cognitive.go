// Package rule defines gruff-go's rule registry and analysers.
// This file implements a parser-only cognitive complexity metric.
package rule

import (
	"fmt"
	"go/ast"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// cognitiveComplexityThreshold is the default parser-only cognitive complexity cap.
const cognitiveComplexityThreshold = 35

// CognitiveComplexityRule flags functions whose cognitive complexity exceeds the maximum.
type CognitiveComplexityRule struct {
	// MaxComplexity is the per-function cognitive complexity cap.
	MaxComplexity int
}

// maxComplexity returns the configured cap, falling back to cognitiveComplexityThreshold.
func (r CognitiveComplexityRule) maxComplexity() int {
	if r.MaxComplexity <= 0 {
		return cognitiveComplexityThreshold
	}
	return r.MaxComplexity
}

// Definition declares the complexity.cognitive rule with one threshold and parser capability.
func (r CognitiveComplexityRule) Definition() Definition {
	max := r.maxComplexity()
	return Definition{
		ID:             "complexity.cognitive",
		Title:          "Cognitive complexity",
		Description:    "Flags functions whose nested control flow and boolean decisions exceed the configured cognitive complexity threshold.",
		Pillar:         finding.PillarComplexity,
		Severity:       finding.SeverityMedium,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Thresholds:     map[string]float64{"maxComplexity": float64(max)},
		Tags:           []string{"metric"},
		Remediation:    "Flatten nested branches, return early, or extract cohesive helper functions.",
	}
}

// AnalyzeUnit emits findings for functions above the cognitive complexity threshold.
func (r CognitiveComplexityRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	max := r.maxComplexity()
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		complexity := cognitiveComplexity(fn)
		if complexity <= max {
			continue
		}
		start := unit.FileSet.Position(fn.Pos())
		end := unit.FileSet.Position(fn.End())
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("function cognitive complexity is %d, above threshold %d", complexity, max),
			File:     unit.File.Path,
			Location: &finding.Location{Line: start.Line, EndLine: end.Line},
			Symbol:   functionName(fn),
			Metadata: map[string]any{"complexity": complexity, "threshold": max},
		})
	}
	return findings
}

// cognitiveComplexity computes a Sonar-inspired parser-only approximation:
// each control structure adds one point plus the current nesting level, boolean
// operators in conditions add one point, and function literals reset the count.
func cognitiveComplexity(fn *ast.FuncDecl) int {
	return cognitiveBlockComplexity(fn.Body, 0)
}

// cognitiveBlockComplexity sums statement complexity in a block at a given nesting level.
func cognitiveBlockComplexity(block *ast.BlockStmt, nesting int) int {
	if block == nil {
		return 0
	}
	total := 0
	for _, stmt := range block.List {
		total += cognitiveStmtComplexity(stmt, nesting)
	}
	return total
}

// cognitiveStmtComplexity scores one statement and its nested bodies.
func cognitiveStmtComplexity(stmt ast.Stmt, nesting int) int {
	switch value := stmt.(type) {
	case *ast.IfStmt:
		score := 1 + nesting + booleanOperatorComplexity(value.Cond)
		score += cognitiveBlockComplexity(value.Body, nesting+1)
		if value.Else != nil {
			if elseIf, ok := value.Else.(*ast.IfStmt); ok {
				score += cognitiveStmtComplexity(elseIf, nesting)
			} else if block, ok := value.Else.(*ast.BlockStmt); ok {
				score += cognitiveBlockComplexity(block, nesting+1)
			}
		}
		return score
	case *ast.ForStmt:
		return 1 + nesting + booleanOperatorComplexity(value.Cond) + cognitiveBlockComplexity(value.Body, nesting+1)
	case *ast.RangeStmt:
		return 1 + nesting + cognitiveBlockComplexity(value.Body, nesting+1)
	case *ast.SwitchStmt:
		return 1 + nesting + cognitiveBlockComplexity(value.Body, nesting+1)
	case *ast.TypeSwitchStmt:
		return 1 + nesting + cognitiveBlockComplexity(value.Body, nesting+1)
	case *ast.SelectStmt:
		return 1 + nesting + cognitiveBlockComplexity(value.Body, nesting+1)
	case *ast.CaseClause:
		return cognitiveStmtListComplexity(value.Body, nesting)
	case *ast.CommClause:
		return cognitiveStmtListComplexity(value.Body, nesting)
	case *ast.BlockStmt:
		return cognitiveBlockComplexity(value, nesting)
	}
	return 0
}

// cognitiveStmtListComplexity scores switch/select clause bodies.
func cognitiveStmtListComplexity(stmts []ast.Stmt, nesting int) int {
	total := 0
	for _, stmt := range stmts {
		total += cognitiveStmtComplexity(stmt, nesting)
	}
	return total
}

// booleanOperatorComplexity counts explicit && and || decisions in an expression.
func booleanOperatorComplexity(expr ast.Expr) int {
	if expr == nil {
		return 0
	}
	total := 0
	ast.Inspect(expr, func(node ast.Node) bool {
		binary, ok := node.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		if binary.Op.String() == "&&" || binary.Op.String() == "||" {
			total++
		}
		return true
	})
	return total
}
