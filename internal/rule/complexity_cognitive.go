// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements complexity.cognitive, a parser-only cognitive complexity metric for functions outside test files.
// A function scoring above the cap becomes a finding that names it; the cap is 25 unless maxComplexity converts to a positive integer.
package rule

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// cognitiveComplexityThreshold is the default parser-only cognitive complexity cap.
//
// It applies whenever MaxComplexity is zero or negative, so with no setting a function scoring 26 or more is reported.
const cognitiveComplexityThreshold = 25

// CognitiveComplexityRule flags functions whose cognitive complexity exceeds the maximum.
//
// It backs the complexity.cognitive rule ID; each finding gives the function's score and the threshold it exceeded in its message and metadata.
// A zero or negative MaxComplexity falls back to cognitiveComplexityThreshold.
type CognitiveComplexityRule struct {
	// MaxComplexity is the per-function cognitive complexity cap; a higher score is a finding, and zero or negative means the default 25.
	MaxComplexity int
}

// maxComplexity returns the configured cap, falling back to cognitiveComplexityThreshold when MaxComplexity is zero or negative.
// Definition and AnalyzeUnit both use it, so the threshold a Definition declares matches the one findings are judged against.
func (r CognitiveComplexityRule) maxComplexity() int {
	if r.MaxComplexity <= 0 {
		return cognitiveComplexityThreshold
	}
	return r.MaxComplexity
}

// Definition declares the complexity.cognitive rule with one threshold and parser capability.
// It returns a Definition, enabled by default at warning severity, whose maxComplexity threshold is MaxComplexity or 25 if that is not positive.
func (r CognitiveComplexityRule) Definition() Definition {
	threshold := r.maxComplexity()
	return Definition{
		ID:             "complexity.cognitive",
		Title:          "Cognitive complexity",
		Description:    "Flags functions outside test files whose nested control flow and boolean decisions exceed the configured cognitive complexity threshold.",
		Pillar:         finding.PillarComplexity,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Thresholds:     map[string]float64{"maxComplexity": float64(threshold)},
		Tags:           []string{"metric"},
		Remediation:    simplifyExecutionPathAdvice,
	}
}

// AnalyzeUnit emits findings for functions above the cognitive complexity threshold.
//
// It returns nil when unit lacks an AST or file set, or when the path of unit is a Go test file.
// Otherwise the result holds one finding per function, method or package-level var function literal scoring above the cap, empty when none does.
//
// Each finding spans the function's first to last line and reads function cognitive complexity is N, above threshold M.
func (r CognitiveComplexityRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	// A test's branches are its assertion sequence, which M14's measurement found not worth splitting.
	if unit.AST == nil || unit.FileSet == nil || isGoTestFile(unit.File.Path) {
		return nil
	}
	threshold := r.maxComplexity()
	findings := []finding.Finding{}
	for _, fn := range measuredFuncDecls(unit.AST) {
		// A declaration with no body, such as one implemented in assembly, has nothing to score.
		if fn.Body == nil {
			continue
		}
		complexity := cognitiveComplexity(fn)
		// A score equal to the threshold passes; only a strictly higher score becomes a finding.
		if complexity <= threshold {
			continue
		}
		start := unit.FileSet.Position(fn.Pos())
		end := unit.FileSet.Position(fn.End())
		findings = append(findings, withLimitBand(finding.Finding{
			Message:  fmt.Sprintf("function cognitive complexity is %d, above threshold %d", complexity, threshold),
			File:     unit.File.Path,
			Location: &finding.Location{Line: start.Line, EndLine: end.Line},
			Symbol:   functionName(fn),
			Metadata: map[string]any{"complexity": complexity, "threshold": threshold},
		}, complexity, threshold, lowerBandFunctionAdvice, simplifyExecutionPathAdvice))
	}
	return findings
}

// cognitiveComplexity computes a Sonar-inspired parser-only approximation of how hard fn is to follow.
//
// Each if, for, range, switch, type switch or select adds one point plus the current nesting level.
// Each && and || in an if or for condition adds one point, even inside a function literal there; closure bodies are not otherwise scored.
//
// Two shapes are softened to avoid findings that are not worth acting on.
// Cases of a switch, type switch or select stay at the statement's own nesting level, and an early-exit guard pays no nesting penalty.
//
// The statement walk skips a labelled statement and its whole body, so a loop written as L: for { } adds no points of its own.
// Only && and || inside it still count, and only when it sits in a function literal within an if or for condition.
// It returns the score of the body of fn at nesting level zero, which is 0 when fn has no body.
func cognitiveComplexity(fn *ast.FuncDecl) int {
	return cognitiveBlockComplexity(fn.Body, 0)
}

// cognitiveBlockComplexity sums statement complexity in a block at a given nesting level.
// It returns the total score of the statements in block, and 0 when block is nil or holds no scored statement.
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
//
// It returns the score of stmt at depth nesting: an if, for, range, switch, type switch or select adds one plus nesting.
// An early-exit guard if drops the nesting penalty, and if and for conditions add their count of && and || operators.
//
// Bodies of if, else, for and range score at nesting plus one, and an else-if, case or select clause, or plain block stays at nesting.
// Any other statement gives 0, including a labelled statement, so a loop written as L: for { } adds nothing for itself or its body.
func cognitiveStmtComplexity(stmt ast.Stmt, nesting int) int {
	switch value := stmt.(type) {
	case *ast.IfStmt:
		penalty := nesting
		// Returning early is the advice this rule gives, so a guard that exits pays no nesting penalty.
		if isEarlyExitGuard(value) {
			penalty = 0
		}
		score := 1 + penalty + booleanOperatorComplexity(value.Cond)
		score += cognitiveBlockComplexity(value.Body, nesting+1)
		if value.Else != nil {
			// Each else-if is scored as a fresh if at this level, so it pays the nesting penalty again unless it is an early-exit guard.
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
	// Dispatch cases are siblings, so their bodies keep the switch's own nesting level.
	case *ast.SwitchStmt:
		return 1 + nesting + cognitiveBlockComplexity(value.Body, nesting)
	case *ast.TypeSwitchStmt:
		return 1 + nesting + cognitiveBlockComplexity(value.Body, nesting)
	case *ast.SelectStmt:
		return 1 + nesting + cognitiveBlockComplexity(value.Body, nesting)
	case *ast.CaseClause:
		return cognitiveStmtListComplexity(value.Body, nesting)
	case *ast.CommClause:
		return cognitiveStmtListComplexity(value.Body, nesting)
	case *ast.BlockStmt:
		return cognitiveBlockComplexity(value, nesting)
	}
	// Every other statement scores 0, including a labelled loop such as L: for { }, whose body is never visited.
	return 0
}

// isEarlyExitGuard reports whether stmt is a guard clause: no else, and a body of exactly one return, continue, break or panic call.
//
// It returns false when stmt has an else branch or any other body; panic counts only when called by its bare name.
// A goto or a call such as os.Exit or log.Fatal is not a guard, so such an if still pays the nesting penalty.
func isEarlyExitGuard(stmt *ast.IfStmt) bool {
	if stmt.Else != nil || stmt.Body == nil || len(stmt.Body.List) != 1 {
		return false
	}
	switch exit := stmt.Body.List[0].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return exit.Tok == token.CONTINUE || exit.Tok == token.BREAK
	case *ast.ExprStmt:
		call, ok := exit.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		name, ok := call.Fun.(*ast.Ident)
		return ok && name.Name == "panic"
	}
	return false
}

// cognitiveStmtListComplexity scores switch/select clause bodies.
// It returns the summed score of each statement in stmts at depth nesting, which is 0 for an empty list.
func cognitiveStmtListComplexity(stmts []ast.Stmt, nesting int) int {
	total := 0
	for _, stmt := range stmts {
		total += cognitiveStmtComplexity(stmt, nesting)
	}
	return total
}

// booleanOperatorComplexity counts explicit && and || decisions in an expression.
// It returns the number of && and || binary operators anywhere inside expr, and 0 when expr is nil or has none.
func booleanOperatorComplexity(expr ast.Expr) int {
	// A for loop with no condition, such as for { }, passes nil here and adds no boolean points.
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
