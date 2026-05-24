// Package rule defines gruff-go's rule registry and analysers.
// This file implements a parser-only NPath complexity metric. NPath
// multiplies the number of independent paths through each statement, so a
// function with many sequential branches grows exponentially even when its
// cyclomatic and cognitive scores stay flat. The metric catches the
// "innocent-looking" dispatch function whose state explosion makes tests
// and reviews intractable.
//
// The implementation is the "modified" NPath that distinguishes
// terminating paths (return, panic) from continuing paths. Classical NPath
// would multiply every early-return guard with every subsequent statement,
// which over-flags idiomatic Go's `if err != nil { return err }` chains.
// The modified form treats the early-return path as an exit point that
// adds to the total but does not compose with paths past the guard, so a
// long sequence of error-check guards grows linearly with the number of
// guards rather than exponentially.
package rule

import (
	"fmt"
	"go/ast"
	"math"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// npathThreshold is the default per-function NPath cap. The value is
// calibrated for Go's error-as-value style under the modified NPath
// formula: well-factored Go functions stay comfortably under 1024 even
// with several guard clauses and switches, while genuinely branch-
// combinatorial dispatchers (nested switches, multi-way if/else without
// terminators) exceed it quickly. PMD's classical 200 is intentionally
// not used because classical NPath over-counts Go's err-return chains.
const npathThreshold = 1024

// npathCap bounds the running product so deeply branched functions cannot
// overflow int before the rule reports them. Anything above the cap is
// reported as the cap value; the report message still communicates "above
// threshold" which is the only contract callers depend on.
const npathCap = math.MaxInt32

// NPathComplexityRule flags functions whose acyclic-path count exceeds the
// configured threshold under the modified NPath formula.
type NPathComplexityRule struct {
	// MaxComplexity is the per-function NPath cap.
	MaxComplexity int
}

// maxComplexity returns the configured cap, falling back to npathThreshold.
func (r NPathComplexityRule) maxComplexity() int {
	if r.MaxComplexity <= 0 {
		return npathThreshold
	}
	return r.MaxComplexity
}

// Definition declares the complexity.npath rule, its severity, default
// state, threshold knob, and the modified-NPath remediation guidance.
func (r NPathComplexityRule) Definition() Definition {
	max := r.maxComplexity()
	return Definition{
		ID:             "complexity.npath",
		Title:          "NPath complexity",
		Description:    "Flags functions whose number of acyclic execution paths (NPath) exceeds the configured threshold. The modified NPath formula treats return/panic guards as exit points so idiomatic Go error chains grow linearly; genuine branch-combination blowups (nested switches, multi-way if/else without terminators) still flag.",
		Pillar:         finding.PillarComplexity,
		Severity:       finding.SeverityMedium,
		Confidence:     finding.ConfidenceHigh,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Thresholds:     map[string]float64{"maxComplexity": float64(max)},
		Tags:           []string{"metric"},
		Remediation:    "Collapse boolean conditions, extract helper functions, or replace nested switches with table-driven dispatch so the path-combination count drops.",
	}
}

// AnalyzeUnit emits findings for functions above the NPath threshold.
func (r NPathComplexityRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
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
		paths := npathFunctionPaths(fn.Body)
		if paths <= max {
			continue
		}
		start := unit.FileSet.Position(fn.Pos())
		end := unit.FileSet.Position(fn.End())
		findings = append(findings, finding.Finding{
			Message:  fmt.Sprintf("function NPath complexity is %d, above threshold %d", paths, max),
			File:     unit.File.Path,
			Location: &finding.Location{Line: start.Line, EndLine: end.Line},
			Symbol:   functionName(fn),
			Metadata: map[string]any{"complexity": paths, "threshold": max},
		})
	}
	return findings
}

// npathFunctionPaths returns the total path count of a function body. The
// continuing and terminating components are summed because every path that
// "falls off" the end and every path that returns mid-body is a distinct
// way the function can complete.
func npathFunctionPaths(body *ast.BlockStmt) int {
	cont, term := npathBlockSplit(body)
	return capPathSum(cont, term)
}

// npathBlockSplit walks a block and returns (continuing, terminating) path
// counts. Statements that unconditionally exit the function add to term
// without composing with subsequent statements; non-terminating statements
// multiply normally into cont. This is the core of the modified NPath
// formula and what keeps Go err-handling chains from exploding.
func npathBlockSplit(block *ast.BlockStmt) (int, int) {
	if block == nil {
		return 1, 0
	}
	cont := 1
	term := 0
	for _, stmt := range block.List {
		sCont, sTerm := npathStmtSplit(stmt)
		term = capPathSum(term, capPathProduct(cont, sTerm))
		cont = capPathProduct(cont, sCont)
		if cont >= npathCap && term >= npathCap {
			return npathCap, npathCap
		}
	}
	return cont, term
}

// npathStmtSplit returns the (continuing, terminating) path counts for a
// single statement. Function literals are intentionally not recursed into:
// closures are an independent host's responsibility and their paths do
// not multiply the containing function's signal.
func npathStmtSplit(stmt ast.Stmt) (int, int) {
	switch value := stmt.(type) {
	case *ast.ReturnStmt:
		return 0, 1
	case *ast.BranchStmt:
		// break/continue/goto move control within the function and don't
		// take the function out of scope, so they continue rather than
		// terminate from the function's perspective.
		return 1, 0
	case *ast.ExprStmt:
		if call, ok := value.X.(*ast.CallExpr); ok && isFunctionExitCall(call) {
			return 0, 1
		}
		return 1, 0
	case *ast.IfStmt:
		return npathIfSplit(value)
	case *ast.ForStmt:
		bodyCont, bodyTerm := npathBlockSplit(value.Body)
		bools := npathBooleanPaths(value.Cond)
		return capPathSum(capPathSum(bodyCont, 1), bools), bodyTerm
	case *ast.RangeStmt:
		bodyCont, bodyTerm := npathBlockSplit(value.Body)
		return capPathSum(bodyCont, 1), bodyTerm
	case *ast.SwitchStmt:
		cont, term := npathSwitchSplit(value.Body)
		return capPathSum(cont, npathBooleanPaths(value.Tag)), term
	case *ast.TypeSwitchStmt:
		return npathSwitchSplit(value.Body)
	case *ast.SelectStmt:
		return npathSelectSplit(value.Body)
	case *ast.BlockStmt:
		return npathBlockSplit(value)
	case *ast.LabeledStmt:
		return npathStmtSplit(value.Stmt)
	}
	return 1, 0
}

// npathIfSplit returns (cont, term) for an if-stmt by combining the
// then-branch and else-branch splits. An absent else contributes one
// continuing path (the implicit fall-through). Boolean operators in the
// condition add directly to cont because each short-circuit point is one
// extra place where the branch decision can be taken.
func npathIfSplit(stmt *ast.IfStmt) (int, int) {
	thenCont, thenTerm := npathBlockSplit(stmt.Body)
	var elseCont, elseTerm int
	if stmt.Else == nil {
		elseCont, elseTerm = 1, 0
	} else {
		elseCont, elseTerm = npathStmtSplit(stmt.Else)
	}
	cont := capPathSum(capPathSum(thenCont, elseCont), npathBooleanPaths(stmt.Cond))
	term := capPathSum(thenTerm, elseTerm)
	return cont, term
}

// npathSwitchSplit sums the (cont, term) of every case body. The implicit
// no-default fall-through contributes one continuing path so the count
// can never collapse to zero on an unmatched value.
func npathSwitchSplit(body *ast.BlockStmt) (int, int) {
	if body == nil {
		return 1, 0
	}
	cont := 0
	term := 0
	hasDefault := false
	for _, clause := range body.List {
		caseClause, ok := clause.(*ast.CaseClause)
		if !ok {
			continue
		}
		if caseClause.List == nil {
			hasDefault = true
		}
		c, te := npathStmtListSplit(caseClause.Body)
		cont = capPathSum(cont, c)
		term = capPathSum(term, te)
	}
	if !hasDefault {
		cont = capPathSum(cont, 1)
	}
	if cont == 0 && term == 0 {
		cont = 1
	}
	return cont, term
}

// npathSelectSplit sums the (cont, term) of every select clause. Select
// has no implicit no-default path because Go panics on a select with no
// runnable communication; the absence of a default does not add a path.
func npathSelectSplit(body *ast.BlockStmt) (int, int) {
	if body == nil {
		return 1, 0
	}
	cont := 0
	term := 0
	for _, clause := range body.List {
		comm, ok := clause.(*ast.CommClause)
		if !ok {
			continue
		}
		c, te := npathStmtListSplit(comm.Body)
		cont = capPathSum(cont, c)
		term = capPathSum(term, te)
	}
	if cont == 0 && term == 0 {
		cont = 1
	}
	return cont, term
}

// npathStmtListSplit applies the same continuing/terminating split as
// npathBlockSplit but to the bare statement slice that switch and select
// clauses carry (no surrounding *ast.BlockStmt).
func npathStmtListSplit(stmts []ast.Stmt) (int, int) {
	cont := 1
	term := 0
	for _, stmt := range stmts {
		sCont, sTerm := npathStmtSplit(stmt)
		term = capPathSum(term, capPathProduct(cont, sTerm))
		cont = capPathProduct(cont, sCont)
		if cont >= npathCap && term >= npathCap {
			return npathCap, npathCap
		}
	}
	return cont, term
}

// isFunctionExitCall reports whether call is a syntactic invocation that
// unconditionally exits the enclosing function. Only the well-known cases
// are recognised; anything else is assumed to return normally. Treating
// log.Fatal / log.Fatalf as exits is the same convention the maintainability
// rule pack already uses elsewhere in this codebase.
func isFunctionExitCall(call *ast.CallExpr) bool {
	if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "panic" {
		return true
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch pkg.Name {
	case "os":
		return selector.Sel.Name == "Exit"
	case "log":
		switch selector.Sel.Name {
		case "Fatal", "Fatalf", "Fatalln", "Panic", "Panicf", "Panicln":
			return true
		}
	case "runtime":
		return selector.Sel.Name == "Goexit"
	}
	return false
}

// npathBooleanPaths counts && and || decisions in expr; each short-circuit
// operator is treated as one extra path because the runtime can exit before
// evaluating the right operand.
func npathBooleanPaths(expr ast.Expr) int {
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

// capPathProduct multiplies two path counts with overflow protection.
// Returning npathCap on overflow keeps the report message accurate ("above
// threshold") while preventing wraparound from producing a misleading
// negative or small positive value.
func capPathProduct(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	if a >= npathCap || b >= npathCap {
		return npathCap
	}
	if a > npathCap/b {
		return npathCap
	}
	return a * b
}

// capPathSum adds two path counts with overflow protection.
func capPathSum(a, b int) int {
	if a >= npathCap || b >= npathCap {
		return npathCap
	}
	if a > npathCap-b {
		return npathCap
	}
	return a + b
}
