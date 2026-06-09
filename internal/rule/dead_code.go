// Package rule defines gruff-go's rule registry and analysers.
// This file implements parser-only unreachable-code checks.
package rule

import (
	"go/ast"
	"go/token"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// UnreachableCodeRule flags statements that follow terminal statements in the same block.
type UnreachableCodeRule struct{}

// Definition declares the dead-code.unreachable-code rule for same-block unreachable statements.
func (UnreachableCodeRule) Definition() Definition {
	return Definition{
		ID:             "dead-code.unreachable-code",
		Title:          "Unreachable code",
		Description:    "Flags statements that appear after return, panic, break, continue, or goto in the same block.",
		Pillar:         finding.PillarDeadCode,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
		Tags:           []string{"control-flow"},
		Remediation:    "Remove the unreachable statement or move it before the terminating control-flow statement.",
	}
}

// AnalyzeUnit emits findings for statements made unreachable by a previous terminal statement in the same lexical block.
func (UnreachableCodeRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil {
		return nil
	}
	findings := []finding.Finding{}
	ast.Inspect(unit.AST, func(node ast.Node) bool {
		block, ok := node.(*ast.BlockStmt)
		if !ok {
			return true
		}
		findings = append(findings, unreachableFindingsInBlock(unit, block)...)
		return true
	})
	return findings
}

// unreachableFindingsInBlock checks one statement list for same-block unreachable code.
func unreachableFindingsInBlock(unit parser.Unit, block *ast.BlockStmt) []finding.Finding {
	findings := []finding.Finding{}
	terminated := false
	terminator := ""
	for _, stmt := range block.List {
		if _, labeled := stmt.(*ast.LabeledStmt); labeled {
			terminated = false
			terminator = ""
		}
		if terminated && !isIgnorableUnreachableStmt(stmt) {
			position := unit.FileSet.Position(stmt.Pos())
			findings = append(findings, finding.Finding{
				Message:  "statement is unreachable after " + terminator,
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Metadata: map[string]any{"after": terminator},
			})
			continue
		}
		if label, ok := terminalStatement(stmt); ok {
			terminated = true
			terminator = label
		}
	}
	return findings
}

// terminalStatement reports whether stmt ends control flow for following statements in the same block.
func terminalStatement(stmt ast.Stmt) (string, bool) {
	return terminalStatementInContext(stmt, true)
}

// terminalStatementInContext reports whether stmt exits the current statement list.
func terminalStatementInContext(stmt ast.Stmt, breakTerminates bool) (string, bool) {
	switch value := stmt.(type) {
	case *ast.ReturnStmt:
		return "return", true
	case *ast.BranchStmt:
		switch value.Tok {
		case token.BREAK:
			if breakTerminates {
				return "break", true
			}
			return "", false
		case token.CONTINUE, token.GOTO:
			return value.Tok.String(), true
		default:
			return "", false
		}
	case *ast.ExprStmt:
		call, ok := value.X.(*ast.CallExpr)
		if ok && isDirectPanicCall(call) {
			return "panic", true
		}
	case *ast.IfStmt:
		if ifStatementTerminates(value, breakTerminates) {
			return "if/else", true
		}
	case *ast.SwitchStmt:
		if switchStatementTerminates(value) {
			return "switch", true
		}
	case *ast.TypeSwitchStmt:
		if typeSwitchStatementTerminates(value) {
			return "type switch", true
		}
	case *ast.SelectStmt:
		if selectStatementTerminates(value) {
			return "select", true
		}
	}
	return "", false
}

// ifStatementTerminates reports whether both if and else paths exit the current list.
func ifStatementTerminates(stmt *ast.IfStmt, breakTerminates bool) bool {
	if stmt.Body == nil || !statementListTerminates(stmt.Body.List, breakTerminates) || stmt.Else == nil {
		return false
	}
	switch value := stmt.Else.(type) {
	case *ast.BlockStmt:
		return statementListTerminates(value.List, breakTerminates)
	case *ast.IfStmt:
		_, ok := terminalStatementInContext(value, breakTerminates)
		return ok
	default:
		return false
	}
}

// switchStatementTerminates reports whether every switch case exits and a default case exists.
func switchStatementTerminates(stmt *ast.SwitchStmt) bool {
	if stmt.Body == nil {
		return false
	}
	return caseClausesTerminate(stmt.Body.List)
}

// typeSwitchStatementTerminates reports whether every type-switch case exits and a default case exists.
func typeSwitchStatementTerminates(stmt *ast.TypeSwitchStmt) bool {
	if stmt.Body == nil {
		return false
	}
	return caseClausesTerminate(stmt.Body.List)
}

// caseClausesTerminate checks switch/type-switch case lists without treating break as terminal.
func caseClausesTerminate(stmts []ast.Stmt) bool {
	if len(stmts) == 0 {
		return false
	}
	hasDefault := false
	for _, stmt := range stmts {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		if clause.List == nil {
			hasDefault = true
		}
		if len(clause.Body) == 0 || branchListContainsFallthrough(clause.Body) || !statementListTerminates(clause.Body, false) {
			return false
		}
	}
	return hasDefault
}

// selectStatementTerminates reports whether every communication clause exits.
func selectStatementTerminates(stmt *ast.SelectStmt) bool {
	if stmt.Body == nil || len(stmt.Body.List) == 0 {
		return false
	}
	for _, item := range stmt.Body.List {
		clause, ok := item.(*ast.CommClause)
		if !ok || len(clause.Body) == 0 || !statementListTerminates(clause.Body, false) {
			return false
		}
	}
	return true
}

// statementListTerminates reports whether the last meaningful statement exits the list.
func statementListTerminates(stmts []ast.Stmt, breakTerminates bool) bool {
	for index := len(stmts) - 1; index >= 0; index-- {
		stmt := stmts[index]
		if _, ok := stmt.(*ast.EmptyStmt); ok {
			continue
		}
		if labeled, ok := stmt.(*ast.LabeledStmt); ok {
			stmt = labeled.Stmt
		}
		_, ok := terminalStatementInContext(stmt, breakTerminates)
		return ok
	}
	return false
}

// branchListContainsFallthrough keeps switch termination conservative.
func branchListContainsFallthrough(stmts []ast.Stmt) bool {
	for _, stmt := range stmts {
		found := false
		ast.Inspect(stmt, func(node ast.Node) bool {
			branch, ok := node.(*ast.BranchStmt)
			if ok && branch.Tok == token.FALLTHROUGH {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// isIgnorableUnreachableStmt skips empty statements and labels that may be goto targets.
func isIgnorableUnreachableStmt(stmt ast.Stmt) bool {
	switch stmt.(type) {
	case *ast.EmptyStmt, *ast.LabeledStmt:
		return true
	default:
		return false
	}
}
