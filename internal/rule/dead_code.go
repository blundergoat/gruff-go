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
		Severity:       finding.SeverityLow,
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
	switch value := stmt.(type) {
	case *ast.ReturnStmt:
		return "return", true
	case *ast.BranchStmt:
		switch value.Tok {
		case token.BREAK, token.CONTINUE, token.GOTO:
			return value.Tok.String(), true
		default:
			return "", false
		}
	case *ast.ExprStmt:
		call, ok := value.X.(*ast.CallExpr)
		if ok && isDirectPanicCall(call) {
			return "panic", true
		}
	}
	return "", false
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
