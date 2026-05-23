// Package rule defines gruff-go's rule registry and analysers.
// This file keeps skipped-test receiver matching scoped to each function body.
package rule

import (
	"go/ast"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// skippedTestFindingsInBlock emits skip findings for one lexical block using the
// testing receiver names visible in that block.
func skippedTestFindingsInBlock(unit parser.Unit, body *ast.BlockStmt, testingPackages map[string]bool, receivers map[string]bool, conditionalRegions []posRange) []finding.Finding {
	if body == nil {
		return nil
	}
	localReceivers := copyReceiverNames(receivers)
	findings := []finding.Finding{}
	ast.Inspect(body, func(node ast.Node) bool {
		if funcLit, ok := node.(*ast.FuncLit); ok {
			nestedReceivers := scopedReceiversForFuncType(localReceivers, funcLit.Type, testingPackages)
			findings = append(findings, skippedTestFindingsInBlock(unit, funcLit.Body, testingPackages, nestedReceivers, conditionalRegions)...)
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok || !isTestingSkipCall(call, localReceivers) {
			return true
		}
		conditional := isPosInsideAny(call.Pos(), call.End(), conditionalRegions)
		if conditional && !skipMessageMentionsDebt(call) {
			return true
		}
		position := unit.FileSet.Position(call.Pos())
		findings = append(findings, finding.Finding{
			Message:  "test contains a skip call",
			File:     unit.File.Path,
			Location: &finding.Location{Line: position.Line, Column: position.Column},
		})
		return true
	})
	return findings
}
