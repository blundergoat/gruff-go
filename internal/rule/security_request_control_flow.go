// Package rule provides bounded control-flow evidence for request security rules.
// It distinguishes mutually exclusive syntax branches without adding type or SSA analysis.
package rule

import (
	"go/ast"
	"go/token"
)

// enclosingControlRegionsContainPosition reports whether a later position stays
// inside every optional control region that contains target. A validator inside
// an optional branch cannot protect a sink after that branch has been skipped.
func enclosingControlRegionsContainPosition(root ast.Node, target ast.Node, position token.Pos) bool {
	for _, region := range enclosingControlRegions(root, target) {
		if !nodeContainsPosition(region, position) {
			return false
		}
	}
	return true
}

// nodesCanShareControlPath rejects nodes placed in different branches of the
// same if, switch, type switch, or select. Independent conditions stay
// compatible because a runtime path may execute both.
func nodesCanShareControlPath(root ast.Node, firstNode, secondNode ast.Node) bool {
	firstBranches := exclusiveControlBranches(root, firstNode)
	secondBranches := exclusiveControlBranches(root, secondNode)
	for controlNode, firstBranch := range firstBranches {
		if secondBranch, sharesControl := secondBranches[controlNode]; sharesControl && secondBranch != firstBranch {
			return false
		}
	}
	return true
}

// enclosingControlRegions returns the optional branch or loop regions that
// must execute before target can execute.
func enclosingControlRegions(root ast.Node, target ast.Node) []ast.Node {
	regions := []ast.Node{}
	targetPosition := target.Pos()
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil || !nodeContainsPosition(node, targetPosition) {
			return false
		}
		switch statement := node.(type) {
		case *ast.IfStmt:
			if branch := ifBranchContainingPosition(statement, targetPosition); branch != nil {
				regions = append(regions, branch)
			}
		case *ast.ForStmt:
			if nodeContainsPosition(statement.Body, targetPosition) {
				regions = append(regions, statement.Body)
			}
		case *ast.RangeStmt:
			if nodeContainsPosition(statement.Body, targetPosition) {
				regions = append(regions, statement.Body)
			}
		case *ast.SwitchStmt:
			if branch := clauseContainingPosition(statement.Body, targetPosition); branch != nil {
				regions = append(regions, branch)
			}
		case *ast.TypeSwitchStmt:
			if branch := clauseContainingPosition(statement.Body, targetPosition); branch != nil {
				regions = append(regions, branch)
			}
		case *ast.SelectStmt:
			if branch := clauseContainingPosition(statement.Body, targetPosition); branch != nil {
				regions = append(regions, branch)
			}
		}
		return true
	})
	return regions
}

// exclusiveControlBranches maps each enclosing multi-branch statement to the
// exact branch containing target.
func exclusiveControlBranches(root ast.Node, target ast.Node) map[ast.Node]ast.Node {
	branches := map[ast.Node]ast.Node{}
	targetPosition := target.Pos()
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil || !nodeContainsPosition(node, targetPosition) {
			return false
		}
		switch statement := node.(type) {
		case *ast.IfStmt:
			if branch := ifBranchContainingPosition(statement, targetPosition); branch != nil {
				branches[statement] = branch
			}
		case *ast.SwitchStmt:
			if branch := clauseContainingPosition(statement.Body, targetPosition); branch != nil {
				branches[statement] = branch
			}
		case *ast.TypeSwitchStmt:
			if branch := clauseContainingPosition(statement.Body, targetPosition); branch != nil {
				branches[statement] = branch
			}
		case *ast.SelectStmt:
			if branch := clauseContainingPosition(statement.Body, targetPosition); branch != nil {
				branches[statement] = branch
			}
		}
		return true
	})
	return branches
}

// ifBranchContainingPosition returns the body or else branch that contains a
// position, or nil when the position belongs to the condition itself.
func ifBranchContainingPosition(statement *ast.IfStmt, position token.Pos) ast.Node {
	if nodeContainsPosition(statement.Body, position) {
		return statement.Body
	}
	if statement.Else != nil && nodeContainsPosition(statement.Else, position) {
		return statement.Else
	}
	return nil
}

// clauseContainingPosition returns one switch/select clause containing position.
func clauseContainingPosition(body *ast.BlockStmt, position token.Pos) ast.Node {
	if body == nil {
		return nil
	}
	for _, statement := range body.List {
		if nodeContainsPosition(statement, position) {
			return statement
		}
	}
	return nil
}

// nodeContainsPosition uses half-open AST source ranges for containment checks.
func nodeContainsPosition(node ast.Node, position token.Pos) bool {
	return node != nil && node.Pos() <= position && position < node.End()
}
