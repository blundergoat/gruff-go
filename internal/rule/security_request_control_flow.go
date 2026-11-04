// Package rule provides bounded control-flow evidence for request security rules.
//
// It distinguishes mutually exclusive syntax branches without adding type or SSA analysis.
// A validator inside an optional branch or loop body cannot clear a sink that runs after it, so that sink can still be reported.
// A Location header and a redirect status written in different branches of one if or switch are never paired into a finding.
package rule

import (
	"go/ast"
	"go/token"
)

// enclosingControlRegionsContainPosition reports whether a later position stays inside every optional control region that contains target.
//
// A validator inside an optional branch cannot protect a sink after that branch has been skipped.
// root is the tree searched for the regions around target, and containment of position uses half-open node ranges.
// The result is also true when target sits in no optional region, and false as soon as one region misses position.
func enclosingControlRegionsContainPosition(root ast.Node, target ast.Node, position token.Pos) bool {
	for _, region := range enclosingControlRegions(root, target) {
		if !nodeContainsPosition(region, position) {
			return false
		}
	}
	return true
}

// nodesCanShareControlPath rejects nodes placed in different branches of the same if, switch, type switch, or select.
//
// Independent conditions stay compatible because a runtime path may execute both.
// It reports false when firstNode and secondNode under root sit in different branches of one if, switch, type switch or select, else true.
// The check is syntactic, so switch clauses joined by fallthrough still conflict, and a condition is in none of its own statement's branches.
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

// enclosingControlRegions returns the optional branches and loop bodies under root that must be entered for target to run.
//
// If and else branches, for and range bodies, and switch, type switch and select clauses count when they hold the start of target.
// Code in an if condition or a loop header adds no region, and regions come outermost first; the slice is empty, not nil, when none apply.
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
		// A loop body may run zero times, so code inside it is as optional as an if branch.
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

// exclusiveControlBranches maps each enclosing multi-branch statement to the exact branch containing target.
// It returns a non-nil map for the if, switch, type switch and select statements under root, empty when target sits in no such branch.
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

// ifBranchContainingPosition returns the body or else branch of statement that contains position, or nil when position is in the condition.
// The else branch is a block or a nested if, and nil is also returned for the init clause or a position outside statement.
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
//
// body is the block of a switch, type switch or select statement, and its clauses are searched in order.
// It returns nil when body is nil or no clause contains position, such as a position in the statement's tag or init.
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
// It reports whether position lies within node, from node.Pos() inclusive to node.End() exclusive; the result is false for a nil node interface.
func nodeContainsPosition(node ast.Node, position token.Pos) bool {
	return node != nil && node.Pos() <= position && position < node.End()
}
