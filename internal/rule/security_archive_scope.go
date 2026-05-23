// Package rule defines gruff-go's rule registry and analysers.
// This file contains archive path-containment matching helpers.
package rule

import (
	"go/ast"
	"strings"
)

// archiveJoinHasContainmentEvidence reports whether a containment-looking call
// directly wraps or references the path produced by this archive entry join.
func archiveJoinHasContainmentEvidence(body *ast.BlockStmt, joinCall *ast.CallExpr) bool {
	assignedNames := archiveJoinAssignedNames(body, joinCall)
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok || !isArchiveContainmentCall(call) {
			return true
		}
		found = nodeContainsTarget(call, joinCall) || nodeUsesAnyIdent(call, assignedNames)
		return !found
	})
	return found
}

// archiveJoinAssignedNames records local names assigned from a specific archive
// path join call, including assignments whose right-hand side wraps the join.
func archiveJoinAssignedNames(body *ast.BlockStmt, joinCall *ast.CallExpr) map[string]bool {
	names := map[string]bool{}
	if body == nil || joinCall == nil {
		return names
	}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch stmt := node.(type) {
		case *ast.ValueSpec:
			for i, name := range stmt.Names {
				if name.Name == "_" || i >= len(stmt.Values) || !nodeContainsTarget(stmt.Values[i], joinCall) {
					continue
				}
				names[name.Name] = true
			}
		case *ast.AssignStmt:
			for i, lhs := range stmt.Lhs {
				name, ok := lhs.(*ast.Ident)
				if !ok || name.Name == "_" || i >= len(stmt.Rhs) || !nodeContainsTarget(stmt.Rhs[i], joinCall) {
					continue
				}
				names[name.Name] = true
			}
		}
		return true
	})
	return names
}

// isArchiveContainmentCall recognises parser-only evidence that code is checking
// archive extraction containment.
func isArchiveContainmentCall(call *ast.CallExpr) bool {
	name := callName(call)
	switch name {
	case "Clean", "Rel", "HasPrefix", "Contains":
		return true
	}
	lower := strings.ToLower(name)
	return strings.Contains(lower, "safe") || strings.Contains(lower, "sanit") || strings.Contains(lower, "within") || strings.Contains(lower, "contain")
}

// nodeContainsTarget reports whether root contains the exact AST node target.
func nodeContainsTarget(root ast.Node, target ast.Node) bool {
	if root == nil || target == nil {
		return false
	}
	found := false
	ast.Inspect(root, func(node ast.Node) bool {
		if found {
			return false
		}
		found = node == target
		return !found
	})
	return found
}

// nodeUsesAnyIdent reports whether root references any name in names.
func nodeUsesAnyIdent(root ast.Node, names map[string]bool) bool {
	if root == nil || len(names) == 0 {
		return false
	}
	found := false
	ast.Inspect(root, func(node ast.Node) bool {
		if found {
			return false
		}
		ident, ok := node.(*ast.Ident)
		found = ok && names[ident.Name]
		return !found
	})
	return found
}
