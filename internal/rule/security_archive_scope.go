// Package rule defines gruff-go's rule registry and analysers.
//
// This file contains archive path-containment matching helpers.
// They look for a containment-looking call, such as Rel, HasPrefix or a safe-named helper, on the path built from an archive entry name.
// Matching is by call name and identifier spelling only, so a helper that checks nothing still counts as evidence.
package rule

import (
	"go/ast"
	"strings"
)

// archiveJoinHasContainmentEvidence reports whether a containment-looking call wraps or uses the archive entry path built by joinCall.
//
// It walks body, skipping nested function literals, looking for a call that isArchiveContainmentCall accepts.
// That call counts when it contains the joinCall node itself or uses any name archiveJoinAssignedNames records for joinCall.
// It reports false when body holds no such call; names are matched by spelling, not by resolved object.
func archiveJoinHasContainmentEvidence(body *ast.BlockStmt, joinCall *ast.CallExpr) bool {
	assignedNames := archiveJoinAssignedNames(body, joinCall)
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		// A containment check inside a closure, such as a deferred func, does not count as evidence for this join.
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

// archiveJoinAssignedNames records local names assigned from joinCall, including assignments whose right-hand side wraps the join.
//
// It scans body, skipping nested function literals, for value specs and assignments whose value at a name's position contains joinCall.
// It returns a set keyed by those names, excluding _, and an empty non-nil map when body or joinCall is nil or nothing matches.
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

// isArchiveContainmentCall recognises parser-only evidence that code is checking archive extraction containment.
//
// It reports true when the callName of call is Clean, Rel, HasPrefix or Contains.
// It also reports true when that name, lowercased, contains safe, sanit, within or contain, and reports false otherwise.
// The word match is a plain substring, so a name such as unsafeCopy or uncontained also counts as containment evidence.
func isArchiveContainmentCall(call *ast.CallExpr) bool {
	name := callName(call)
	switch name {
	case "Clean", "Rel", "HasPrefix", "Contains":
		return true
	}
	lower := strings.ToLower(name)
	return strings.Contains(lower, "safe") || strings.Contains(lower, "sanit") || strings.Contains(lower, "within") || strings.Contains(lower, "contain")
}

// nodeContainsTarget reports whether root contains the exact AST node target, root itself included.
// It reports false when root or target is nil; a different node with the same text never matches.
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
// It reports false when root is nil or names is empty; any identifier with a matching spelling counts, selector field names included.
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
