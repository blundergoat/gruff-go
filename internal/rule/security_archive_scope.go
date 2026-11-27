// Package rule defines gruff-go's rule registry and analysers.
//
// This file checks whether an archive extraction guards its entry or joined path with a checked containment call such as Rel, HasPrefix, or IsLocal.
// Matching is parser-only by call name and identifier spelling, so a custom helper named safe* whose result is checked still counts as evidence.
package rule

import (
	"go/ast"
	"go/token"
	"strings"
)

// archiveJoinHasContainmentEvidence reports whether a containment check in body protects joinCall, entryExpr, or archiveNameVars.
//
// It walks body, skipping nested function literals, for calls isArchiveContainmentCall accepts, such as Rel, IsLocal or a safe-named helper.
//   - The call's result must be used; a stored result must be read by an if, switch or return.
//   - A bare filepath.Clean is not containment.
//   - Path aliases follow only path-producing expressions, so an unrelated err never stands in for the target.
func archiveJoinHasContainmentEvidence(body *ast.BlockStmt, joinCall *ast.CallExpr, entryExpr ast.Expr, archiveNameVars map[string]ast.Expr) bool {
	assignedNames := archiveJoinAssignedNames(body, joinCall)
	entryNames := archiveEntryIdentSet(archiveNameVars)
	entryText := formatExpr(entryExpr)
	found := false
	walkArchiveContainment(body, func(call *ast.CallExpr, boundIdents []*ast.Ident, isDiscarded bool) bool {
		// A discarded call, such as a bare filepath.Rel(dest, target) whose answer nobody reads, cannot protect the extraction.
		if found || isDiscarded || !isArchiveContainmentCall(call) {
			return !found
		}
		matchesTarget := nodeContainsTarget(call, joinCall) || nodeUsesAnyIdent(call, assignedNames)
		matchesEntry := isEntryGuardCall(call) && archiveCallInspectsEntry(call, entryText, entryNames)
		// A check on some other value, such as an error message, says nothing about where this entry is written.
		if !matchesTarget && !matchesEntry {
			return true
		}
		// A result stored in a variable counts only once an if, switch or return reads it.
		if len(boundIdents) > 0 && !anyIdentCheckedInControlFlow(body, boundIdents) {
			return true
		}
		found = true
		return false
	})
	return found
}

// walkArchiveContainment visits call expressions in body (skipping nested FuncLits) while noting bare discarded calls and LHS bindings.
func walkArchiveContainment(body *ast.BlockStmt, visit func(call *ast.CallExpr, boundIdents []*ast.Ident, isDiscarded bool) bool) {
	var walk func(node ast.Node, bound []*ast.Ident, discarded bool) bool
	walk = func(node ast.Node, bound []*ast.Ident, discarded bool) bool {
		if node == nil {
			return true
		}
		// A check inside a closure, such as a deferred func, may never run before the file is written, so it is not evidence.
		if _, nested := node.(*ast.FuncLit); nested {
			return true
		}
		switch typed := node.(type) {
		case *ast.ExprStmt:
			// A call used as a whole statement throws its result away.
			if call, ok := typed.X.(*ast.CallExpr); ok {
				return visit(call, nil, true)
			}
		case *ast.AssignStmt:
			return walkArchiveAssign(typed, walk)
		case *ast.ValueSpec:
			return walkArchiveValueSpec(typed, walk)
		case *ast.CallExpr:
			if !visit(typed, bound, discarded) {
				return false
			}
			for _, arg := range typed.Args {
				if !walk(arg, nil, false) {
					return false
				}
			}
			return true
		}
		keepGoing := true
		ast.Inspect(node, func(child ast.Node) bool {
			if !keepGoing {
				return false
			}
			if child == node {
				return true
			}
			if _, nested := child.(*ast.FuncLit); nested {
				return false
			}
			switch child.(type) {
			case *ast.ExprStmt, *ast.AssignStmt, *ast.ValueSpec, *ast.CallExpr:
				keepGoing = walk(child, nil, false)
				return false
			}
			return true
		})
		return keepGoing
	}
	walk(body, nil, false)
}

// walkArchiveAssign passes each right-hand expression of stmt to walk with its non-blank LHS identifiers attached.
// It returns true to continue traversal, or false as soon as walk returns false.
func walkArchiveAssign(stmt *ast.AssignStmt, walk func(ast.Node, []*ast.Ident, bool) bool) bool {
	// One call can fill several names, as in rel, err := filepath.Rel(dest, target), so every name is tied to that call.
	if len(stmt.Rhs) == 1 {
		bound, allBlank := nonBlankIdents(stmt.Lhs)
		return walk(stmt.Rhs[0], bound, allBlank)
	}
	// With several values, each name is tied only to the value in its own position.
	for i, rhs := range stmt.Rhs {
		var bound []*ast.Ident
		allBlank := false
		if i < len(stmt.Lhs) {
			bound, allBlank = nonBlankIdents([]ast.Expr{stmt.Lhs[i]})
		}
		if !walk(rhs, bound, allBlank) {
			return false
		}
	}
	return true
}

// walkArchiveValueSpec passes each value expression of spec to walk with its non-blank LHS identifiers attached.
// It returns true to continue traversal, or false as soon as walk returns false.
func walkArchiveValueSpec(spec *ast.ValueSpec, walk func(ast.Node, []*ast.Ident, bool) bool) bool {
	// One call in a var declaration can fill several names, so every declared name is tied to that call.
	if len(spec.Values) == 1 {
		exprs := make([]ast.Expr, len(spec.Names))
		for i, name := range spec.Names {
			exprs[i] = name
		}
		bound, allBlank := nonBlankIdents(exprs)
		return walk(spec.Values[0], bound, allBlank)
	}
	for i, val := range spec.Values {
		var bound []*ast.Ident
		allBlank := false
		if i < len(spec.Names) {
			bound, allBlank = nonBlankIdents([]ast.Expr{spec.Names[i]})
		}
		if !walk(val, bound, allBlank) {
			return false
		}
	}
	return true
}

// nonBlankIdents collects non-blank identifier targets from exprs and reports whether every target was the blank identifier _.
func nonBlankIdents(exprs []ast.Expr) ([]*ast.Ident, bool) {
	if len(exprs) == 0 {
		return nil, false
	}
	bound := make([]*ast.Ident, 0, len(exprs))
	allBlank := true
	// A field or index target, such as cfg.ok, keeps the result, so the call is not treated as discarded.
	for _, expr := range exprs {
		ident, ok := expr.(*ast.Ident)
		if !ok {
			allBlank = false
			continue
		}
		// A blank target discards that part of the result.
		if ident.Name == "_" {
			continue
		}
		allBlank = false
		bound = append(bound, ident)
	}
	return bound, allBlank
}

// anyIdentCheckedInControlFlow reports whether any identifier in idents is referenced inside an if/switch/return condition or expression in body.
func anyIdentCheckedInControlFlow(body *ast.BlockStmt, idents []*ast.Ident) bool {
	names := make(map[string]bool, len(idents))
	// Names are matched by spelling, so a check of an unrelated variable with the same name also counts.
	for _, ident := range idents {
		if ident != nil && ident.Name != "" && ident.Name != "_" {
			names[ident.Name] = true
		}
	}
	// With only blank targets there is nothing a later check could read.
	if len(names) == 0 {
		return false
	}
	checked := false
	ast.Inspect(body, func(node ast.Node) bool {
		if checked {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch stmt := node.(type) {
		case *ast.IfStmt:
			if nodeUsesAnyIdent(stmt.Cond, names) {
				checked = true
				return false
			}
		case *ast.SwitchStmt:
			if nodeUsesAnyIdent(stmt.Tag, names) {
				checked = true
				return false
			}
		case *ast.ReturnStmt:
			for _, result := range stmt.Results {
				if nodeUsesAnyIdent(result, names) {
					checked = true
					return false
				}
			}
		}
		return true
	})
	return checked
}

// archiveEntryIdentSet extracts the local variable names recorded in archiveNameVars.
func archiveEntryIdentSet(archiveNameVars map[string]ast.Expr) map[string]bool {
	out := make(map[string]bool, len(archiveNameVars))
	for name := range archiveNameVars {
		out[name] = true
	}
	return out
}

// isEntryGuardCall reports whether call can validate an archive entry name directly before or instead of joining it.
// The strings and bytes Contains functions count only when they look for "..", so a filter such as strings.Contains(f.Name, "__MACOSX") is no guard.
func isEntryGuardCall(call *ast.CallExpr) bool {
	switch callName(call) {
	case "IsLocal", "Localize", "OpenInRoot", "OpenRoot":
		return true
	case "Contains", "ContainsAny", "ContainsRune", "ContainsFunc":
		// A plain substring test protects the user's extraction folder only when it rejects parent-directory segments.
		return callHasDotDotLiteral(call)
	}
	lower := strings.ToLower(callName(call))
	return strings.Contains(lower, "safe") || strings.Contains(lower, "sanit") || strings.Contains(lower, "within") || strings.Contains(lower, "contain")
}

// callHasDotDotLiteral reports whether any argument of call is a string literal containing "..", such as strings.Contains(f.Name, "..").
func callHasDotDotLiteral(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		// Only a literal such as ".." or "../" shows the call is looking for an entry that climbs out of the destination.
		if literal, ok := arg.(*ast.BasicLit); ok && literal.Kind == token.STRING && strings.Contains(literal.Value, "..") {
			return true
		}
	}
	return false
}

// archiveCallInspectsEntry reports whether any argument of call references entryText or a local alias in entryNames.
func archiveCallInspectsEntry(call *ast.CallExpr, entryText string, entryNames map[string]bool) bool {
	for _, arg := range call.Args {
		// An argument that uses a local copy of the entry name, such as name := f.Name, inspects the entry.
		if nodeUsesAnyIdent(arg, entryNames) {
			return true
		}
		// An argument that spells the entry expression itself, such as f.Name, inspects it too.
		if entryText != "" && strings.Contains(formatExpr(arg), entryText) {
			return true
		}
	}
	return false
}

// archiveJoinAssignedNames records local names in body assigned from joinCall or derived from them via path-producing operations.
//
// It scans body, skipping closures, to a fixed point so alias chains like target := filepath.Join(...); clean := filepath.Clean(target)
// reach containment checks without following non-path calls such as os.MkdirAll; returns an empty map when body or joinCall is nil.
func archiveJoinAssignedNames(body *ast.BlockStmt, joinCall *ast.CallExpr) map[string]bool {
	names := map[string]bool{}
	// Without a function body or a join call there are no path names to track.
	if body == nil || joinCall == nil {
		return names
	}
	// Repeat until no new name is added, so a chain such as target -> clean -> final is followed to its end.
	for {
		added := false
		ast.Inspect(body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			switch stmt := node.(type) {
			case *ast.ValueSpec:
				for i, name := range stmt.Names {
					// Skip blank names, names already tracked, and names without a value of their own.
					if name.Name == "_" || names[name.Name] || i >= len(stmt.Values) {
						continue
					}
					// A name set from the joined path, or from a path built on it, now holds the extraction target.
					if nodeContainsTarget(stmt.Values[i], joinCall) || isArchiveDerivedPathExpr(stmt.Values[i], names) {
						names[name.Name] = true
						added = true
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range stmt.Lhs {
					name, ok := lhs.(*ast.Ident)
					// Skip non-name targets, blank names, names already tracked, and names without a value of their own.
					if !ok || name.Name == "_" || names[name.Name] || i >= len(stmt.Rhs) {
						continue
					}
					// A name assigned from the joined path, or from a path built on it, now holds the extraction target.
					if nodeContainsTarget(stmt.Rhs[i], joinCall) || isArchiveDerivedPathExpr(stmt.Rhs[i], names) {
						names[name.Name] = true
						added = true
					}
				}
			}
			return true
		})
		// A pass that adds no name means every alias has been found.
		if !added {
			break
		}
	}
	return names
}

// isArchiveDerivedPathExpr reports whether expr derives a path value from a tracked archive path identifier in names.
// Arbitrary non-path calls such as os.MkdirAll or os.Create return false so their error or file results never alias the target path.
func isArchiveDerivedPathExpr(expr ast.Expr, names map[string]bool) bool {
	if expr == nil || len(names) == 0 {
		return false
	}
	switch node := expr.(type) {
	case *ast.Ident:
		return names[node.Name]
	case *ast.ParenExpr:
		return isArchiveDerivedPathExpr(node.X, names)
	case *ast.CallExpr:
		switch callName(node) {
		// Only path-shaping calls carry the target forward; os.MkdirAll(filepath.Dir(target), 0o755) returns an error, not a path.
		case "Clean", "Abs", "EvalSymlinks", "ToSlash", "FromSlash", "Join", "Dir":
			return nodeUsesAnyIdent(node, names)
		}
	}
	return false
}

// isArchiveContainmentCall recognises parser-only evidence that call is checking archive extraction containment.
//
// Rel, HasPrefix, IsLocal, Localize, OpenInRoot, OpenRoot, or a helper named with safe, sanit, within, or contain return true.
// Contains* calls count only when checking for ".."; bare filepath.Clean or path.Clean returns false since cleaning does not enforce containment.
func isArchiveContainmentCall(call *ast.CallExpr) bool {
	name := callName(call)
	switch name {
	case "Rel", "HasPrefix", "IsLocal", "Localize", "OpenInRoot", "OpenRoot":
		return true
	case "Contains", "ContainsAny", "ContainsRune", "ContainsFunc":
		// A substring test on a joined target path counts only when it rejects parent-directory traversal ("..").
		return callHasDotDotLiteral(call)
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
