// Package rule defines gruff-go's rule registry and analysers.
//
// This file decides when a later write removes a binding's request taint before a sink reads it.
// The request-driven security rules consult it before flagging a value.
// Without it, a handler that replaces request input with request-free data before the sink could still be reported as a finding.
package rule

import (
	"go/ast"
	"go/token"
)

// taintClearedBefore reports whether a write carrying no request data is guaranteed to replace this binding's value before sinkPos.
//
// Only writes that dominate the sink count: an assignment inside a branch the sink sits outside of may never run, so it proves nothing.
// A true result lets taintedBefore treat the sink as reading clean data, so a handler that overwrites request input first is not flagged.
//
// binding is the tainted variable's declaration object and taintPos is where its taint was first introduced; only writes after taintPos count.
// sinkPos is the position of the sink reading the binding.
//
// It reports false when the scope has no body, sinkPos is invalid, the body uses goto, &binding appears or a closure assigns binding by bare name.
// It also reports false when no request-free dominating write follows taintPos, or a later bare-name assignment may restore request data.
func (s *requestTaintScope) taintClearedBefore(binding *ast.Object, taintPos, sinkPos token.Pos) bool {
	// Without a body or an ordered sink there is no dominance to establish.
	if s.body == nil || !sinkPos.IsValid() {
		return false
	}
	// Some constructs break the straight-line ordering this proof relies on, and
	// wrongly clearing taint hides a real finding rather than adding a noisy one.
	if s.clearingDefeatedByControlFlow(binding) {
		return false
	}
	clearPos := token.NoPos
	// Later dominating writes override earlier ones, so the last one decides.
	for _, statement := range statementsDominatingSink(s.body, sinkPos) {
		assignment, isAssignment := statement.(*ast.AssignStmt)
		if !isAssignment || assignment.Pos() <= taintPos {
			continue
		}
		value, attributed := replacementValueFor(assignment, binding)
		// A plain write of request-free data such as name = "guest" clears; name += "x" or name, err := lookup() never clears.
		if attributed && s.exprCarriesNoRequestData(value) {
			clearPos = assignment.Pos()
		}
	}
	// No dominating write replaced the request-controlled value.
	if !clearPos.IsValid() {
		return false
	}
	// A later write that may put request data back defeats the clear, even inside a branch that may not run, so the binding keeps its taint.
	return !s.bindingRewrittenBetween(binding, clearPos, sinkPos)
}

// bindingRewrittenBetween reports whether an assignment with binding as its bare-name target, inside the window, can bring back request data.
//
// Branch-local and closure writes count, because this asks whether the clear still holds rather than whether it ran.
// A true result means the clear does not hold, so the binding stays tainted at the sink and the calling rule decides whether to report it.
//
// afterPos and beforePos bound the window exclusively: only assignments starting after afterPos and before beforePos are examined.
// A compound or multi-value write to binding counts as a rewrite; a plain write counts only when its value may carry request data.
// It reports false when no such write falls in the window.
func (s *requestTaintScope) bindingRewrittenBetween(binding *ast.Object, afterPos, beforePos token.Pos) bool {
	rewritten := false
	ast.Inspect(s.body, func(node ast.Node) bool {
		if rewritten {
			return false
		}
		switch typed := node.(type) {
		case *ast.AssignStmt:
			// Only an assignment between the sanitizing call and the sink can put request data back into the value.
			if typed.Pos() <= afterPos || typed.Pos() >= beforePos {
				return true
			}
			rewritten = s.assignmentMayRestoreRequestData(typed, binding)
		case *ast.RangeStmt:
			if typed.Pos() <= afterPos || typed.Pos() >= beforePos {
				return true
			}
			if rangeWritesBinding(typed, binding) && !s.exprCarriesNoRequestData(typed.X) {
				rewritten = true
			}
		}
		return true
	})
	return rewritten
}

// rangeWritesBinding reports whether rangeStmt assigns its key or value to binding as a bare identifier.
// It returns false when rangeStmt is nil or neither its Key nor Value resolves to binding.
func rangeWritesBinding(rangeStmt *ast.RangeStmt, binding *ast.Object) bool {
	if rangeStmt == nil {
		return false
	}
	return identifierBinds(rangeStmt.Key, binding) || identifierBinds(rangeStmt.Value, binding)
}

// assignmentMayRestoreRequestData reports whether assignment writes binding with a value that may carry request data.
// Compound or multi-value writes to binding return true; plain writes return true unless exprCarriesNoRequestData proves them clean.
func (s *requestTaintScope) assignmentMayRestoreRequestData(assignment *ast.AssignStmt, binding *ast.Object) bool {
	if assignment == nil {
		return false
	}
	value, attributed := replacementValueFor(assignment, binding)
	// A compound or multi-value write keeps or may restore request data.
	if !attributed {
		return assignmentWritesBinding(assignment, binding)
	}
	return !s.exprCarriesNoRequestData(value)
}

// enclosingLoopStartForBackEdgeTaint returns the start position of the innermost loop enclosing sinkPos that can re-taint binding on its back-edge.
//
// When a loop body after sinkPos or a for-loop post statement writes request-derived data into binding, iteration 2+ enters sinkPos tainted unless
// a dominating clean write inside that loop runs before sinkPos.
// It returns token.NoPos when no enclosing loop rewrites binding with request data after sinkPos, or when body or sinkPos is invalid.
func (s *requestTaintScope) enclosingLoopStartForBackEdgeTaint(binding *ast.Object, sinkPos token.Pos) token.Pos {
	if s.body == nil || !sinkPos.IsValid() {
		return token.NoPos
	}
	innermost := token.NoPos
	ast.Inspect(s.body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		switch loop := node.(type) {
		case *ast.ForStmt:
			if loop.Pos() >= sinkPos || sinkPos >= loop.End() {
				return true
			}
			postAssign, _ := loop.Post.(*ast.AssignStmt)
			if s.assignmentMayRestoreRequestData(postAssign, binding) || s.bindingRewrittenBetween(binding, sinkPos, loop.End()) {
				if !innermost.IsValid() || loop.Pos() > innermost {
					innermost = loop.Pos()
				}
			}
		case *ast.RangeStmt:
			if loop.Pos() >= sinkPos || sinkPos >= loop.End() {
				return true
			}
			if (rangeWritesBinding(loop, binding) && !s.exprCarriesNoRequestData(loop.X)) ||
				s.bindingRewrittenBetween(binding, sinkPos, loop.End()) {
				if !innermost.IsValid() || loop.Pos() > innermost {
					innermost = loop.Pos()
				}
			}
		}
		return true
	})
	return innermost
}

// clearingDefeatedByControlFlow reports whether the body uses a construct that makes statement order unsafe for proving a clear.
//
// A goto can skip the clearing write, &binding lets a callee rewrite it, and a closure assigning binding by bare name may run later.
// Each one keeps the taint rather than risking a missed finding.
//
// binding is the tainted variable whose clearing write is being checked.
// It reports false when the body has no goto, no &binding and no closure assigning binding by bare name; the caller still looks for a clear.
func (s *requestTaintScope) clearingDefeatedByControlFlow(binding *ast.Object) bool {
	defeated := false
	ast.Inspect(s.body, func(node ast.Node) bool {
		if defeated {
			return false
		}
		switch typed := node.(type) {
		// Any goto in the function, even one far from this binding, blocks clearing, so every tainted value there stays tainted.
		case *ast.BranchStmt:
			defeated = typed.Tok == token.GOTO
		// Any &binding, such as json.Unmarshal(data, &name), lets a callee rewrite the value, so the taint stays.
		case *ast.UnaryExpr:
			defeated = typed.Op == token.AND && identifierBinds(typed.X, binding)
		case *ast.FuncLit:
			// The walk still descends, so a goto or address-of inside a closure that leaves the binding alone is not missed.
			defeated = blockWritesBinding(typed.Body, binding)
		}
		return !defeated
	})
	return defeated
}

// blockWritesBinding reports whether an assignment statement inside block has binding as a bare-name target.
//
// clearingDefeatedByControlFlow calls it on each closure body; range clauses and parenthesised targets such as (binding) are missed.
// It reports false when no assignment in block, under any operator, has binding bare on its left-hand side.
func blockWritesBinding(block *ast.BlockStmt, binding *ast.Object) bool {
	written := false
	ast.Inspect(block, func(node ast.Node) bool {
		if written {
			return false
		}
		switch typed := node.(type) {
		case *ast.AssignStmt:
			written = assignmentWritesBinding(typed, binding)
		case *ast.RangeStmt:
			written = rangeWritesBinding(typed, binding)
		}
		return !written
	})
	return written
}

// identifierBinds reports whether expr is exactly this binding's identifier.
//
// binding is the declaration object expr must resolve to, so a same-spelled name in another scope does not match.
// It reports false for a selector such as user.Name, an index or any other expression, and for an unresolved identifier.
func identifierBinds(expr ast.Expr, binding *ast.Object) bool {
	identifier, isIdentifier := expr.(*ast.Ident)
	return isIdentifier && identifier.Obj != nil && identifier.Obj == binding
}

// exprCarriesNoRequestData reports whether expr can be written to a tainted binding without carrying request data into it.
//
// Reading the request, or any tainted local including the binding itself, keeps the taint alive, so name = strings.TrimSpace(name) never clears.
// It reports false when any part of expr, even a nested call argument, reads the request or names a tainted binding.
func (s *requestTaintScope) exprCarriesNoRequestData(expr ast.Expr) bool {
	clean := true
	ast.Inspect(expr, func(node ast.Node) bool {
		if !clean {
			return false
		}
		candidate, isExpr := node.(ast.Expr)
		if !isExpr {
			return true
		}
		if _, readsRequest := s.requestAccessLabel(candidate); readsRequest {
			clean = false
			return false
		}
		identifier, isIdentifier := candidate.(*ast.Ident)
		if !isIdentifier {
			return true
		}
		if s.isRequestIdentifier(identifier) || (identifier.Obj != nil && s.taintedBindings[identifier.Obj]) {
			clean = false
			return false
		}
		return true
	})
	return clean
}

// replacementValueFor returns the value a plain = or := assignment writes to binding as a bare identifier, and true when it found one.
//
// A compound assignment keeps the previous value, and sides of unequal length, as in a multi-value call or comma-ok read, cannot pair per name.
// It returns nil and false for those, and when assignment does not name binding on its left-hand side.
func replacementValueFor(assignment *ast.AssignStmt, binding *ast.Object) (ast.Expr, bool) {
	if assignment.Tok != token.ASSIGN && assignment.Tok != token.DEFINE {
		return nil, false
	}
	if len(assignment.Lhs) != len(assignment.Rhs) {
		return nil, false
	}
	for index, lhs := range assignment.Lhs {
		if identifierBinds(lhs, binding) {
			return assignment.Rhs[index], true
		}
	}
	return nil, false
}

// assignmentWritesBinding reports whether binding is a bare identifier on the assignment's left-hand side under any assignment operator.
//
// Unlike replacementValueFor, it also counts += and multi-value writes such as name, err = parse(data).
// It reports false when assignment only writes other names, or writes a field or element such as user.Name rather than binding itself.
func assignmentWritesBinding(assignment *ast.AssignStmt, binding *ast.Object) bool {
	for _, lhs := range assignment.Lhs {
		if identifierBinds(lhs, binding) {
			return true
		}
	}
	return false
}

// statementsDominatingSink collects the statements that must run before the sink on every path reaching it.
//
// At each level of the sink's enclosing statement lists it takes the statements preceding the one the sink sits in, outermost first.
// Descent follows blocks, labels, if and else branches, loop bodies and case or comm clauses, and stops at anything else, such as a closure.
//
// body is the function body to search and sinkPos is the sink's position.
// It returns the collected statements, an empty slice when nothing precedes the sink at any level or sinkPos lies outside every statement in body.
func statementsDominatingSink(body *ast.BlockStmt, sinkPos token.Pos) []ast.Stmt {
	dominating := []ast.Stmt{}
	statements := body.List
	for statements != nil {
		containing := statementHolding(statements, sinkPos)
		// The sink is not inside this list, so nothing deeper can dominate it.
		if containing < 0 {
			break
		}
		dominating = append(dominating, statements[:containing]...)
		statements = innerStatementsHolding(statements[containing], sinkPos)
	}
	return dominating
}

// statementHolding returns the index of the statement containing sinkPos, or -1.
// statements is the statement list to search in order; a statement holds sinkPos when it starts at or before it and ends after it.
func statementHolding(statements []ast.Stmt, sinkPos token.Pos) int {
	for index, statement := range statements {
		if statement.Pos() <= sinkPos && sinkPos < statement.End() {
			return index
		}
	}
	return -1
}

// innerStatementsHolding returns the statement list inside statement that holds sinkPos.
//
// Descending into a branch or loop body is sound because the sink is known to be inside it, so the body's earlier statements still precede it.
// Anything else, notably a closure that runs at an unrelated time, ends the walk rather than lending its statements dominance they do not have.
//
// It returns nil for such a statement and for a sink in an if or loop header; a sink in a case or comm header gets that clause's body.
func innerStatementsHolding(statement ast.Stmt, sinkPos token.Pos) []ast.Stmt {
	switch typed := statement.(type) {
	case *ast.BlockStmt:
		return typed.List
	case *ast.LabeledStmt:
		return innerStatementsHolding(typed.Stmt, sinkPos)
	case *ast.IfStmt:
		if blockHolds(typed.Body, sinkPos) {
			return typed.Body.List
		}
		if typed.Else != nil && typed.Else.Pos() <= sinkPos && sinkPos < typed.Else.End() {
			return innerStatementsHolding(typed.Else, sinkPos)
		}
	case *ast.ForStmt:
		if blockHolds(typed.Body, sinkPos) {
			return typed.Body.List
		}
	case *ast.RangeStmt:
		if blockHolds(typed.Body, sinkPos) {
			return typed.Body.List
		}
	case *ast.SwitchStmt:
		return clauseStatementsHolding(typed.Body, sinkPos)
	case *ast.TypeSwitchStmt:
		return clauseStatementsHolding(typed.Body, sinkPos)
	case *ast.SelectStmt:
		return clauseStatementsHolding(typed.Body, sinkPos)
	}
	return nil
}

// clauseStatementsHolding returns the case or comm clause body holding sinkPos.
//
// body is the switch, type switch or select block whose clauses are searched.
// It returns nil when body is nil or no clause holds sinkPos, such as a sink in the switch tag, which ends the walk.
func clauseStatementsHolding(body *ast.BlockStmt, sinkPos token.Pos) []ast.Stmt {
	if body == nil {
		return nil
	}
	for _, clause := range body.List {
		if clause.Pos() > sinkPos || sinkPos >= clause.End() {
			continue
		}
		switch typed := clause.(type) {
		case *ast.CaseClause:
			return typed.Body
		case *ast.CommClause:
			return typed.Body
		}
	}
	return nil
}

// blockHolds reports whether sinkPos falls inside this block.
// It reports false when block is nil or sinkPos lies outside its braces.
func blockHolds(block *ast.BlockStmt, sinkPos token.Pos) bool {
	return block != nil && block.Pos() <= sinkPos && sinkPos < block.End()
}
