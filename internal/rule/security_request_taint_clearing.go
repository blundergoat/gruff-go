// Package rule defines gruff-go's rule registry and analysers.
// This file decides when a later write removes a binding's request taint before a
// sink reads it. Taint that a dominating assignment has already replaced would
// otherwise report correctly written handlers, so the request-driven security
// rules consult this before flagging a value.
package rule

import (
	"go/ast"
	"go/token"
)

// taintClearedBefore reports whether a write carrying no request data is
// guaranteed to replace this binding's value before sinkPos. Only writes that
// dominate the sink count: an assignment inside a branch the sink sits outside of
// may never run, so it proves nothing about what the sink reads.
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
		if attributed && s.exprCarriesNoRequestData(value) {
			clearPos = assignment.Pos()
		}
	}
	// No dominating write replaced the request-controlled value.
	if !clearPos.IsValid() {
		return false
	}
	// A write after the clear - including one inside a branch that may not run -
	// can put request data back, so the clear only holds while nothing follows it.
	return !s.bindingRewrittenBetween(binding, clearPos, sinkPos)
}

// bindingRewrittenBetween reports whether any write to binding between the two
// positions can reintroduce request data. Branch-local and closure writes count,
// because this asks whether the clear still holds rather than whether it ran.
func (s *requestTaintScope) bindingRewrittenBetween(binding *ast.Object, afterPos, beforePos token.Pos) bool {
	rewritten := false
	ast.Inspect(s.body, func(node ast.Node) bool {
		if rewritten {
			return false
		}
		assignment, isAssignment := node.(*ast.AssignStmt)
		if !isAssignment || assignment.Pos() <= afterPos || assignment.Pos() >= beforePos {
			return true
		}
		value, attributed := replacementValueFor(assignment, binding)
		// A compound or multi-value write keeps or may restore request data.
		if !attributed {
			rewritten = assignmentWritesBinding(assignment, binding)
			return true
		}
		rewritten = !s.exprCarriesNoRequestData(value)
		return true
	})
	return rewritten
}

// clearingDefeatedByControlFlow reports whether this body uses a construct that
// makes statement order an unreliable guide to what reaches the sink. A `goto`
// can jump over the clearing write, taking the binding's address lets a callee
// rewrite it invisibly, and a closure assigning it runs at a time this ordering
// cannot predict. Each one keeps the taint rather than risking a missed finding.
func (s *requestTaintScope) clearingDefeatedByControlFlow(binding *ast.Object) bool {
	defeated := false
	ast.Inspect(s.body, func(node ast.Node) bool {
		if defeated {
			return false
		}
		switch typed := node.(type) {
		case *ast.BranchStmt:
			defeated = typed.Tok == token.GOTO
		case *ast.UnaryExpr:
			defeated = typed.Op == token.AND && identifierBinds(typed.X, binding)
		case *ast.FuncLit:
			// The walk still descends, so a `goto` or address-of inside a closure
			// that leaves the binding alone is not missed.
			defeated = blockWritesBinding(typed.Body, binding)
		}
		return !defeated
	})
	return defeated
}

// blockWritesBinding reports whether any assignment inside block targets binding.
func blockWritesBinding(block *ast.BlockStmt, binding *ast.Object) bool {
	written := false
	ast.Inspect(block, func(node ast.Node) bool {
		if written {
			return false
		}
		if assignment, isAssignment := node.(*ast.AssignStmt); isAssignment {
			written = assignmentWritesBinding(assignment, binding)
		}
		return !written
	})
	return written
}

// identifierBinds reports whether expr is exactly this binding's identifier.
func identifierBinds(expr ast.Expr, binding *ast.Object) bool {
	identifier, isIdentifier := expr.(*ast.Ident)
	return isIdentifier && identifier.Obj != nil && identifier.Obj == binding
}

// exprCarriesNoRequestData reports whether expr can be written to a tainted
// binding without carrying request data into it. Reading the request, or any
// tainted local including the binding itself, keeps the taint alive.
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

// replacementValueFor returns the value a plain assignment writes to binding.
// A compound assignment keeps the previous value and a multi-value call cannot be
// split per name, so neither yields a replacement this analysis can reason about.
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

// assignmentWritesBinding reports whether binding appears on the assignment's
// left-hand side under any assignment operator.
func assignmentWritesBinding(assignment *ast.AssignStmt, binding *ast.Object) bool {
	for _, lhs := range assignment.Lhs {
		if identifierBinds(lhs, binding) {
			return true
		}
	}
	return false
}

// statementsDominatingSink collects the statements that must run before the sink
// on every path reaching it: at each level of the sink's enclosing statement
// lists, the statements preceding the one the sink sits in, outermost first.
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
func statementHolding(statements []ast.Stmt, sinkPos token.Pos) int {
	for index, statement := range statements {
		if statement.Pos() <= sinkPos && sinkPos < statement.End() {
			return index
		}
	}
	return -1
}

// innerStatementsHolding returns the statement list inside statement that holds
// sinkPos. Descending into a branch or loop body is sound because the sink is
// already known to be inside it, so the body's earlier statements still precede
// it. Anything else - notably a closure, which runs at an unrelated time - ends
// the walk rather than lending its statements dominance they do not have.
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
func blockHolds(block *ast.BlockStmt, sinkPos token.Pos) bool {
	return block != nil && block.Pos() <= sinkPos && sinkPos < block.End()
}
