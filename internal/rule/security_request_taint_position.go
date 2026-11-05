// Package rule defines gruff-go's rule registry and analysers.
//
// This file resolves where a request-taint value becomes available within a function body.
// A sink placed before the taint is introduced, such as sink(name) above name = r.FormValue("n"), is not flagged.
// The position tracking is shared by the request-driven security rules.
package rule

import (
	"go/ast"
	"go/token"
)

// markTaintedAt records one lexical binding as request-controlled and remembers when that taint first became available.
//
// Unresolved names are not conflated with same-spelled variables in another scope.
// taintedBefore compares each sink against the recorded position, so a sink placed before the taint is not flagged.
//
// identifier names the binding to taint; a nil, blank or unresolved identifier is ignored.
// pos is where the taint became available, and only the earliest pos recorded for a binding is kept.
func (s *requestTaintScope) markTaintedAt(identifier *ast.Ident, pos token.Pos) {
	// Blank or unresolved syntax cannot anchor a binding-safe taint fact.
	if identifier == nil || identifier.Name == "_" || identifier.Obj == nil {
		return
	}
	s.taintedBindings[identifier.Obj] = true
	if previousPosition, exists := s.firstTaintPos[identifier.Obj]; !exists || pos < previousPosition {
		s.firstTaintPos[identifier.Obj] = pos
	}
}

// taintIntroPos resolves when an assignment's request taint becomes available.
//
// Aliases, conversions, string-builder and reader wrappers, path.Clean, concatenations and parsed-URL String calls inherit the source's position.
// A sink placed before the forwarded source is tainted is not flagged; direct request access and URL syntax parses taint at the assignment.
//
// rhs is the assigned expression, looked through parentheses, dereferences and the forwarding wrappers above.
// fallback is used for a direct request access, a URL syntax parse, or any rhs that forwards no binding with a recorded taint position.
// It returns the earliest taint position among the forwarded sources, or fallback when rhs forwards none.
func (s *requestTaintScope) taintIntroPos(rhs ast.Expr, fallback token.Pos) token.Pos {
	switch e := rhs.(type) {
	case *ast.ParenExpr:
		return s.taintIntroPos(e.X, fallback)
	case *ast.StarExpr:
		return s.taintIntroPos(e.X, fallback)
	case *ast.Ident:
		if e.Obj != nil {
			if pos, ok := s.firstTaintPos[e.Obj]; ok {
				return pos
			}
		}
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return s.earliestOperandTaintPos([]ast.Expr{e.X, e.Y}, fallback)
		}
	case *ast.CallExpr:
		if arg, ok := conversionArg(e); ok {
			return s.taintIntroPos(arg, fallback)
		}
		if arg, ok := s.pathCleanArg(e); ok {
			return s.taintIntroPos(arg, fallback)
		}
		if receiver, ok := s.parsedURLStringReceiver(e); ok {
			return s.taintIntroPos(receiver, fallback)
		}
		if s.isStringBuilderCall(e) || s.isReaderConsumer(e) {
			return s.earliestOperandTaintPos(e.Args, fallback)
		}
	}
	return fallback
}

// earliestOperandTaintPos returns the earliest taint-introduction position among the request-controlled operands of a wrapper or concatenation.
//
// The wrapped value inherits its source's taint position rather than its own, possibly earlier, assignment position.
//
// args are the wrapper's arguments or the concatenation's operands; only those directRequestExpr accepts are considered.
// fallback is passed to taintIntroPos for each considered operand and is returned when no operand is considered.
func (s *requestTaintScope) earliestOperandTaintPos(args []ast.Expr, fallback token.Pos) token.Pos {
	best := token.NoPos
	for _, arg := range args {
		if !s.directRequestExpr(arg) {
			continue
		}
		pos := s.taintIntroPos(arg, fallback)
		if !best.IsValid() || pos < best {
			best = pos
		}
	}
	if best.IsValid() {
		return best
	}
	return fallback
}

// taintedBefore reports whether a binding carries request data introduced before sinkPos.
//
// An invalid sinkPos disables ordering so inline checks retain taint.
// For name := "guest", then sink(name), then name = r.FormValue("n"), it reports false at the sink.
//
// identifier is the use being checked; it reports false for a nil or unresolved identifier, or one whose binding was never tainted.
// With a valid sinkPos it also reports false when no taint is recorded before sinkPos or a dominating request-free write clears it first.
func (s *requestTaintScope) taintedBefore(identifier *ast.Ident, sinkPos token.Pos) bool {
	// A use must resolve to the same declaration that introduced the taint.
	if identifier == nil || identifier.Obj == nil || !s.taintedBindings[identifier.Obj] {
		return false
	}
	if !sinkPos.IsValid() {
		return true
	}
	pos, ok := s.firstTaintPos[identifier.Obj]
	if !ok || pos >= sinkPos {
		return false
	}
	// A dominating write of request-free data replaces the tainted value, so the
	// sink reads clean data even though this binding held request input earlier.
	return !s.taintClearedBefore(identifier.Obj, pos, sinkPos)
}
