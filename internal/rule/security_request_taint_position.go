// Package rule defines gruff-go's rule registry and analysers.
// This file resolves where a request-taint value becomes available within a
// function body, so a sink that runs before the taint is introduced is not
// flagged. The position tracking is shared by the request-driven security rules.
package rule

import (
	"go/ast"
	"go/token"
)

// markTaintedAt records name as carrying request-controlled data and remembers
// the earliest position at which that taint became available, so taintedBefore
// can keep the taint from leaking backwards to sinks that run before it.
func (s *requestTaintScope) markTaintedAt(name string, pos token.Pos) {
	s.tainted[name] = true
	if prev, ok := s.firstTaintPos[name]; !ok || pos < prev {
		s.firstTaintPos[name] = pos
	}
}

// taintIntroPos resolves when an assignment's request taint becomes available. A
// value that merely forwards another tainted value - a pure alias (b := a), a
// string-builder/conversion/path.Clean wrapper (b := fmt.Sprintf("%s", a)), or a
// concatenation (b := a + x) - inherits the source's earliest taint position, so a
// value wrapped before its source is tainted (a := safe; b := wrap(a); sink(b); a =
// req) is not flagged at the wrapper; a direct request access taints at the
// assignment. Mirrors the propagation set in directRequestExpr.
func (s *requestTaintScope) taintIntroPos(rhs ast.Expr, fallback token.Pos) token.Pos {
	switch e := rhs.(type) {
	case *ast.ParenExpr:
		return s.taintIntroPos(e.X, fallback)
	case *ast.StarExpr:
		return s.taintIntroPos(e.X, fallback)
	case *ast.Ident:
		if pos, ok := s.firstTaintPos[e.Name]; ok {
			return pos
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
		if s.isStringBuilderCall(e) || s.isReaderConsumer(e) {
			return s.earliestOperandTaintPos(e.Args, fallback)
		}
	}
	return fallback
}

// earliestOperandTaintPos returns the earliest taint-introduction position among
// the request-controlled operands of a wrapper or concatenation, so the wrapped
// value inherits its source's taint position rather than its own (possibly
// earlier) assignment position.
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

// taintedBefore reports whether name carries request data introduced at or before
// sinkPos. An invalid sinkPos disables the ordering check (treating any taint as
// in scope) so callers without a position still get the previous behaviour.
func (s *requestTaintScope) taintedBefore(name string, sinkPos token.Pos) bool {
	if !s.tainted[name] {
		return false
	}
	if !sinkPos.IsValid() {
		return true
	}
	pos, ok := s.firstTaintPos[name]
	return ok && pos < sinkPos
}
