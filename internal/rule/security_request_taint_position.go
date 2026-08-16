// Package rule defines gruff-go's rule registry and analysers.
// This file resolves where a request-taint value becomes available within a
// function body, so a sink that runs before the taint is introduced is not
// flagged. The position tracking is shared by the request-driven security rules.
package rule

import (
	"go/ast"
	"go/token"
)

// markTaintedAt records one lexical binding as request-controlled and remembers
// when that taint first became available. Unresolved names are not conflated
// with same-spelled variables in another scope.
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

// taintedBefore reports whether a binding carries request data introduced before
// sinkPos. An invalid sinkPos disables ordering so inline checks retain taint.
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
