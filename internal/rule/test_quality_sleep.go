// Package rule defines gruff-go's rule registry and analysers.
// This file implements a parser-only test-quality check for time.Sleep
// usage in Go test files. Sleeps in tests are the dominant source of
// flakiness because real timing is non-deterministic across machines and CI.
package rule

import (
	"go/ast"
	"go/token"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// SleepInTestRule flags time.Sleep call sites inside *_test.go files. The
// rule is scoped to test files because production code legitimately sleeps
// (rate limiting, retry backoff); inside tests the same call is almost
// always either a flake or a missing synchronisation primitive.
type SleepInTestRule struct{}

// Definition declares the test-quality.sleep-in-test rule, its severity,
// default-enabled state, flake-oriented tags, and remediation guidance
// pointing maintainers at channel- or fake-clock-based alternatives.
func (SleepInTestRule) Definition() Definition {
	return Definition{
		ID:             "test-quality.sleep-in-test",
		Title:          "Sleep in test",
		Description:    "Flags time.Sleep calls in _test.go files. Sleeps are the dominant source of test flakiness; prefer explicit synchronisation primitives or fake clocks.",
		Pillar:         finding.PillarTestQuality,
		Severity:       finding.SeverityAdvisory,
		Confidence:     finding.ConfidenceHigh,
		Capability:     CapabilityParser,
		DefaultEnabled: true,
		Tags:           []string{"tests", "flake"},
		Remediation:    "Replace time.Sleep with channel/WaitGroup synchronisation, polling against an observable condition, or a fake clock that advances deterministically.",
	}
}

// AnalyzeUnit emits findings for every time.Sleep call site in test files.
// The rule walks fn.Body per declaration so the finding's Symbol carries the
// enclosing test or helper function name, which makes triage in large suites
// considerably faster than a bare file:line pointer.
func (SleepInTestRule) AnalyzeUnit(unit parser.Unit, ctx Context) []finding.Finding {
	if unit.AST == nil || unit.FileSet == nil || !isGoTestFile(unit.File.Path) || shouldSkipGeneratedUnit(unit, ctx) {
		return nil
	}
	timePackages := packageImportNames(unit.AST, "time", "time")
	if len(timePackages) == 0 {
		return nil
	}
	testingPackages := testingPackageNames(unit.AST)
	assertionPackages := assertionPackageNames(unit.AST)
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		symbol := functionName(fn)
		acceptedPollingSleeps := acceptedPollingSleepPositions(fn, timePackages, testingPackages, assertionPackages)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !selectorCallMatches(call, timePackages, "Sleep") {
				return true
			}
			if acceptedPollingSleeps[call.Pos()] {
				return true
			}
			position := unit.FileSet.Position(call.Pos())
			findings = append(findings, finding.Finding{
				Message:  "test calls time.Sleep; replace with explicit synchronisation",
				File:     unit.File.Path,
				Location: &finding.Location{Line: position.Line, Column: position.Column},
				Symbol:   symbol,
				Metadata: map[string]any{"call": "time.Sleep"},
			})
			return true
		})
	}
	return findings
}

// acceptedPollingSleepPositions returns time.Sleep call positions that sit
// inside a bounded polling loop with observable work and a failure after timeout.
func acceptedPollingSleepPositions(fn *ast.FuncDecl, timePackages, testingPackages, assertionPackages map[string]bool) map[token.Pos]bool {
	accepted := map[token.Pos]bool{}
	if fn == nil || fn.Body == nil {
		return accepted
	}
	ctx := pollingLoopContext{
		timePackages:      timePackages,
		testingPackages:   testingPackages,
		assertionPackages: assertionPackages,
		receivers:         testingHandlesForFunc(fn, testingPackages),
		accepted:          accepted,
	}
	collectAcceptedPollingSleeps(fn.Body, ctx)
	return accepted
}

// pollingLoopContext carries the parser-only evidence sets used while accepting
// bounded polling sleeps.
type pollingLoopContext struct {
	timePackages      map[string]bool
	testingPackages   map[string]bool
	assertionPackages map[string]bool
	receivers         map[string]bool
	accepted          map[token.Pos]bool
}

// collectAcceptedPollingSleeps walks block statements and records sleep calls
// under accepted polling loops without suppressing unrelated sleeps elsewhere.
func collectAcceptedPollingSleeps(block *ast.BlockStmt, ctx pollingLoopContext) {
	if block == nil {
		return
	}
	for index, stmt := range block.List {
		switch current := stmt.(type) {
		case *ast.ForStmt:
			if isAcceptedPollingLoop(current, block.List[index+1:], ctx) {
				recordSleepCalls(current.Body, ctx.timePackages, ctx.accepted)
				continue
			}
			collectAcceptedPollingSleeps(current.Body, ctx)
		case *ast.RangeStmt:
			collectAcceptedPollingSleeps(current.Body, ctx)
		case *ast.IfStmt:
			collectAcceptedPollingSleeps(current.Body, ctx)
			if elseBlock, ok := current.Else.(*ast.BlockStmt); ok {
				collectAcceptedPollingSleeps(elseBlock, ctx)
			}
		case *ast.SwitchStmt:
			collectAcceptedPollingSleeps(current.Body, ctx)
		case *ast.TypeSwitchStmt:
			collectAcceptedPollingSleeps(current.Body, ctx)
		case *ast.SelectStmt:
			collectAcceptedPollingSleeps(current.Body, ctx)
		}
	}
}

// isAcceptedPollingLoop applies the bounded-polling contract to one for loop.
func isAcceptedPollingLoop(loop *ast.ForStmt, following []ast.Stmt, ctx pollingLoopContext) bool {
	return loopHasFiniteBound(loop, ctx.timePackages) &&
		loopHasObservableExitCondition(loop) &&
		statementsHaveFailureCall(following, ctx.testingPackages, ctx.assertionPackages, ctx.receivers)
}

// loopHasFiniteBound recognises deadline and explicit attempt-count loop conditions.
func loopHasFiniteBound(loop *ast.ForStmt, timePackages map[string]bool) bool {
	if loop == nil || loop.Cond == nil {
		return false
	}
	return containsTimeDeadlineCheck(loop.Cond, timePackages) || loopHasAttemptBound(loop)
}

// containsTimeDeadlineCheck reports whether expr checks time.Now against a deadline.
func containsTimeDeadlineCheck(expr ast.Expr, timePackages map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if selector.Sel.Name != "Before" && selector.Sel.Name != "After" {
			return true
		}
		if nested, ok := selector.X.(*ast.CallExpr); ok && selectorCallMatches(nested, timePackages, "Now") {
			found = true
			return false
		}
		return true
	})
	return found
}

// loopHasAttemptBound reports whether loop has an obvious counter initializer,
// comparison, and increment/decrement post statement.
func loopHasAttemptBound(loop *ast.ForStmt) bool {
	counter := loopCounterName(loop.Init)
	if counter == "" || !conditionBoundsCounter(loop.Cond, counter) {
		return false
	}
	return postUpdatesCounter(loop.Post, counter)
}

// loopCounterName extracts the loop-local counter name from common for-loop initializers.
func loopCounterName(stmt ast.Stmt) string {
	switch current := stmt.(type) {
	case *ast.AssignStmt:
		if len(current.Lhs) != 1 {
			return ""
		}
		if ident, ok := current.Lhs[0].(*ast.Ident); ok && ident.Name != "_" {
			return ident.Name
		}
	case *ast.DeclStmt:
		decl, ok := current.Decl.(*ast.GenDecl)
		if !ok || len(decl.Specs) != 1 {
			return ""
		}
		spec, ok := decl.Specs[0].(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 {
			return ""
		}
		if name := spec.Names[0]; name.Name != "_" {
			return name.Name
		}
	}
	return ""
}

// conditionBoundsCounter reports whether expr compares the loop counter.
func conditionBoundsCounter(expr ast.Expr, counter string) bool {
	binary, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	switch binary.Op {
	case token.LSS, token.LEQ, token.GTR, token.GEQ:
	default:
		return false
	}
	return exprIsIdent(binary.X, counter) || exprIsIdent(binary.Y, counter)
}

// postUpdatesCounter reports whether stmt visibly advances the loop counter.
func postUpdatesCounter(stmt ast.Stmt, counter string) bool {
	switch current := stmt.(type) {
	case *ast.IncDecStmt:
		return exprIsIdent(current.X, counter)
	case *ast.AssignStmt:
		for _, lhs := range current.Lhs {
			if exprIsIdent(lhs, counter) {
				return true
			}
		}
	}
	return false
}

// exprIsIdent reports whether expr is the named identifier.
func exprIsIdent(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

// loopHasObservableExitCondition requires an if condition inside the loop that
// checks state and exits the polling loop on success.
func loopHasObservableExitCondition(loop *ast.ForStmt) bool {
	if loop == nil || loop.Body == nil {
		return false
	}
	found := false
	ast.Inspect(loop.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		stmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		if conditionObservesState(stmt.Cond) && blockExitsPolling(stmt.Body) {
			found = true
			return false
		}
		return true
	})
	return found
}

// conditionObservesState rejects pure time checks and accepts parser-visible
// reads or calls that inspect the system under test.
func conditionObservesState(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		if found {
			return false
		}
		switch current := node.(type) {
		case *ast.CallExpr:
			if callFunctionName(current) != "Now" {
				found = true
				return false
			}
		case *ast.SelectorExpr, *ast.IndexExpr:
			found = true
			return false
		}
		return true
	})
	return found
}

// blockExitsPolling reports whether a success branch exits the loop or test.
func blockExitsPolling(block *ast.BlockStmt) bool {
	if block == nil {
		return false
	}
	for _, stmt := range block.List {
		switch stmt.(type) {
		case *ast.ReturnStmt, *ast.BranchStmt:
			return true
		}
	}
	return false
}

// statementsHaveFailureCall reports whether any following statement can fail
// the test after the polling loop exhausts its finite bound.
func statementsHaveFailureCall(statements []ast.Stmt, testingPackages, assertionPackages, receivers map[string]bool) bool {
	if len(statements) == 0 {
		return false
	}
	return blockHasFailureCall(&ast.BlockStmt{List: statements}, testingPackages, assertionPackages, receivers)
}

// recordSleepCalls stores every time.Sleep call inside block.
func recordSleepCalls(block *ast.BlockStmt, timePackages map[string]bool, accepted map[token.Pos]bool) {
	ast.Inspect(block, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && selectorCallMatches(call, timePackages, "Sleep") {
			accepted[call.Pos()] = true
		}
		return true
	})
}
