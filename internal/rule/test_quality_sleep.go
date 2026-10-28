// Package rule defines gruff-go's rule registry and analysers.
// This file implements a parser-only test-quality check for time.Sleep
// usage in Go test files. Sleeps in tests are the dominant source of
// flakiness because real timing is non-deterministic across machines and CI.
package rule

import (
	"go/ast"
	"go/token"
	"strings"

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
	packages := sleepPackages{
		time:      timePackages,
		testing:   testingPackageNames(unit.AST),
		assertion: assertionPackageNames(unit.AST),
		synctest:  packageImportNames(unit.AST, "testing/synctest", "synctest"),
	}
	findings := []finding.Finding{}
	for _, decl := range unit.AST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		symbol := functionName(fn)
		skipped := skippedSleepPositions(fn, packages)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !selectorCallMatches(call, timePackages, "Sleep") {
				return true
			}
			if skipped[call.Pos()] {
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

// sleepPackages holds the import aliases the sleep checks resolve calls through.
type sleepPackages struct {
	time      map[string]bool
	testing   map[string]bool
	assertion map[string]bool
	synctest  map[string]bool
}

// skippedSleepPositions returns the sleeps in fn this rule does not report: a
// bounded poll's backoff, a sleep inside a synctest bubble, a sleep the test
// times itself, and a test double's configured delay. Precision-floor M02
// measured each as a deliberate sleep rather than a wait standing in for
// synchronisation.
func skippedSleepPositions(fn *ast.FuncDecl, packages sleepPackages) map[token.Pos]bool {
	skipped := acceptedPollingSleepPositions(fn, packages)
	recordBubbleSleeps(fn.Body, packages, skipped)
	recordTimedSleeps(fn.Body, packages.time, skipped)
	receiver := receiverIdentName(fn)
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && selectorCallMatches(call, packages.time, "Sleep") && isTestDoubleDelay(call, receiver) {
			skipped[call.Pos()] = true
		}
		return true
	})
	return skipped
}

// recordBubbleSleeps marks every sleep inside a function passed to synctest.Test
// or synctest.Run, where time.Sleep advances the bubble's fake clock.
func recordBubbleSleeps(body *ast.BlockStmt, packages sleepPackages, skipped map[token.Pos]bool) {
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !selectorCallMatches(call, packages.synctest, "Test") && !selectorCallMatches(call, packages.synctest, "Run") {
			return true
		}
		for _, argument := range call.Args {
			if bubble, isFunc := argument.(*ast.FuncLit); isFunc {
				markSleeps(bubble.Body, packages.time, skipped)
			}
		}
		return true
	})
}

// markSleeps marks every time.Sleep call under node, nested closures included.
func markSleeps(node ast.Node, timePackages map[string]bool, skipped map[token.Pos]bool) {
	ast.Inspect(node, func(child ast.Node) bool {
		if call, ok := child.(*ast.CallExpr); ok && selectorCallMatches(call, timePackages, "Sleep") {
			skipped[call.Pos()] = true
		}
		return true
	})
}

// recordTimedSleeps marks a sleep statement that sits between `start :=
// time.Now()` and a later time.Since(start) in the same block, because the
// elapsed time around the sleep is what the test measures.
func recordTimedSleeps(body *ast.BlockStmt, timePackages map[string]bool, skipped map[token.Pos]bool) {
	ast.Inspect(body, func(node ast.Node) bool {
		block, ok := node.(*ast.BlockStmt)
		if !ok {
			return true
		}
		started := map[string]bool{}
		for index, stmt := range block.List {
			if name, isStart := timeNowAssignment(stmt, timePackages); isStart {
				started[name] = true
				continue
			}
			call, isSleep := sleepStatementCall(stmt, timePackages)
			if isSleep && laterStatementsReadElapsed(block.List[index+1:], started, timePackages) {
				skipped[call.Pos()] = true
			}
		}
		return true
	})
}

// timeNowAssignment returns the name a `name := time.Now()` statement assigns.
func timeNowAssignment(stmt ast.Stmt, timePackages map[string]bool) (string, bool) {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return "", false
	}
	name, isIdent := assign.Lhs[0].(*ast.Ident)
	call, isCall := assign.Rhs[0].(*ast.CallExpr)
	if !isIdent || !isCall || !selectorCallMatches(call, timePackages, "Now") {
		return "", false
	}
	return name.Name, true
}

// sleepStatementCall returns the time.Sleep call a statement makes on its own.
func sleepStatementCall(stmt ast.Stmt, timePackages map[string]bool) (*ast.CallExpr, bool) {
	expression, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return nil, false
	}
	call, isCall := expression.X.(*ast.CallExpr)
	return call, isCall && selectorCallMatches(call, timePackages, "Sleep")
}

// laterStatementsReadElapsed reports whether a statement calls time.Since with
// one of the recorded start times.
func laterStatementsReadElapsed(statements []ast.Stmt, started map[string]bool, timePackages map[string]bool) bool {
	found := false
	for _, stmt := range statements {
		ast.Inspect(stmt, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok && selectorCallMatches(call, timePackages, "Since") && len(call.Args) == 1 {
				if start, isIdent := call.Args[0].(*ast.Ident); isIdent && started[start.Name] {
					found = true
				}
			}
			return !found
		})
	}
	return found
}

// isTestDoubleDelay recognises a sleep whose duration is the test double's own
// configured delay field, such as time.Sleep(m.delay). Random jitter stays
// reported: M02's labels count a randomly timed test as worth making deterministic.
func isTestDoubleDelay(call *ast.CallExpr, receiver string) bool {
	if len(call.Args) != 1 || receiver == "" {
		return false
	}
	selector, ok := call.Args[0].(*ast.SelectorExpr)
	if !ok {
		return false
	}
	root, isIdent := selector.X.(*ast.Ident)
	return isIdent && root.Name == receiver
}

// receiverIdentName returns a test double method's named receiver, or "" for a
// function or a suite's Test method, whose sleeps are the test waiting.
func receiverIdentName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 || strings.HasPrefix(fn.Name.Name, "Test") {
		return ""
	}
	return fn.Recv.List[0].Names[0].Name
}

// acceptedPollingSleepPositions returns time.Sleep call positions that sit
// inside a bounded polling loop with observable work and a failure after timeout.
func acceptedPollingSleepPositions(fn *ast.FuncDecl, packages sleepPackages) map[token.Pos]bool {
	accepted := map[token.Pos]bool{}
	if fn == nil || fn.Body == nil {
		return accepted
	}
	ctx := pollingLoopContext{
		timePackages:      packages.time,
		testingPackages:   packages.testing,
		assertionPackages: packages.assertion,
		receivers:         testingHandlesForFunc(fn, packages.testing),
		results:           fn.Type.Results,
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
	results           *ast.FieldList
	accepted          map[token.Pos]bool
}

// collectAcceptedPollingSleeps walks block statements and records sleep calls
// under accepted polling loops without suppressing unrelated sleeps elsewhere.
func collectAcceptedPollingSleeps(block *ast.BlockStmt, ctx pollingLoopContext) {
	if block == nil {
		return
	}
	for index, stmt := range block.List {
		// A label such as `Loop:` wraps the loop the polling checks read.
		if labeled, ok := stmt.(*ast.LabeledStmt); ok {
			stmt = labeled.Stmt
		}
		switch current := stmt.(type) {
		case *ast.ForStmt:
			if isAcceptedPollingLoop(current, block.List[index+1:], ctx) {
				recordSleepCalls(current.Body, ctx.timePackages, ctx.accepted)
				continue
			}
			collectAcceptedPollingSleeps(current.Body, ctx)
		case *ast.RangeStmt:
			if isAcceptedPollingRange(current, block.List[index+1:], ctx) {
				recordSleepCalls(current.Body, ctx.timePackages, ctx.accepted)
				continue
			}
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
		loopHasObservableExitCondition(loop.Body) &&
		timeoutIsReported(following, ctx)
}

// isAcceptedPollingRange applies the same contract to `for range N` over an
// integer literal, whose literal count is the finite bound.
func isAcceptedPollingRange(loop *ast.RangeStmt, following []ast.Stmt, ctx pollingLoopContext) bool {
	count, ok := loop.X.(*ast.BasicLit)
	return ok && count.Kind == token.INT && loopHasObservableExitCondition(loop.Body) && timeoutIsReported(following, ctx)
}

// timeoutIsReported requires the code after the loop to fail the test, or to
// hand the timeout back to the caller of a polling helper.
func timeoutIsReported(following []ast.Stmt, ctx pollingLoopContext) bool {
	return statementsHaveFailureCall(following, ctx.testingPackages, ctx.assertionPackages, ctx.receivers) ||
		returnsTimeoutToCaller(following, ctx.results)
}

// returnsTimeoutToCaller accepts a helper whose statement after the loop returns
// false from a bool helper, or a non-nil final error, so the caller sees the timeout.
func returnsTimeoutToCaller(following []ast.Stmt, results *ast.FieldList) bool {
	if len(following) == 0 || results == nil {
		return false
	}
	ret, ok := following[0].(*ast.ReturnStmt)
	types := []ast.Expr{}
	for _, field := range results.List {
		for range max(len(field.Names), 1) {
			types = append(types, field.Type)
		}
	}
	if !ok || len(types) == 0 || len(ret.Results) != len(types) {
		return false
	}
	last := len(types) - 1
	if isErrorType(types[last]) {
		return !isNilIdentifier(ret.Results[last])
	}
	resultType, isIdent := types[0].(*ast.Ident)
	value, isValue := ret.Results[0].(*ast.Ident)
	return len(types) == 1 && isIdent && resultType.Name == "bool" && isValue && value.Name == "false"
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
		// An elapsed-time bound such as time.Since(start) < timeout is a deadline too.
		if selectorCallMatches(call, timePackages, "Since") || selectorCallMatches(call, timePackages, "Until") {
			found = true
			return false
		}
		if selector.Sel.Name != "Before" && selector.Sel.Name != "After" && selector.Sel.Name != "Sub" {
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

// postUpdatesCounter reports whether stmt visibly advances the loop counter, so
// a no-op post like `i = i` or `i += 0` is not mistaken for a finite bound.
func postUpdatesCounter(stmt ast.Stmt, counter string) bool {
	switch current := stmt.(type) {
	case *ast.IncDecStmt:
		return exprIsIdent(current.X, counter)
	case *ast.AssignStmt:
		for index, lhs := range current.Lhs {
			if !exprIsIdent(lhs, counter) || index >= len(current.Rhs) {
				continue
			}
			return assignmentAdvancesCounter(current.Tok, current.Rhs[index], counter)
		}
	}
	return false
}

// assignmentAdvancesCounter reports whether an assignment to the loop counter
// makes visible progress: a compound += / -= by a non-zero amount, or a plain
// = whose RHS is `counter ± x` with a non-zero other operand.
func assignmentAdvancesCounter(tok token.Token, rhs ast.Expr, counter string) bool {
	switch tok {
	case token.ADD_ASSIGN, token.SUB_ASSIGN:
		return !isZeroLiteral(rhs)
	case token.ASSIGN:
		binary, ok := rhs.(*ast.BinaryExpr)
		if !ok || (binary.Op != token.ADD && binary.Op != token.SUB) {
			return false
		}
		if exprIsIdent(binary.X, counter) {
			return !isZeroLiteral(binary.Y)
		}
		if exprIsIdent(binary.Y, counter) {
			return !isZeroLiteral(binary.X)
		}
	}
	return false
}

// isZeroLiteral reports whether expr is the integer literal 0.
func isZeroLiteral(expr ast.Expr) bool {
	literal, ok := expr.(*ast.BasicLit)
	return ok && literal.Kind == token.INT && literal.Value == "0"
}

// exprIsIdent reports whether expr is the named identifier.
func exprIsIdent(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

// loopHasObservableExitCondition requires an if condition inside the loop body
// that checks state, in its condition or its init statement, and exits the
// polling loop on success.
func loopHasObservableExitCondition(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		stmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		if (conditionObservesState(stmt.Cond) || initObservesState(stmt.Init)) && blockExitsPolling(stmt.Body) {
			found = true
			return false
		}
		return true
	})
	return found
}

// initObservesState reports whether an if statement's init, such as
// `_, err := http.Get(url)`, calls or reads the system under test.
func initObservesState(init ast.Stmt) bool {
	assign, ok := init.(*ast.AssignStmt)
	if !ok {
		return false
	}
	for _, value := range assign.Rhs {
		if conditionObservesState(value) {
			return true
		}
	}
	return false
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
			switch callFunctionName(current) {
			case "Now", "Since", "Until":
				// Pure wall-clock reads are not observation of the system under
				// test; do not descend (the time.X selector would otherwise count).
				return false
			}
			found = true
			return false
		case *ast.SelectorExpr, *ast.IndexExpr:
			found = true
			return false
		}
		return true
	})
	return found
}

// blockExitsPolling reports whether a success branch leaves the polling loop.
// A return ends the test and a break (including labeled break) leaves the loop;
// continue, goto, and fallthrough keep iterating, so accepting them as an exit
// would suppress the sleep finding for a test that is still spinning rather than
// synchronizing on the observed condition.
func blockExitsPolling(block *ast.BlockStmt) bool {
	if block == nil {
		return false
	}
	for _, stmt := range block.List {
		switch current := stmt.(type) {
		case *ast.ReturnStmt:
			return true
		case *ast.BranchStmt:
			if current.Tok == token.BREAK {
				return true
			}
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

// recordSleepCalls accepts only the polling loop's own backoff sleeps. It does
// not descend into nested function literals (goroutines, subtests, helpers) or
// nested loops, whose sleeps are not the bounded-polling backoff and must keep
// flagging even when the enclosing loop qualifies.
func recordSleepCalls(block *ast.BlockStmt, timePackages map[string]bool, accepted map[token.Pos]bool) {
	ast.Inspect(block, func(node ast.Node) bool {
		switch node.(type) {
		case *ast.FuncLit, *ast.ForStmt, *ast.RangeStmt:
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if ok && selectorCallMatches(call, timePackages, "Sleep") {
			accepted[call.Pos()] = true
		}
		return true
	})
}
