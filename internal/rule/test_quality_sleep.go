// Package rule defines gruff-go's rule registry and analysers.
//
// This file implements test-quality.sleep-in-test, a parser-only check for time.Sleep calls in Go test files.
// Sleeps in tests are the dominant source of flakiness because real timing is non-deterministic across machines and CI.
package rule

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// SleepInTestRule flags time.Sleep call sites inside *_test.go files, reported as test-quality.sleep-in-test findings.
//
// The rule is scoped to test files because production code legitimately sleeps for rate limiting or retry backoff.
// Inside tests the same call is almost always a flake or a missing synchronisation primitive; skippedSleepPositions lists the exceptions.
type SleepInTestRule struct{}

// Definition declares the test-quality.sleep-in-test rule that gruff-go analyse reports and lists among the run's rules.
//
// Its tags mark it as a flake check, and its remediation points maintainers at channel, WaitGroup, polling or fake-clock alternatives.
// It returns the same advisory, high-confidence, parser-capability, default-enabled Definition on every call.
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

// AnalyzeUnit emits findings for time.Sleep call sites in test files, apart from the sleeps skippedSleepPositions exempts.
//
// It walks each declared function's body, closures included, so Symbol names the enclosing test or helper, faster to triage than file:line alone.
//
// unit is the parsed file, analysed only when it is a Go test file with an AST and a file set, and ctx decides whether a generated unit is skipped.
// It returns one finding per reported time.Sleep call, and an empty slice when none is reported.
// It returns nil when unit is skipped or imports time only through a dot or blank import, or not at all.
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
			// Exempted sleeps, such as a bounded poll's backoff or a sleep inside a synctest bubble, raise no finding.
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

// skippedSleepPositions returns the sleeps in fn this rule does not report, so the user sees no finding for them.
//
// It skips syntax read as polling backoff, synctest bubble sleeps, self-timed sleeps or receiver-field delays; the match is syntactic.
//
// packages holds the time, testing, assertion and synctest import names that calls are resolved through.
// The result maps each skipped call position to true and is empty, never nil, when fn has no skipped sleep.
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

// recordBubbleSleeps marks every sleep inside a function literal passed to synctest.Test or synctest.Run.
//
// Inside that bubble time.Sleep advances a fake clock, so the test is not waiting on real time and the user sees no finding.
// body is the function body searched, packages supplies the synctest and time import names, and skipped receives each bubble sleep position.
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
// timePackages holds the time import names a call must resolve through, and skipped receives each matching call position as true.
func markSleeps(node ast.Node, timePackages map[string]bool, skipped map[token.Pos]bool) {
	ast.Inspect(node, func(child ast.Node) bool {
		if call, ok := child.(*ast.CallExpr); ok && selectorCallMatches(call, timePackages, "Sleep") {
			skipped[call.Pos()] = true
		}
		return true
	})
}

// recordTimedSleeps marks a sleep the test times itself, so a test measuring elapsed time around a sleep raises no finding for it.
//
// The sleep must be its own statement after a time.Now() assignment and before a later statement in the same block calling time.Since on that name.
// body is searched block by block, timePackages holds the time import names, and skipped receives each timed sleep's call position.
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

// timeNowAssignment returns the name a start := time.Now() statement assigns, so recordTimedSleeps can match a later time.Since.
//
// stmt must be a single-target assignment whose right side is a time.Now call through one of timePackages, the time import names.
// Any other statement gives an empty name and false.
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

// sleepStatementCall returns the time.Sleep call a statement makes on its own, the only sleep shape recordTimedSleeps skips.
//
// stmt counts only as an expression statement calling time.Sleep through one of timePackages, the time import names.
// Otherwise the bool is false, and the call is nil unless stmt is a call statement to another function.
func sleepStatementCall(stmt ast.Stmt, timePackages map[string]bool) (*ast.CallExpr, bool) {
	expression, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return nil, false
	}
	call, isCall := expression.X.(*ast.CallExpr)
	return call, isCall && selectorCallMatches(call, timePackages, "Sleep")
}

// laterStatementsReadElapsed reports whether a statement after the sleep calls time.Since with one of the recorded start times.
//
// statements follow the sleep, started holds names assigned from time.Now, and timePackages holds the time import names Since must resolve through.
// A call nested anywhere in those statements counts, including inside a closure.
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

// isTestDoubleDelay recognises a sleep whose single argument is a field of the method's receiver, such as time.Sleep(m.delay).
//
// A duration computed in the Sleep argument, such as random jitter, does not match; a value already stored in a receiver field does.
//
// call is a time.Sleep call and receiver is the method's receiver name from receiverIdentName.
// It reports true only when call's single argument selects directly from receiver, and false whenever receiver is empty.
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

// receiverIdentName returns the named receiver of a method whose name does not start with Test, for isTestDoubleDelay's receiver-field exemption.
//
// fn is the declaration inspected; a plain function, an unnamed receiver, or a method whose name starts with Test gives the empty string.
// A suite's Test method therefore gets no receiver-field exemption for its sleeps.
func receiverIdentName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 || strings.HasPrefix(fn.Name.Name, "Test") {
		return ""
	}
	return fn.Recv.List[0].Names[0].Name
}

// acceptedPollingSleepPositions returns the backoff sleeps of polling loops whose syntax reads as bounded, observed and failing on timeout.
//
// The match is syntactic: a recognised bound, a state-observing if that returns or breaks, and failure or timeout-return syntax after the loop.
// A nested loop can qualify on its own under a loop that does not; inside an accepted loop, nested loops and closures get no polling exemption.
// fn is the function to search and packages its import names; the map is empty, never nil, when fn is nil, has no body, or has no accepted loop.
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

// collectAcceptedPollingSleeps records the backoff sleeps of accepted polling loops under block; other sleeps stay eligible for other exemptions.
//
// It descends into if bodies, plain else blocks and non-qualifying loops; case bodies, else-if chains, bare blocks and closures are skipped.
// block is the statement list searched, nil for none, and ctx carries the import names, testing handles and result types the checks use.
// ctx's accepted map receives each backoff sleep position.
func collectAcceptedPollingSleeps(block *ast.BlockStmt, ctx pollingLoopContext) {
	if block == nil {
		return
	}
	for index, stmt := range block.List {
		// Labeling a polling loop does not stop its backoff sleeps from qualifying for the polling exemption.
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
		// Polling loops inside case or comm clauses get no exemption from this walk; the other sleep exemptions still apply.
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
//
// loop is the for statement, following the statements after it in the same block, and ctx the import names, handles and results the checks read.
// It reports true when loop passes loopHasFiniteBound, its body passes loopHasObservableExitCondition and following passes timeoutIsReported.
// These are syntax matches: a deadline call anywhere in the condition counts, and the matched return or break may sit in a nested loop or closure.
func isAcceptedPollingLoop(loop *ast.ForStmt, following []ast.Stmt, ctx pollingLoopContext) bool {
	return loopHasFiniteBound(loop, ctx.timePackages) &&
		loopHasObservableExitCondition(loop.Body) &&
		timeoutIsReported(following, ctx)
}

// isAcceptedPollingRange applies the same contract to for range N over an integer literal, whose literal count is the finite bound.
//
// loop is the range statement, following the statements after it in the same block, and ctx the evidence the timeout check reads.
// It reports true when loop ranges over an integer literal, its body passes loopHasObservableExitCondition and following passes timeoutIsReported.
// These are syntax matches: the matched return or break may sit in a nested loop or closure, so it need not leave loop.
func isAcceptedPollingRange(loop *ast.RangeStmt, following []ast.Stmt, ctx pollingLoopContext) bool {
	count, ok := loop.X.(*ast.BasicLit)
	return ok && count.Kind == token.INT && loopHasObservableExitCondition(loop.Body) && timeoutIsReported(following, ctx)
}

// timeoutIsReported accepts failure syntax after the loop, or a return that hands a timeout back to a polling helper's caller.
//
// following is the statements after the loop, and ctx supplies the testing and assertion import names, the testing handles and the result list.
// It reports true when statementsHaveFailureCall finds a recognised failure call in following, a syntax match that need not run,
// or when following starts with a return of false from a lone bool result or of any final error result but the bare nil identifier; else false.
func timeoutIsReported(following []ast.Stmt, ctx pollingLoopContext) bool {
	return statementsHaveFailureCall(following, ctx.testingPackages, ctx.assertionPackages, ctx.receivers) ||
		returnsTimeoutToCaller(following, ctx.results)
}

// returnsTimeoutToCaller accepts a polling helper whose first statement after the loop is a return shaped like a timeout.
//
// It reports true for a return of false from a lone bool result, or a final error expression other than the bare predeclared nil identifier.
// The value is not evaluated, so a variable holding nil or an unrelated error also counts; any other first statement reports false.
// following is the statements after the loop, only the first of them read, and results is the enclosing function's result list, nil for none.
func returnsTimeoutToCaller(following []ast.Stmt, results *ast.FieldList) bool {
	if len(following) == 0 || results == nil {
		return false
	}
	ret, ok := following[0].(*ast.ReturnStmt)
	resultTypes := []ast.Expr{}
	for _, field := range results.List {
		// Grouped result names count separately, so a helper returning ok, done bool cannot qualify as a lone-bool timeout helper.
		for range max(len(field.Names), 1) {
			resultTypes = append(resultTypes, field.Type)
		}
	}
	if !ok || len(resultTypes) == 0 || len(ret.Results) != len(resultTypes) {
		return false
	}
	last := len(resultTypes) - 1
	if isErrorType(resultTypes[last]) {
		return !isNilIdentifier(ret.Results[last])
	}
	resultType, isIdent := resultTypes[0].(*ast.Ident)
	value, isValue := ret.Results[0].(*ast.Ident)
	return len(resultTypes) == 1 && isIdent && resultType.Name == "bool" && isValue && value.Name == "false"
}

// loopHasFiniteBound recognises deadline and explicit attempt-count loop conditions, the bound a polling loop needs.
//
// loop is the for statement and timePackages the time import names a deadline check must use.
// It reports true for a recognised deadline call shape in the condition, or for the counter shape loopHasAttemptBound matches.
// A nil loop or condition reports false, and the match is syntactic, so a deadline check || true still counts.
func loopHasFiniteBound(loop *ast.ForStmt, timePackages map[string]bool) bool {
	if loop == nil || loop.Cond == nil {
		return false
	}
	return containsTimeDeadlineCheck(loop.Cond, timePackages) || loopHasAttemptBound(loop)
}

// containsTimeDeadlineCheck reports whether expr holds a time call shape read as a deadline check, wherever it sits in expr.
// timePackages holds the time import names; time.Since or time.Until anywhere in expr counts, as does Before, After or Sub on a time.Now call.
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

// loopHasAttemptBound reports whether loop has an obvious counter initializer, comparison, and increment or decrement post statement.
// A loop such as for i := 0; i < 5; i++ qualifies; a missing init, condition or post reports false.
func loopHasAttemptBound(loop *ast.ForStmt) bool {
	counter := loopCounterName(loop.Init)
	if counter == "" || !conditionBoundsCounter(loop.Cond, counter) {
		return false
	}
	return postUpdatesCounter(loop.Post, counter)
}

// loopCounterName extracts the counter name from common for-loop initializers, including an assignment to an existing variable.
//
// stmt is the loop's init statement; a single-target assignment or a one-name var declaration gives that name.
// It returns the empty string for a nil stmt, a blank name, or any other init shape.
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
// Only a top-level <, <=, > or >= with counter on either side counts, so i != n or i < n && ok reports false.
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

// postUpdatesCounter reports whether stmt visibly advances the loop counter, so a no-op post like i = i or i += 0 is not read as a bound.
// An i++ or i-- counts, and an assignment counts when assignmentAdvancesCounter accepts the value it assigns to counter.
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

// assignmentAdvancesCounter reports whether an assignment to the loop counter makes visible progress.
//
// A compound += or -= by a non-zero amount counts, as does a plain = adding or subtracting a non-zero operand and counter, in either order.
// Non-zero here means any operand except the integer literal 0.
//
// tok is the assignment operator and rhs the value assigned to counter, the loop counter's name; any operator but +=, -= or = reports false.
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
// name is the identifier text to match; any expr that is not an identifier reports false.
func exprIsIdent(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

// loopHasObservableExitCondition accepts a loop body holding a state-observing if whose block directly contains a return or break.
//
// The if may sit anywhere under body, inside nested loops and closures too, and the return or break need not leave the polling loop.
// It reports true when such an if passes conditionObservesState or initObservesState, and false for a nil body or when none is found.
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

// initObservesState reports whether an if statement's init, such as _, err := http.Get(url), assigns a value conditionObservesState accepts.
//
// init is the if's init statement; anything but an assignment, a nil init included, reports false.
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

// conditionObservesState recognises calls, selectors and indexes outside calls named Now, Since and Until in an if condition.
//
// It does not establish that they inspect the system under test: time.Now().After(deadline) counts, because its outer call is named After.
// A bare identifier such as ready, or a comparison of plain locals, does not count here; the if's init statement is checked separately.
//
// It reports true when expr holds such a call, selector or index, else false; a call named Now, Since or Until is skipped with its arguments.
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
				// A call named Now, Since or Until reads as a clock read, so neither it nor its time.X selector counts as observing state.
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

// blockExitsPolling reports whether block directly contains a return or break, without resolving its enclosing function or target loop.
//
// A labeled break counts too, and a return that ends only a closure or a break that leaves only a nested loop still counts here.
// continue, goto and fallthrough do not satisfy this check, so a continue-only branch cannot qualify a loop by itself.
//
// block is the success branch's body; only its top-level statements are read, and a nil block reports false.
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

// statementsHaveFailureCall reports whether the statements after a polling loop hold failure syntax blockHasFailureCall recognises.
//
// The match is syntactic and does not prove the call runs once the loop exhausts its bound.
//
// statements are the ones after the loop, and receivers holds the testing handle names a failure call can go through.
// testingPackages and assertionPackages hold the testing and assertion import names; an empty statements list reports false.
func statementsHaveFailureCall(statements []ast.Stmt, testingPackages, assertionPackages, receivers map[string]bool) bool {
	if len(statements) == 0 {
		return false
	}
	return blockHasFailureCall(&ast.BlockStmt{List: statements}, testingPackages, assertionPackages, receivers)
}

// recordSleepCalls accepts only the polling loop's own backoff sleeps for the polling exemption.
//
// It does not descend into nested function literals, such as goroutines, subtests or helpers, or into nested loops.
// Their sleeps get no polling exemption here, though the bubble, timed-sleep or receiver-field checks can still skip them.
//
// block is the accepted loop's body, timePackages holds the time import names, and accepted receives each backoff sleep's call position as true.
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
