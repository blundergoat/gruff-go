// Package rule tests which empty blocks dead-code.empty-block still reports.
//
// The constructs removed from the rule on 2026-09-07 are Go idioms whose emptiness is the
// behaviour. Each is paired here with a control that must keep firing, because a rule that
// stops reporting unfinished branches has been narrowed too far.
package rule

import "testing"

// emptyBlockLines reports the line numbers dead-code.empty-block flags in one file.
//
// The source text is parsed as pkg/sample.go for EmptyBlockRule with an empty Context; source that fails to parse stops the test.
// The slice holds one line number per finding in the order the rule emits them, and is empty but non-nil when no block is flagged.
func emptyBlockLines(t *testing.T, source string) []int {
	t.Helper()
	unit := parseOne(t, "pkg/sample.go", source)
	lines := []int{}
	for _, item := range (EmptyBlockRule{}).AnalyzeUnit(unit, Context{}) {
		lines = append(lines, item.Location.Line)
	}
	return lines
}

// requireEmptyBlockCount fails unless the rule reported exactly n blocks.
//
// The source text is a whole Go file checked through emptyBlockLines, so source that fails to parse stops the test before any count is compared.
// On a count mismatch the test stops via t.Fatalf, listing the reported lines.
func requireEmptyBlockCount(t *testing.T, source string, n int) {
	t.Helper()
	if got := emptyBlockLines(t, source); len(got) != n {
		t.Fatalf("empty-block reported %d blocks at %v, want %d", len(got), got, n)
	}
}

// A loop whose header does the work is deliberate, and its body is empty on purpose.
// A failure means a for loop that works in its condition or post statement is flagged as an empty block.
func TestEmptyBlockIgnoresLoopsThatWorkInTheirHeader(t *testing.T) {
	requireEmptyBlockCount(t, `package pkg

func advance(i int) bool { return i < 3 }

func headerWork() {
	for i := 0; advance(i); i++ {
	}
}
`, 0)
}

// Draining or waiting on a channel is what an empty range body is for.
// A failure means ranging over a channel with an empty body is flagged as an empty block.
func TestEmptyBlockIgnoresRangeDrain(t *testing.T) {
	requireEmptyBlockCount(t, `package pkg

func drain(ch chan int) {
	for range ch {
	}
}
`, 0)
}

// `select {}` parks the goroutine forever; it is a blocking statement, not a gap.
// A failure means an empty select, written to block forever, is flagged as an empty block.
func TestEmptyBlockIgnoresBlockingSelect(t *testing.T) {
	requireEmptyBlockCount(t, `package pkg

func park() {
	select {}
}
`, 0)
}

// A comment between the braces is the author saying why the block is empty.
// A failure means an empty block that explains itself in a comment is still flagged.
func TestEmptyBlockIgnoresACommentedBody(t *testing.T) {
	requireEmptyBlockCount(t, `package pkg

func documented(err error) {
	if err != nil {
		// Handled by the caller's recovery boundary.
	}
}
`, 0)
}

// The controls: an empty if body, a bare infinite loop and an empty switch are each still reported.
//
// The empty if is the confirmed true positive the precision corpus pins for this rule.
// A failure means the rule was narrowed far enough to miss unfinished branches.
func TestEmptyBlockStillReportsUnfinishedBranches(t *testing.T) {
	requireEmptyBlockCount(t, `package pkg

func unfinished(x bool) {
	if x {
	}
}
`, 1)

	requireEmptyBlockCount(t, `package pkg

func spin() {
	for {
	}
}
`, 1)

	requireEmptyBlockCount(t, `package pkg

func unfinishedSwitch(x int) {
	switch x {
	}
}
`, 1)
}
