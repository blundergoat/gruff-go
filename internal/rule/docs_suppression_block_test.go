// Package rule tests which comment blocks count as a suppression's rationale.
//
// The shape here is cobra's command.go: two ordinary sentences naming the analyser, the false
// positive and the upstream issue, with the directive trailing the statement below. Demanding a
// `reason:` keyword rejected that, which is the confirmed false positive this rule carries.
package rule

import "testing"

// suppressionLines reports the lines docs.suppression-without-rationale flags in one Go file.
//
// The source text is parsed as pkg/sample.go for SuppressionWithoutRationaleRule with an empty Context; source that fails to parse stops the test.
// The slice holds one line number per finding in the order the rule emits them, and is empty but non-nil when nothing is flagged.
func suppressionLines(t *testing.T, source string) []int {
	t.Helper()
	unit := parseOne(t, "pkg/sample.go", source)
	lines := []int{}
	for _, item := range (SuppressionWithoutRationaleRule{}).AnalyzeUnit(unit, Context{}) {
		lines = append(lines, item.Location.Line)
	}
	return lines
}

// requireSuppressionCount fails unless the rule reported exactly n directives.
//
// The source text is a whole Go file checked through suppressionLines, so source that fails to parse stops the test before any count is compared.
// On a count mismatch the test stops via t.Fatalf, listing the reported lines.
func requireSuppressionCount(t *testing.T, source string, n int) {
	t.Helper()
	if got := suppressionLines(t, source); len(got) != n {
		t.Fatalf("reported %d directives at lines %v, want %d", len(got), got, n)
	}
}

// The cobra shape: a prose block above, the directive trailing the statement below.
// A failure means a gosec suppression with a two-sentence rationale above it is reported again, the false positive this file pins.
func TestSuppressionAcceptsAProseBlockAboveTheDirective(t *testing.T) {
	requireSuppressionCount(t, `package pkg

func find(matches []string) string {
	if len(matches) == 1 {
		// Temporarily disable gosec G602, which produces a false positive.
		// See https://github.com/securego/gosec/issues/1005.
		return matches[0] // #nosec G602
	}
	return ""
}
`, 0)
}

// TestSuppressionStillReportsABareDirective expects one finding for the fixture's unexplained nolint directive.
func TestSuppressionStillReportsABareDirective(t *testing.T) {
	requireSuppressionCount(t, `package pkg

func widget() int {
	//nolint:gocyclo
	return 1
}
`, 1)
}

// Ordinary prose in a declaration's doc group describes the declaration, not the suppression below it.
// A failure means a function's doc comment would excuse the directive placed under it.
func TestSuppressionRejectsADeclarationDocGroup(t *testing.T) {
	requireSuppressionCount(t, `package pkg

// Execute runs the command and returns its exit status.
//nolint:gocyclo
func Execute() int {
	return 0
}
`, 1)
}

// A detached comment is about something else, so a blank line breaks the block.
// A failure means any comment above a blank line would excuse the directive below it.
func TestSuppressionRejectsADetachedComment(t *testing.T) {
	requireSuppressionCount(t, `package pkg

func widget() int {
	// This explains the loop below in some detail.

	//nolint:gocyclo
	return 1
}
`, 1)
}

// One suppression cannot excuse another, so a stack of directives is still reported.
// Both must be reported; a failure means one directive is taken as the other's rationale.
func TestSuppressionRejectsAStackOfDirectives(t *testing.T) {
	requireSuppressionCount(t, `package pkg

func widget() int {
	//nolint:gocyclo
	//nolint:funlen
	return 1
}
`, 2)
}

// Ordinary prose trailing code explains that code, not the directive on the next line, so the directive is still reported.
//
// Measured in prometheus: the pathBuf array declaration carries a trailing comment about reducing allocations during recursion.
// It sits directly above an errcheck suppression and says nothing about it.
func TestSuppressionRejectsACommentTrailingCode(t *testing.T) {
	requireSuppressionCount(t, `package pkg

func inspect() {
	var pathBuf [4]int        // To reduce allocations during recursion.
	walk(pathBuf[:0]) //nolint:errcheck
}

func walk(p []int) {}
`, 1)
}
