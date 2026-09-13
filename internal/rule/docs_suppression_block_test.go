// Package rule tests which comment blocks count as a suppression's rationale.
//
// The shape here is cobra's command.go: two ordinary sentences naming the analyser, the false
// positive and the upstream issue, with the directive trailing the statement below. Demanding a
// `reason:` keyword rejected that, which is the confirmed false positive this rule carries.
package rule

import "testing"

// suppressionLines reports the lines docs.suppression-without-rationale flags in one Go file.
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
func requireSuppressionCount(t *testing.T, source string, n int) {
	t.Helper()
	if got := suppressionLines(t, source); len(got) != n {
		t.Fatalf("reported %d directives at lines %v, want %d", len(got), got, n)
	}
}

// The cobra shape: a prose block above, the directive trailing the statement below.
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

// The control the task names: a bare directive with nothing explaining it still fires.
func TestSuppressionStillReportsABareDirective(t *testing.T) {
	requireSuppressionCount(t, `package pkg

func widget() int {
	//nolint:gocyclo
	return 1
}
`, 1)
}

// A declaration's doc group describes the declaration, not the suppression below it.
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
func TestSuppressionRejectsAStackOfDirectives(t *testing.T) {
	requireSuppressionCount(t, `package pkg

func widget() int {
	//nolint:gocyclo
	//nolint:funlen
	return 1
}
`, 2)
}

// A comment trailing code explains that code, not the directive on the next line.
// Measured in prometheus: `var pathBuf [4]Node // To reduce allocations during recursion.`
// sits directly above a //nolint:errcheck and says nothing about it.
func TestSuppressionRejectsACommentTrailingCode(t *testing.T) {
	requireSuppressionCount(t, `package pkg

func inspect() {
	var pathBuf [4]int        // To reduce allocations during recursion.
	walk(pathBuf[:0]) //nolint:errcheck
}

func walk(p []int) {}
`, 1)
}
