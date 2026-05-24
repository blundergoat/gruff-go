// Package rule tests parser-only dead-code rules.
package rule

import "testing"

// TestUnreachableCodeRule covers same-block unreachable statements and label recovery.
func TestUnreachableCodeRule(t *testing.T) {
	unit := parseOne(t, "dead.go", `// Package sample is a test package.
package sample

func ReturnThenWork() int {
	return 1
	println("never")
}

func PanicThenWork() {
	panic("stop")
	println("never")
}

func LabelTarget() {
	return
target:
	println("reachable by goto")
	goto target
}
`)
	findings := UnreachableCodeRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want two unreachable statements", findings)
	}
}
