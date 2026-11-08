// Package rule tests parser-only dead-code rules.
//
// These tests feed inline Go fixtures to UnreachableCodeRule and count its findings.
// A failure means gruff-go analyse would report too many or too few unreachable statements.
package rule

import "testing"

// TestUnreachableCodeRule covers same-block unreachable statements and label recovery.
// It expects two findings in total across the return, panic and label fixtures.
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
	// One finding follows the return and one the panic; the target label stops reporting, so the later goto adds none.
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want two unreachable statements", findings)
	}
}

// TestUnreachableCodeRuleBranchTermination covers branch forms where every syntactic path exits.
// It expects two findings in total across the if/else and switch fixtures.
func TestUnreachableCodeRuleBranchTermination(t *testing.T) {
	unit := parseOne(t, "dead.go", `// Package sample is a test package.
package sample

func IfElseTerminal(flag bool) {
	if flag {
		return
	} else {
		panic("stop")
	}
	println("never")
}

func SwitchTerminal(value int) {
	switch value {
	case 1:
		return
	default:
		panic("stop")
	}
	println("never")
}
`)
	findings := UnreachableCodeRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want two branch-termination findings", findings)
	}
}

// TestUnreachableCodeRuleKeepsReachableBranchShapes confirms partial branches and fallthrough stay out of scope.
// A failure means users would see unreachable-code findings on statements that still run.
func TestUnreachableCodeRuleKeepsReachableBranchShapes(t *testing.T) {
	unit := parseOne(t, "reachable.go", `// Package sample is a test package.
package sample

func IfBranchCanContinue(flag bool) {
	if flag {
		return
	}
	println("reachable")
}

func SwitchCanContinue(value int) {
	switch value {
	case 1:
		fallthrough
	default:
		println("reachable")
	}
	println("also reachable")
}
`)
	findings := UnreachableCodeRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for reachable branch shapes", findings)
	}
}
