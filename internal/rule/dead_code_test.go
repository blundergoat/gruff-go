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

// TestUnreachableCodeRuleBranchTermination covers branch forms where every syntactic path exits.
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
