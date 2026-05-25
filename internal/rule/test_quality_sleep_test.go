// Package rule tests the parser-only test-quality.sleep-in-test rule.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestSleepInTestRuleFlagsDirectCall asserts the basic time.Sleep call site is reported.
func TestSleepInTestRuleFlagsDirectCall(t *testing.T) {
	unit := parseOne(t, "sleep_test.go", `package sample

import (
	"testing"
	"time"
)

func TestSleepy(t *testing.T) {
	time.Sleep(100 * time.Millisecond)
}
`)
	findings := SleepInTestRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one sleep finding", findings)
	}
	if findings[0].Symbol != "TestSleepy" {
		t.Errorf("symbol = %q, want %q", findings[0].Symbol, "TestSleepy")
	}
}

// TestSleepInTestRuleFlagsNestedSubtest verifies subtests and goroutines inside tests are reached.
func TestSleepInTestRuleFlagsNestedSubtest(t *testing.T) {
	unit := parseOne(t, "sleep_test.go", `package sample

import (
	"testing"
	"time"
)

func TestSubtests(t *testing.T) {
	t.Run("inner", func(t *testing.T) {
		go func() { time.Sleep(50 * time.Millisecond) }()
	})
}
`)
	findings := SleepInTestRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one nested-sleep finding", findings)
	}
}

// TestSleepInTestRuleFlagsHelperCall confirms private helpers in _test.go are in scope.
func TestSleepInTestRuleFlagsHelperCall(t *testing.T) {
	unit := parseOne(t, "sleep_test.go", `package sample

import "time"

func waitOnce() {
	time.Sleep(time.Second)
}
`)
	findings := SleepInTestRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want helper-sleep finding", findings)
	}
}

// TestSleepInTestRuleRespectsImportAlias verifies aliased time imports are still detected.
func TestSleepInTestRuleRespectsImportAlias(t *testing.T) {
	unit := parseOne(t, "alias_test.go", `package sample

import t2 "time"

func waitAlias() {
	t2.Sleep(t2.Second)
}
`)
	findings := SleepInTestRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want aliased-sleep finding", findings)
	}
}

// TestSleepInTestRuleSkipsProductionFiles confirms the rule is scoped to _test.go.
func TestSleepInTestRuleSkipsProductionFiles(t *testing.T) {
	unit := parseOne(t, "service.go", `package sample

import "time"

func Wait() {
	time.Sleep(time.Second)
}
`)
	findings := SleepInTestRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for production code", findings)
	}
}

// TestSleepInTestRuleIgnoresShadowedReceiver verifies non-time receivers named "time" do not fire.
func TestSleepInTestRuleIgnoresShadowedReceiver(t *testing.T) {
	unit := parseOne(t, "shadow_test.go", `package sample

import "testing"

type fakeTime struct{}

func (fakeTime) Sleep(any) {}

func TestShadow(t *testing.T) {
	time := fakeTime{}
	time.Sleep(nil)
}
`)
	findings := SleepInTestRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for shadowed time receiver", findings)
	}
}

// TestSleepInTestRuleIsDefaultEnabled asserts the rule ships enabled with parser capability.
func TestSleepInTestRuleIsDefaultEnabled(t *testing.T) {
	def := SleepInTestRule{}.Definition()
	if !def.DefaultEnabled {
		t.Error("test-quality.sleep-in-test must be default-enabled")
	}
	if def.Capability != CapabilityParser {
		t.Errorf("capability = %q, want parser", def.Capability)
	}
	if def.Severity != finding.SeverityAdvisory {
		t.Errorf("severity = %q, want advisory", def.Severity)
	}
}
