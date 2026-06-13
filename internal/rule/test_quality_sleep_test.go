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

// TestSleepInTestRuleAcceptsBoundedPolling accepts sleeps only when the loop
// has a finite bound, observable condition, and failure after timeout.
func TestSleepInTestRuleAcceptsBoundedPolling(t *testing.T) {
	unit := parseOne(t, "poll_test.go", `package sample

import (
	"testing"
	"time"
)

type serviceState struct{}

func (serviceState) Ready() bool { return true }

func TestPollReady(t *testing.T) {
	service := serviceState{}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if service.Ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("service never became ready")
}
`)
	if got := (SleepInTestRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("bounded polling sleep should be accepted, got %#v", got)
	}
}

// TestSleepInTestRuleKeepsIncompletePollingFindings rejects polling loops that
// are missing a timeout, observable condition, or failure path.
func TestSleepInTestRuleKeepsIncompletePollingFindings(t *testing.T) {
	unit := parseOne(t, "poll_test.go", `package sample

import (
	"testing"
	"time"
)

type serviceState struct{}

func (serviceState) Ready() bool { return true }

func TestNoTimeout(t *testing.T) {
	service := serviceState{}
	for {
		if service.Ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNoFailureAfterTimeout(t *testing.T) {
	service := serviceState{}
	for i := 0; i < 3; i++ {
		if service.Ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestBlindSleepBeforeAssertion(t *testing.T) {
	go func() {}()
	time.Sleep(10 * time.Millisecond)
	t.Fatalf("still blind")
}

func TestStateComparisonIsNotFiniteBound(t *testing.T) {
	service := serviceState{}
	events := []string{}
	for len(events) < 1 {
		if service.Ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("events never arrived")
}
`)
	findings := SleepInTestRule{}.AnalyzeUnit(unit, Context{})
	got := map[string]bool{}
	for _, item := range findings {
		got[item.Symbol] = true
	}
	for _, want := range []string{"TestNoTimeout", "TestNoFailureAfterTimeout", "TestBlindSleepBeforeAssertion", "TestStateComparisonIsNotFiniteBound"} {
		if !got[want] {
			t.Fatalf("%s should still flag; got %#v", want, findings)
		}
	}
}

// TestSleepInTestRuleRejectsContinueAsPollingExit confirms a polling loop whose
// success branch only continues still flags the sleep: continue keeps iterating,
// so the test is sleeping instead of synchronizing on the observed condition.
func TestSleepInTestRuleRejectsContinueAsPollingExit(t *testing.T) {
	unit := parseOne(t, "poll_test.go", `package sample

import (
	"testing"
	"time"
)

type serviceState struct{}

func (serviceState) Ready() bool { return true }

func TestContinuePolling(t *testing.T) {
	service := serviceState{}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if service.Ready() {
			continue
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("service never became ready")
}
`)
	findings := SleepInTestRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one sleep finding (continue does not exit the loop)", findings)
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

// TestSleepInTestRuleFlagsSleepInsideGoroutineWithinPolling ensures a sleep in a
// goroutine spawned inside a bounded polling loop still flags: it is not the
// loop's backoff, so accepting the loop must not whitelist nested-closure sleeps.
func TestSleepInTestRuleFlagsSleepInsideGoroutineWithinPolling(t *testing.T) {
	unit := parseOne(t, "poll_test.go", `package sample

import (
	"testing"
	"time"
)

type serviceState struct{}

func (serviceState) Ready() bool { return true }

func TestPollWithGoroutineSleep(t *testing.T) {
	service := serviceState{}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		go func() {
			time.Sleep(50 * time.Millisecond)
		}()
		if service.Ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("service never became ready")
}
`)
	findings := SleepInTestRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("goroutine sleep inside polling loop should flag while the backoff sleep is accepted; got %d: %#v", len(findings), findings)
	}
}

// TestSleepInTestRuleRejectsWallClockOnlyExit ensures a polling loop whose only
// exit checks elapsed wall-clock time (time.Since) is not accepted: it is still
// sleeping on the clock rather than synchronizing on the system under test.
func TestSleepInTestRuleRejectsWallClockOnlyExit(t *testing.T) {
	unit := parseOne(t, "poll_test.go", `package sample

import (
	"testing"
	"time"
)

func TestWallClockPolling(t *testing.T) {
	start := time.Now()
	deadline := start.Add(time.Second)
	timeout := time.Second / 2
	for time.Now().Before(deadline) {
		if time.Since(start) > timeout {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("never finished")
}
`)
	findings := SleepInTestRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("wall-clock-only polling exit should not be accepted; the sleep must flag, got %d: %#v", len(findings), findings)
	}
}

// TestSleepInTestRuleRejectsNoProgressCounter ensures a loop whose counter never
// advances (`i = i`) is not treated as a finite attempt bound, so its sleep still
// flags instead of being accepted as bounded polling.
func TestSleepInTestRuleRejectsNoProgressCounter(t *testing.T) {
	unit := parseOne(t, "poll_test.go", `package sample

import (
	"testing"
	"time"
)

type serviceState struct{}

func (serviceState) Ready() bool { return true }

func TestNoProgressPolling(t *testing.T) {
	service := serviceState{}
	for i := 0; i < 3; i = i {
		if service.Ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("service never became ready")
}
`)
	findings := SleepInTestRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("a counter that never advances (i = i) is not a finite bound; the sleep must flag, got %d: %#v", len(findings), findings)
	}
}
