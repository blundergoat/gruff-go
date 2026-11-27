// Package rule tests the parser-only test-quality.sleep-in-test rule.
//
// Each fixture is inline Go source parsed as a _test.go file, except one production file that checks the rule stays out of non-test code.
// A failing test points at a change in what the rule reports: its finding count, the Symbol it names, its file scope, or its shipped definition.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestSleepInTestRuleFlagsDirectCall asserts the basic time.Sleep call site is reported, with the enclosing test function as its Symbol.
// t fails on any finding count other than one, or on a Symbol other than TestSleepy, for the fixture's direct sleep.
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
// t fails on any finding count other than one for the sleep inside the subtest's goroutine.
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
// t requires exactly one finding for waitOnce, a helper that no test in the fixture calls.
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

// TestSleepInTestRuleAcceptsBoundedPolling checks a poll with a finite bound, observable condition and timeout failure raises no finding.
// t fails on any finding for the deadline poll, whose ready check returns and whose timeout calls t.Fatalf.
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

// TestSleepInTestRuleKeepsIncompletePollingFindings keeps sleeps reported in polls that lack a finite bound or a failure after timeout.
// The plain sleep before an assertion must flag too; t fails naming the first fixture test, in list order, that drew no finding.
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
	flaggedSymbols := map[string]bool{}
	for _, item := range findings {
		flaggedSymbols[item.Symbol] = true
	}
	for _, want := range []string{"TestNoTimeout", "TestNoFailureAfterTimeout", "TestBlindSleepBeforeAssertion", "TestStateComparisonIsNotFiniteBound"} {
		if !flaggedSymbols[want] {
			t.Fatalf("%s should still flag; got %#v", want, findings)
		}
	}
}

// TestSleepInTestRuleRejectsContinueAsPollingExit confirms a polling loop whose success branch only continues still flags the sleep.
// t requires one finding, because continue stays in the loop instead of leaving it once the condition is observed.
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
// t fails on any finding from the service.go fixture, where this test-quality rule must stay silent.
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

// TestSleepInTestRuleIgnoresShadowedReceiver verifies a local value named time with its own Sleep method does not fire.
// The fixture has no time import, so t checks that path only; a shadowed time in a file that also imports time is not covered here.
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

// TestSleepInTestRuleIsDefaultEnabled asserts the rule ships enabled with parser capability at advisory severity.
// t reports each of those three Definition fields that differs from what the rule ships with.
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

// TestSleepInTestRuleFlagsSleepInsideGoroutineWithinPolling checks a polling fixture with two sleeps yields exactly one finding.
// One sleep is the bounded loop's backoff and one sits in a goroutine; the test does not check which of them the finding names.
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

// TestSleepInTestRuleRejectsWallClockOnlyExit ensures a polling loop whose only exit checks elapsed wall-clock time (time.Since) is not accepted.
// Such a loop still sleeps on the clock rather than synchronizing on the system under test, so t requires its sleep to flag.
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

// TestSleepInTestRuleRejectsNoProgressCounter ensures a loop whose counter never advances (i = i) is not treated as a finite attempt bound.
// t requires the sleep to stay reported instead of being accepted as bounded polling.
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

// TestSleepInTestRuleSkipsDeliberateSleeps covers sleeps the rule accepts as deliberate, and t requires each case to yield no finding.
// Cases: a synctest fake-clock bubble, a test double's configured delay, a sleep the test times itself, and bounded polls in observed forms.
func TestSleepInTestRuleSkipsDeliberateSleeps(t *testing.T) {
	cases := map[string]string{
		"synctest test bubble": `func TestBubble(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		time.Sleep(time.Second)
		synctest.Wait()
	})
}`,
		"synctest run bubble": `func TestRun(t *testing.T) {
	synctest.Run(func() { go func() { time.Sleep(time.Second) }() })
}`,
		"test double delay": `type slowWriter struct{ delay time.Duration }

func (w *slowWriter) Write(p []byte) (int, error) {
	time.Sleep(w.delay)
	return len(p), nil
}`,
		"sleep the test times": `func TestElapsed(t *testing.T) {
	start := time.Now()
	time.Sleep(10 * time.Millisecond)
	if time.Since(start) < 10*time.Millisecond {
		t.Fatal("slept too little")
	}
}`,
		"poll helper returns false on timeout": `func waitForLog(t *testing.T) bool {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if scan(t) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}`,
		"labelled range poll exits from an if init": `func TestStarted(t *testing.T) {
	started := false
Loop:
	for range 10 {
		if _, err := probe(); err == nil {
			started = true
			break Loop
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !started {
		t.Fatal("never started")
	}
}`,
		"elapsed-time deadline poll": `func TestSince(t *testing.T) {
	start := time.Now()
	for time.Since(start) < time.Second {
		if ready() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("never ready")
}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			unit := parseOne(t, "deliberate_test.go", sleepFixture(body))
			if got := (SleepInTestRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
				t.Fatalf("findings = %#v, want none", got)
			}
		})
	}
}

// TestSleepInTestRuleKeepsLookalikeSleeps keeps each skipped shape's near miss reported.
// t requires exactly one finding per case, so a skip shape must not widen enough to hide a nearby blind sleep.
func TestSleepInTestRuleKeepsLookalikeSleeps(t *testing.T) {
	cases := map[string]string{
		"sleep before the bubble opens": `func TestBubble(t *testing.T) {
	time.Sleep(time.Second)
	synctest.Test(t, func(t *testing.T) {})
}`,
		"bubble call from another package": `func TestFake(t *testing.T) {
	fake.Test(t, func(t *testing.T) { time.Sleep(time.Second) })
}`,
		"delay field of a parameter, not the receiver": `func wait(cfg *slowWriter) {
	time.Sleep(cfg.delay)
}`,
		"random jitter stays reported": `func jitter() {
	time.Sleep(time.Duration(rand.Intn(300)) * time.Millisecond)
}`,
		"fixed sleep in a method": `func (w *slowWriter) Flush() {
	time.Sleep(time.Second)
}`,
		"suite test method sleeping on its own field": `func (w *slowWriter) TestFlush(t *testing.T) {
	time.Sleep(w.delay)
}`,
		"start time never read again": `func TestStartOnly(t *testing.T) {
	start := time.Now()
	time.Sleep(10 * time.Millisecond)
	_ = start
}`,
		"poll helper returns true on timeout": `func waitForLog(t *testing.T) bool {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if scan(t) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}`,
		"poll helper returns a nil error on timeout": `func waitForLog(t *testing.T) error {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if scan(t) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}`,
		"range over a slice is not a bounded poll": `func TestEach(t *testing.T) {
	for range []int{1, 2} {
		if _, err := probe(); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("never started")
}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			unit := parseOne(t, "lookalike_test.go", sleepFixture(body))
			if got := (SleepInTestRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
				t.Fatalf("findings = %#v, want one", got)
			}
		})
	}
}

// sleepFixture wraps one case body in a test file importing every package the cases name.
// It returns the fixture source: the package sample clause, imports, slowWriter type and scan, probe and ready stubs, then body and a newline.
func sleepFixture(body string) string {
	return `package sample

import (
	"math/rand"
	"testing"
	"testing/synctest"
	"time"

	fake "example.com/fake"
)

var _ = rand.Intn
var _ = synctest.Wait
var _ = fake.Test

type slowWriter struct{ delay time.Duration }

func scan(*testing.T) bool { return true }
func probe() (int, error) { return 0, nil }
func ready() bool { return true }

` + body + "\n"
}
