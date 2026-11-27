// Package rule tests additional parser-only test-quality rules.
//
// This file covers FatalInGoroutineRule, which flags t.Fatal or t.FailNow called from a goroutine a test starts, and TempDirMisuseRule.
// TempDirMisuseRule flags an empty-parent temp directory made in a test or in a helper that takes a testing handle.
package rule

import "testing"

// TestFatalInGoroutineRule checks for two findings in a fixture with t.Fatal, t.Error and a subtest's t.FailNow called in goroutines.
func TestFatalInGoroutineRule(t *testing.T) {
	unit := parseOne(t, "async_test.go", `package sample

import "testing"

func TestAsync(t *testing.T) {
	go func() {
		t.Fatal("failed")
	}()
	go func() {
		t.Error("reported")
	}()
}

func TestSubtest(t *testing.T) {
	t.Run("case", func(t *testing.T) {
		go func() {
			t.FailNow()
		}()
	})
}
`)
	findings := FatalInGoroutineRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want two fatal-in-goroutine findings", findings)
	}
}

// TestFatalInGoroutineRuleIgnoresNonTestingReceivers verifies Fatal on a fakeT that shadows t in a goroutine is not reported.
func TestFatalInGoroutineRuleIgnoresNonTestingReceivers(t *testing.T) {
	unit := parseOne(t, "async_test.go", `package sample

import "testing"

type fakeT struct{}

func (fakeT) Fatal(args ...any) {}

func TestAsync(t *testing.T) {
	go func(t fakeT) {
		t.Fatal("not testing")
	}(fakeT{})
}
`)
	findings := FatalInGoroutineRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
}

// TestTempDirMisuseRule checks for two findings in a fixture containing os.MkdirTemp and ioutil.TempDir calls.
// The fixture includes empty-parent calls, t.TempDir usage, a testing.TB helper and a function without a testing handle.
func TestTempDirMisuseRule(t *testing.T) {
	unit := parseOne(t, "tempdir_test.go", `package sample

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestTemp(t *testing.T) {
	_, _ = os.MkdirTemp("", "case")
	_, _ = os.MkdirTemp(t.TempDir(), "nested")
	_ = t.TempDir()
}

func helper(t testing.TB) {
	_, _ = ioutil.TempDir("", "helper")
}

func noTestingHandle() {
	_, _ = os.MkdirTemp("", "manual")
}
`)
	findings := TempDirMisuseRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want test and helper tempdir findings", findings)
	}
}

// TestTempDirMisuseRuleHandlesNestedSubtests verifies nested testing receivers stay in scope.
func TestTempDirMisuseRuleHandlesNestedSubtests(t *testing.T) {
	unit := parseOne(t, "tempdir_test.go", `package sample

import (
	"os"
	"testing"
)

func TestTemp(t *testing.T) {
	t.Run("case", func(t *testing.T) {
		_, _ = os.MkdirTemp("", "case")
	})
}
`)
	findings := TempDirMisuseRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want nested subtest tempdir finding", findings)
	}
}
