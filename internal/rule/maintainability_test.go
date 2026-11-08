// Package rule tests parser-only maintainability rules.
//
// Each test parses inline Go fixtures with parseOne and counts one rule's findings; a count failure prints those findings.
package rule

import "testing"

// TestIgnoredErrorRule checks IgnoredErrorRule on a fixture that discards three errors with _ = and also discards a plain int value.
//
// It expects exactly two findings for direct ignored errors, with calls handled conservatively; any other count fails and prints the findings.
func TestIgnoredErrorRule(t *testing.T) {
	unit := parseOne(t, "maintain.go", `// Package sample is a test package.
package sample

import (
	"errors"
	"fmt"
)

func sample(file interface{ Close() error }) {
	err := errors.New("failed")
	_ = err
	_ = fmt.Errorf("wrapped: %w", err)
	_ = file.Close()
	value := 1
	_ = value
}
`)
	findings := IgnoredErrorRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want two direct ignored errors", findings)
	}
}

// TestContextTODOProductionRule expects one finding from a production fixture with TODO and Background, and none from a test fixture.
// A count failure prints the production or test-file findings that were reported.
func TestContextTODOProductionRule(t *testing.T) {
	production := parseOne(t, "service.go", `// Package sample is a test package.
package sample

import "context"

func sample() {
	_ = context.TODO()
	_ = context.Background()
}
`)
	if findings := (ContextTODOProductionRule{}).AnalyzeUnit(production, Context{}); len(findings) != 1 {
		t.Fatalf("production findings = %#v, want one context.TODO finding", findings)
	}

	testFile := parseOne(t, "service_test.go", `package sample

import "context"

func sample() {
	_ = context.TODO()
}
`)
	if findings := (ContextTODOProductionRule{}).AnalyzeUnit(testFile, Context{}); len(findings) != 0 {
		t.Fatalf("test findings = %#v, want none", findings)
	}
}

// TestProductionPanicRule expects one finding from a production fixture with literal and variable panics.
//
// It expects no findings from a command's package main; a count failure prints the findings that were reported.
func TestProductionPanicRule(t *testing.T) {
	production := parseOne(t, "service.go", `// Package sample is a test package.
package sample

func Crash() {
	panic("boom")
}

func Internal(err error) {
	panic(err)
}
`)
	if findings := analyseProductionPanicUnit(production); len(findings) != 1 {
		t.Fatalf("production findings = %#v, want one literal panic finding", findings)
	}

	mainFile := parseOne(t, "cmd/tool/main.go", `package main

func main() {
	panic("bootstrap")
}
`)
	if findings := analyseProductionPanicUnit(mainFile); len(findings) != 0 {
		t.Fatalf("main findings = %#v, want none", findings)
	}
}
