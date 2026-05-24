// Package rule tests parser-only maintainability rules.
package rule

import "testing"

// TestIgnoredErrorRule covers direct ignored error values and conservative call handling.
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

// TestContextTODOProductionRule verifies production context.TODO calls are visible while tests and Background are ignored.
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

// TestProductionPanicRule verifies literal production panics and the conservative exemptions.
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
	if findings := (ProductionPanicRule{}).AnalyzeUnit(production, Context{}); len(findings) != 1 {
		t.Fatalf("production findings = %#v, want one literal panic finding", findings)
	}

	mainFile := parseOne(t, "cmd/tool/main.go", `package main

func main() {
	panic("bootstrap")
}
`)
	if findings := (ProductionPanicRule{}).AnalyzeUnit(mainFile, Context{}); len(findings) != 0 {
		t.Fatalf("main findings = %#v, want none", findings)
	}
}
