// Package rule tests additional parser-only maintainability rules.
package rule

import "testing"

// TestDeferInLoopRule covers loop defers and helper-scope alternatives.
func TestDeferInLoopRule(t *testing.T) {
	unit := parseOne(t, "loops.go", `// Package sample is a test package.
package sample

func bad(files []File) {
	for _, file := range files {
		defer file.Close()
	}
	for i := 0; i < 3; i++ {
		if i > 0 {
			defer cleanup(i)
		}
	}
}

func ok(files []File) {
	for _, file := range files {
		func() {
			defer file.Close()
		}()
	}
}
`)
	findings := DeferInLoopRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want two loop defers", findings)
	}
}

// TestLogFatalLibraryRule covers fatal exits in reusable code and command exemptions.
func TestLogFatalLibraryRule(t *testing.T) {
	library := parseOne(t, "pkg/service.go", `// Package sample is a test package.
package sample

import (
	"log"
	"os"
)

func Load() {
	log.Fatal("failed")
	os.Exit(1)
}
`)
	if findings := (LogFatalLibraryRule{}).AnalyzeUnit(library, Context{}); len(findings) != 2 {
		t.Fatalf("library findings = %#v, want two fatal exits", findings)
	}

	mainFile := parseOne(t, "cmd/tool/main.go", `package main

import "log"

func main() {
	log.Fatal("failed")
}
`)
	if findings := (LogFatalLibraryRule{}).AnalyzeUnit(mainFile, Context{}); len(findings) != 0 {
		t.Fatalf("main findings = %#v, want none", findings)
	}
}

// TestLoopVariableAddressRule covers escaping range variable addresses and safe indexed addresses.
func TestLoopVariableAddressRule(t *testing.T) {
	unit := parseOne(t, "range.go", `// Package sample is a test package.
package sample

type Holder struct {
	Value *int
}

func Append(values []int) []*int {
	var out []*int
	for _, v := range values {
		out = append(out, &v)
	}
	return out
}

func Return(values []int) *int {
	for _, v := range values {
		return &v
	}
	return nil
}

func Store(values []int, holders []Holder) {
	for i, v := range values {
		holders[i].Value = &v
	}
}

func Safe(values []int) []*int {
	var out []*int
	for i, v := range values {
		p := &v
		_ = *p
		out = append(out, &values[i])
	}
	return out
}
`)
	findings := LoopVariableAddressRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 3 {
		t.Fatalf("findings = %#v, want append, return, and store findings", findings)
	}
}
