// Package rule tests additional parser-only maintainability rules.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

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

// TestLoopVariableAddressRuleLegacyEscapesAndSafeAlternatives preserves every
// escaping context while pinning indexed and non-escaping address negatives.
func TestLoopVariableAddressRuleLegacyEscapesAndSafeAlternatives(t *testing.T) {
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
	root := writeGoModForUnit(t, unit, ".", "module sample\n\ngo 1.21\n")
	findings := LoopVariableAddressRule{}.AnalyzeUnit(unit, Context{Root: root})
	if len(findings) != 3 {
		t.Fatalf("findings = %#v, want append, return, and store findings", findings)
	}
}

// TestLoopVariableAddressRuleSyntaxVersionMatrix pins declaration and assignment
// forms independently across every supported module-version state.
func TestLoopVariableAddressRuleSyntaxVersionMatrix(t *testing.T) {
	tests := []struct {
		name                 string
		rangeToken           string
		path                 string
		rootVersion          string
		rootWithoutDirective bool
		nestedVersion        string
		wantFindingCount     int
		wantRangeVariables   bool
	}{
		{name: "declaration go 1.21", rangeToken: ":=", rootVersion: "1.21", wantFindingCount: 2, wantRangeVariables: true},
		{name: "declaration go 1.22", rangeToken: ":=", rootVersion: "1.22", wantFindingCount: 0},
		{name: "declaration later go 1.25", rangeToken: ":=", rootVersion: "1.25.0", wantFindingCount: 0},
		{name: "declaration no module", rangeToken: ":=", wantFindingCount: 0},
		{name: "declaration module without go directive uses implicit 1.16", rangeToken: ":=", rootWithoutDirective: true, wantFindingCount: 2, wantRangeVariables: true},
		{name: "assignment go 1.21", rangeToken: "=", rootVersion: "1.21", wantFindingCount: 2, wantRangeVariables: true},
		{name: "assignment go 1.22", rangeToken: "=", rootVersion: "1.22", wantFindingCount: 2, wantRangeVariables: true},
		{name: "assignment later go 1.25", rangeToken: "=", rootVersion: "1.25.0", wantFindingCount: 2, wantRangeVariables: true},
		{name: "assignment no module", rangeToken: "=", wantFindingCount: 2, wantRangeVariables: true},
		{name: "assignment module without go directive", rangeToken: "=", rootWithoutDirective: true, wantFindingCount: 2, wantRangeVariables: true},
		{name: "declaration nested legacy overrides modern root", rangeToken: ":=", path: "legacy/pkg/range.go", rootVersion: "1.25.0", nestedVersion: "1.21", wantFindingCount: 2, wantRangeVariables: true},
		{name: "declaration nested modern overrides legacy root", rangeToken: ":=", path: "modern/pkg/range.go", rootVersion: "1.21", nestedVersion: "1.22", wantFindingCount: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if path == "" {
				path = "pkg/range.go"
			}
			unit := parseOne(t, path, loopVariableAddressMatrixFixture(tt.rangeToken))
			ctx := Context{}
			if tt.rootVersion != "" {
				ctx.Root = writeGoModForUnit(t, unit, ".", loopVariableAddressGoMod("root", tt.rootVersion))
			} else if tt.rootWithoutDirective {
				ctx.Root = writeGoModForUnit(t, unit, ".", "module root\n")
			}
			if tt.nestedVersion != "" {
				writeGoModForUnit(t, unit, tt.path[:len(tt.path)-len("/pkg/range.go")], loopVariableAddressGoMod("nested", tt.nestedVersion))
			}

			findings := LoopVariableAddressRule{}.AnalyzeUnit(unit, ctx)
			if len(findings) != tt.wantFindingCount {
				t.Fatalf("finding count = %d, want %d", len(findings), tt.wantFindingCount)
			}
			if tt.wantRangeVariables {
				assertLoopVariableAddressVariables(t, findings, "i", "v")
			}
		})
	}
}

// TestLoopVariableAddressRuleGatesEachRangeStatement proves a Go 1.22 module
// suppresses declaration-form aliases without hiding assignment-form aliases in
// the same analysis unit.
func TestLoopVariableAddressRuleGatesEachRangeStatement(t *testing.T) {
	unit := parseOne(t, "pkg/range.go", `// Package sample is a test package.
package sample

func collect(values []int) []*int {
	var out []*int
	for declaredIndex, declaredValue := range values {
		out = append(out, &declaredIndex, &declaredValue)
	}
	var assignedIndex int
	var assignedValue int
	for assignedIndex, assignedValue = range values {
		out = append(out, &assignedIndex, &assignedValue)
	}
	return out
}
`)
	root := writeGoModForUnit(t, unit, ".", loopVariableAddressGoMod("sample", "1.22"))
	findings := LoopVariableAddressRule{}.AnalyzeUnit(unit, Context{Root: root})
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want only two assignment-form findings", findings)
	}
	assertLoopVariableAddressVariables(t, findings, "assignedIndex", "assignedValue")
}

// loopVariableAddressMatrixFixture returns key/value address escapes for one
// declaration or assignment range form.
func loopVariableAddressMatrixFixture(rangeToken string) string {
	predeclared := ""
	if rangeToken == "=" {
		predeclared = "\tvar i int\n\tvar v int\n"
	}
	return `// Package sample is a test package.
package sample

func collect(values []int) []*int {
	var out []*int
` + predeclared + "\tfor i, v " + rangeToken + ` range values {
		out = append(out, &i, &v)
	}
	return out
}
`
}

// loopVariableAddressGoMod returns a minimal versioned module fixture.
func loopVariableAddressGoMod(module string, version string) string {
	return "module " + module + "\n\ngo " + version + "\n"
}

// assertLoopVariableAddressVariables verifies findings cover each expected key
// or value operand exactly once.
func assertLoopVariableAddressVariables(t *testing.T, findings []finding.Finding, variables ...string) {
	t.Helper()
	seen := map[string]int{}
	for _, item := range findings {
		variable, _ := item.Metadata["variable"].(string)
		seen[variable]++
	}
	for _, variable := range variables {
		if seen[variable] != 1 {
			t.Fatalf("variable %q finding count = %d, want 1; findings = %#v", variable, seen[variable], findings)
		}
	}
}
