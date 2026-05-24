// Package rule tests the parser-only NPath complexity metric.
package rule

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestNPathBelowThresholdPasses confirms a small function does not fire.
func TestNPathBelowThresholdPasses(t *testing.T) {
	unit := parseOne(t, "small.go", `package sample

func add(a, b int) int {
	if a > 0 {
		return a + b
	}
	return b
}
`)
	findings := NPathComplexityRule{MaxComplexity: 5}.AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for simple function", findings)
	}
}

// TestNPathFlagsBranchCombinationBlowup is the rule's reason to exist: many
// sequential ifs produce 2^n paths while cyclomatic stays at n+1.
func TestNPathFlagsBranchCombinationBlowup(t *testing.T) {
	body := strings.Repeat("\tif a {} \n", 10) // 2^10 = 1024 paths, all in a flat function.
	unit := parseOne(t, "blowup.go", `package sample

func blowup(a bool) {
`+body+`}
`)
	findings := NPathComplexityRule{MaxComplexity: 200}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one blowup finding", findings)
	}
	got, ok := findings[0].Metadata["complexity"].(int)
	if !ok || got < 1024 {
		t.Errorf("metadata complexity = %v, want >= 1024", findings[0].Metadata["complexity"])
	}
}

// TestNPathBooleanOperatorsCount asserts && and || each contribute one path.
func TestNPathBooleanOperatorsCount(t *testing.T) {
	unit := parseOne(t, "bool.go", `package sample

func decide(a, b, c, d, e bool) {
	if a && b || c && d || e {
		return
	}
}
`)
	findings := NPathComplexityRule{MaxComplexity: 3}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one finding for 4 boolean operators", findings)
	}
}

// TestNPathSwitchSumsClauses verifies switch case bodies are summed and a
// missing default adds one fall-through path.
func TestNPathSwitchSumsClauses(t *testing.T) {
	unit := parseOne(t, "switch.go", `package sample

func dispatch(x int) {
	switch x {
	case 1:
	case 2:
	case 3:
	case 4:
	}
}
`)
	findings := NPathComplexityRule{MaxComplexity: 3}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want finding for 4 cases + no default", findings)
	}
}

// TestNPathRangeLoopAddsOne checks that for/range bodies plus one captures
// the loop-taken-vs-skipped axis.
func TestNPathRangeLoopAddsOne(t *testing.T) {
	unit := parseOne(t, "range.go", `package sample

func iter(items []int) {
	for range items {
		if len(items) > 0 {
			return
		}
	}
}
`)
	findings := NPathComplexityRule{MaxComplexity: 2}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want finding above threshold 2", findings)
	}
}

// TestNPathCapsAtInt32Max protects against integer overflow on degenerate
// functions; the report must communicate "above threshold" without wrapping.
func TestNPathCapsAtInt32Max(t *testing.T) {
	body := strings.Repeat("\tif a {} \n", 40) // 2^40 would overflow int32 if not capped.
	unit := parseOne(t, "huge.go", `package sample

func huge(a bool) {
`+body+`}
`)
	findings := NPathComplexityRule{MaxComplexity: 200}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want huge finding", findings)
	}
	complexity, ok := findings[0].Metadata["complexity"].(int)
	if !ok || complexity <= 0 {
		t.Errorf("complexity = %v, want positive capped value", findings[0].Metadata["complexity"])
	}
}

// TestNPathIsDefaultEnabled asserts the rule ships enabled with parser capability and medium severity.
func TestNPathIsDefaultEnabled(t *testing.T) {
	def := NPathComplexityRule{}.Definition()
	if !def.DefaultEnabled {
		t.Error("complexity.npath must be default-enabled")
	}
	if def.Capability != CapabilityParser {
		t.Errorf("capability = %q, want parser", def.Capability)
	}
	if def.Severity != finding.SeverityMedium {
		t.Errorf("severity = %q, want medium", def.Severity)
	}
	if def.Thresholds["maxComplexity"] != npathThreshold {
		t.Errorf("default threshold = %v, want %d", def.Thresholds["maxComplexity"], npathThreshold)
	}
}
