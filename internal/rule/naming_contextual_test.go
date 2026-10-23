// Package rule defines gruff-go's rule registry and analysers.
// This file exercises the contextual-generic rule's size-gated detection logic.
package rule

import "testing"

// TestContextualGenericIgnoresShortGenericRange confirms generic range names are tolerated in short loops.
func TestContextualGenericIgnoresShortGenericRange(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func Render(users []string) {
	for _, item := range users {
		println(item)
	}
}
`)
	findings := (ContextualGenericRule{MinBodyLines: 3}).AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("short loop should pass, got %#v", findings)
	}
}

// TestContextualGenericFlagsLongGenericRange checks the rule emits a finding when the body crosses the line gate.
func TestContextualGenericFlagsLongGenericRange(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func Render(users []string) {
	for _, item := range users {
		println(item)
		println(item)
		println(item)
		println(item)
		println(item)
		println(item)
	}
}
`)
	findings := (ContextualGenericRule{MinBodyLines: 5}).AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "item" {
		t.Fatalf("findings = %#v, want one item finding", findings)
	}
	if findings[0].Metadata["range"] != "users" {
		t.Fatalf("metadata = %#v, want range users", findings[0].Metadata)
	}
}

// TestContextualGenericHonoursConfiguredGenericNames verifies user-supplied generic name lists override defaults.
func TestContextualGenericHonoursConfiguredGenericNames(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func Render(records []string) {
	for _, record := range records {
		println(record)
		println(record)
	}
}
`)
	defaultFindings := (ContextualGenericRule{MinBodyLines: 1}).AnalyzeUnit(unit, Context{})
	if len(defaultFindings) != 0 {
		t.Fatalf("record is not a default generic name, got %#v", defaultFindings)
	}
	configured := (ContextualGenericRule{
		GenericNames: []string{"record"},
		MinBodyLines: 1,
	}).AnalyzeUnit(unit, Context{})
	if len(configured) != 1 || configured[0].Symbol != "record" {
		t.Fatalf("configured findings = %#v, want record", configured)
	}
}

// TestContextualGenericFlagsAccumulatorsOnlyWhenGatesPass exercises both the function-length and require-multiple gates.
func TestContextualGenericFlagsAccumulatorsOnlyWhenGatesPass(t *testing.T) {
	unit := parseOne(t, "pkg/file.go", `package pkg

func Build(users []string) []string {
	out := []string{}
	result := []string{}
	for _, user := range users {
		out = append(out, user)
		result = append(result, user)
	}
	return append(out, result...)
}

func Single(users []string) []string {
	out := []string{}
	for _, user := range users {
		out = append(out, user)
	}
	return out
}
`)
	findings := (ContextualGenericRule{
		MinFunctionLines: 3,
	}).AnalyzeUnit(unit, Context{})
	got := findingSymbols(findings)
	if len(got) != 2 || !got["out"] || !got["result"] {
		t.Fatalf("findings = %#v, want out and result from Build only", findings)
	}

	allowSingle := false
	singleFindings := (ContextualGenericRule{
		MinFunctionLines: 3,
		RequireMultiple:  &allowSingle,
	}).AnalyzeUnit(unit, Context{})
	if len(singleFindings) != 3 {
		t.Fatalf("single-allowed findings = %#v, want three accumulator findings", singleFindings)
	}
}

// TestContextualGenericCountsCodeLinesInLoopBody checks the loop-body gate counts code lines only (FAMILY-CONTRACT
// section 12, search `Code lines in every line count`): comments and blank lines in the body are free, and a body one
// code line over the gate still reports.
func TestContextualGenericCountsCodeLinesInLoopBody(t *testing.T) {
	padded := parseOne(t, "pkg/file.go", `package pkg

func Render(users []string) {
	for _, item := range users {
		// Each user prints on its own line.
		println(item)

		println(item)
		// The second pass repeats the first.
		println(item)

		println(item)
		/* The last call closes the group. */
		println(item)
	}
}
`)
	if got := (ContextualGenericRule{MinBodyLines: 5}).AnalyzeUnit(padded, Context{}); len(got) != 0 {
		t.Fatalf("five code lines with padding stay at the gate, got %#v", got)
	}

	over := parseOne(t, "pkg/file.go", `package pkg

func Render(users []string) {
	for _, item := range users {
		// Each user prints on its own line.
		println(item)

		println(item)
		println(item)
		println(item)
		println(item)
		println(item)
	}
}
`)
	findings := (ContextualGenericRule{MinBodyLines: 5}).AnalyzeUnit(over, Context{})
	if len(findings) != 1 || findings[0].Metadata["bodyLines"] != 6 {
		t.Fatalf("findings = %#v, want one finding on a six-code-line body", findings)
	}
}

// TestContextualGenericCountsCodeLinesInFunction checks the function gate counts code lines only: the doc comment,
// body comments and blank lines are free, and a function one code line over the gate still reports.
func TestContextualGenericCountsCodeLinesInFunction(t *testing.T) {
	padded := parseOne(t, "pkg/file.go", `package pkg

// Build returns every user twice, once per list.
func Build(users []string) []string {
	// The first list keeps the input order.
	out := []string{}

	// The second list repeats it.
	result := []string{}
	return append(out, result...)
}
`)
	if got := (ContextualGenericRule{MinFunctionLines: 5}).AnalyzeUnit(padded, Context{}); len(got) != 0 {
		t.Fatalf("five code lines with padding stay at the gate, got %#v", got)
	}

	over := parseOne(t, "pkg/file.go", `package pkg

// Build returns every user twice, once per list.
func Build(users []string) []string {
	// The first list keeps the input order.
	out := []string{}
	result := []string{}
	result = append(result, users...)
	return append(out, result...)
}
`)
	findings := (ContextualGenericRule{MinFunctionLines: 5}).AnalyzeUnit(over, Context{})
	got := findingSymbols(findings)
	if len(got) != 2 || !got["out"] || !got["result"] || findings[0].Metadata["functionLines"] != 6 {
		t.Fatalf("findings = %#v, want out and result on a six-code-line function", findings)
	}
}

// TestContextualGenericSkipsTestAndGeneratedFiles ensures the rule ignores test and machine-generated files.
func TestContextualGenericSkipsTestAndGeneratedFiles(t *testing.T) {
	testUnit := parseOne(t, "pkg/file_test.go", `package pkg

func TestRender() {
	for _, item := range []string{"a"} {
		println(item)
		println(item)
	}
}
`)
	if got := (ContextualGenericRule{MinBodyLines: 1}).AnalyzeUnit(testUnit, Context{}); len(got) != 0 {
		t.Fatalf("test file should pass, got %#v", got)
	}

	generatedUnit := parseOne(t, "pkg/generated.go", `// Generated by tool. DO NOT EDIT.
package pkg

func Render(users []string) {
	for _, item := range users {
		println(item)
		println(item)
	}
}
`)
	if got := (ContextualGenericRule{MinBodyLines: 1}).AnalyzeUnit(generatedUnit, Context{}); len(got) != 0 {
		t.Fatalf("generated file should pass, got %#v", got)
	}

	if got := (ContextualGenericRule{MinBodyLines: 1}).AnalyzeUnit(generatedUnit, Context{IncludeIgnored: true}); len(got) != 1 {
		t.Fatalf("include-ignored generated file should be analysed, got %#v", got)
	}
}

// TestContextualGenericIsDefaultEnabled asserts the rule ships on by default and runs at parser capability.
func TestContextualGenericIsDefaultEnabled(t *testing.T) {
	definition := ContextualGenericRule{}.Definition()
	if !definition.DefaultEnabled {
		t.Error("naming.contextual-generic must be default-enabled")
	}
	if definition.Capability != CapabilityParser {
		t.Error("naming.contextual-generic must be parser-capability")
	}
}
