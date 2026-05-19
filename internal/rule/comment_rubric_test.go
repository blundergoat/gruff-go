// Package rule defines gruff-go's rule registry and analysers.
// This file exercises the comment-rubric rule across its configuration knobs.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestCommentRubricRulePackageSummary verifies package summary detection across missing, short, and well-formed files.
func TestCommentRubricRulePackageSummary(t *testing.T) {
	rule := CommentRubricRule{
		RequirePackageSummary:  true,
		MinPackageCommentLines: 2,
	}

	missing := parseOne(t, "missing.go", `package sample
`)
	findings := rule.AnalyzeUnit(missing, Context{})
	if len(findings) != 1 || findings[0].Message != "package summary is missing" {
		t.Fatalf("missing findings = %#v, want one missing package summary finding", findings)
	}

	short := parseOne(t, "short.go", `// Package sample explains too little.
package sample
`)
	findings = rule.AnalyzeUnit(short, Context{})
	if len(findings) != 1 || findings[0].Metadata["lines"] != 1 || findings[0].Metadata["threshold"] != 2 {
		t.Fatalf("short findings = %#v, want one line-threshold package summary finding", findings)
	}

	ok := parseOne(t, "ok.go", `// Package sample describes the maintenance boundary for this test fixture.
// It provides enough context for future maintainers to understand ownership.
package sample
`)
	if findings := rule.AnalyzeUnit(ok, Context{}); len(findings) != 0 {
		t.Fatalf("ok findings = %#v, want none", findings)
	}
}

// TestCommentRubricRuleFunctionComments checks that function and method declarations require useful comments.
func TestCommentRubricRuleFunctionComments(t *testing.T) {
	unit := parseOne(t, "functions.go", `package sample

// Documented explains the contract.
func Documented() {}

// MultiLine explains the contract.
// It can use more than one non-empty line.
func MultiLine() {}

// Restated.
func Restated() {}

func Missing() {}

type Worker struct{}

func (Worker) MissingMethod() {}
`)
	findings := CommentRubricRule{RequireFunctionComments: true}.AnalyzeUnit(unit, Context{})
	got := findingSymbols(findings)
	want := []string{"Restated", "Missing", "Worker.MissingMethod"}
	if len(got) != len(want) {
		t.Fatalf("findings = %#v, want symbols %v", findings, want)
	}
	for _, symbol := range want {
		if !got[symbol] {
			t.Fatalf("findings = %#v, missing %s", findings, symbol)
		}
	}
}

// TestCommentRubricRuleNamedTypeComments exercises the named-type, struct-only, and interface-only enforcement modes.
func TestCommentRubricRuleNamedTypeComments(t *testing.T) {
	unit := parseOne(t, "types.go", `package sample

// Documented is covered.
type Documented struct{}

// RestatedStruct.
type RestatedStruct struct{}

type MissingStruct struct{}

type MissingInterface interface{}

type MissingAlias string

// Grouped declarations share this attached comment.
type (
	GroupedStruct struct{}
	GroupedAlias string
)
`)
	findings := CommentRubricRule{RequireNamedTypeComments: true}.AnalyzeUnit(unit, Context{})
	got := findingSymbols(findings)
	want := []string{"RestatedStruct", "MissingStruct", "MissingInterface", "MissingAlias"}
	if len(got) != len(want) {
		t.Fatalf("findings = %#v, want symbols %v", findings, want)
	}
	for _, symbol := range want {
		if !got[symbol] {
			t.Fatalf("findings = %#v, missing %s", findings, symbol)
		}
	}

	structOnly := CommentRubricRule{RequireStructComments: true}.AnalyzeUnit(unit, Context{})
	if got := findingSymbols(structOnly); len(got) != 2 || !got["RestatedStruct"] || !got["MissingStruct"] {
		t.Fatalf("struct-only findings = %#v, want RestatedStruct and MissingStruct", structOnly)
	}
	interfaceOnly := CommentRubricRule{RequireInterfaceComments: true}.AnalyzeUnit(unit, Context{})
	if got := findingSymbols(interfaceOnly); len(got) != 1 || !got["MissingInterface"] {
		t.Fatalf("interface-only findings = %#v, want MissingInterface only", interfaceOnly)
	}
}

// TestCommentRubricRuleConstAndVarComments confirms const and var enforcement skips function-local declarations.
func TestCommentRubricRuleConstAndVarComments(t *testing.T) {
	unit := parseOne(t, "values.go", `package sample

// DocumentedConst explains why this constant exists.
const DocumentedConst = 1

// RestatedConst.
const RestatedConst = 2

const MissingConst = 2

// Grouped constants explain the group contract.
const (
	GroupedConst = 3
	AnotherGroupedConst = 4
)

// documentedVar explains why this variable is package scoped.
var documentedVar = 1

// restatedVar.
var restatedVar = 2

var missingVar = 2

func localValues() {
	const localConst = 1
	var localVar = 2
	_, _ = localConst, localVar
}
`)
	findings := CommentRubricRule{
		RequireConstComments: true,
		RequireVarComments:   true,
	}.AnalyzeUnit(unit, Context{})
	got := findingSymbols(findings)
	want := []string{"RestatedConst", "MissingConst", "restatedVar", "missingVar"}
	if len(got) != len(want) {
		t.Fatalf("findings = %#v, want symbols %v", findings, want)
	}
	for _, symbol := range want {
		if !got[symbol] {
			t.Fatalf("findings = %#v, missing %s", findings, symbol)
		}
	}
	if got["localConst"] || got["localVar"] {
		t.Fatalf("findings = %#v, local values must not be enforced", findings)
	}
}

// TestCommentRubricRuleScopeControlsAndTests verifies include, exclude, and test-skip path controls.
func TestCommentRubricRuleScopeControlsAndTests(t *testing.T) {
	mainUnit := parseOne(t, "internal/config/config.go", `package config

func Missing() {}
`)
	otherUnit := parseOne(t, "internal/other/other.go", `package other

func Missing() {}
`)
	testUnit := parseOne(t, "internal/config/config_test.go", `package config

func MissingTestHelper() {}
`)
	rule := CommentRubricRule{
		IncludePaths:            []string{"internal/config/**"},
		ExcludePaths:            []string{"internal/config/*_test.go"},
		RequireFunctionComments: true,
	}
	if findings := rule.AnalyzeUnit(mainUnit, Context{}); len(findings) != 1 {
		t.Fatalf("included findings = %#v, want one", findings)
	}
	if findings := rule.AnalyzeUnit(otherUnit, Context{}); len(findings) != 0 {
		t.Fatalf("non-included findings = %#v, want none", findings)
	}
	if findings := rule.AnalyzeUnit(testUnit, Context{}); len(findings) != 0 {
		t.Fatalf("excluded test findings = %#v, want none", findings)
	}

	noTests := CommentRubricRule{RequireFunctionComments: true, IgnoreTests: true}
	if findings := noTests.AnalyzeUnit(testUnit, Context{}); len(findings) != 0 {
		t.Fatalf("ignore-tests findings = %#v, want none", findings)
	}
}

// TestCommentRubricRuleDefaultsConfigured confirms the rule activates only after explicit opt-in configuration.
func TestCommentRubricRuleDefaultsConfigured(t *testing.T) {
	unit := parseOne(t, "sample.go", `package sample

func Missing() {}
`)
	defaults := Defaults()
	if findings := defaults.Analyze([]parser.Unit{unit}, Context{}); containsRuleID(findings, "docs.comment-rubric") {
		t.Fatalf("default findings = %#v, want docs.comment-rubric disabled", findings)
	}

	registry, err := DefaultsConfigured(Config{
		Enabled: map[string]bool{
			"docs.comment-rubric":  true,
			"docs.package-comment": false,
		},
		Thresholds: map[string]map[string]float64{
			"docs.comment-rubric": {
				"minPackageCommentLines": 2,
			},
		},
		Options: map[string]map[string]any{
			"docs.comment-rubric": {
				"includePaths":            []any{"sample.go"},
				"requireFunctionComments": true,
				"requirePackageSummary":   true,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings := registry.Analyze([]parser.Unit{unit}, Context{})
	if !containsRuleID(findings, "docs.comment-rubric") {
		t.Fatalf("findings = %#v, want docs.comment-rubric findings", findings)
	}
	got := findingSymbols(findings)
	if !got["Missing"] {
		t.Fatalf("findings = %#v, want Missing function finding", findings)
	}
}

// findingSymbols collects finding symbols into a set keyed by symbol name.
func findingSymbols(findings []finding.Finding) map[string]bool {
	out := map[string]bool{}
	for _, item := range findings {
		out[item.Symbol] = true
	}
	return out
}

// findingMessages collects finding messages into a set keyed by message text.
func findingMessages(findings []finding.Finding) map[string]bool {
	out := map[string]bool{}
	for _, item := range findings {
		out[item.Message] = true
	}
	return out
}
