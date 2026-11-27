// Package rule defines gruff-go's rule registry and analysers.
//
// This file tests docs.comment-rubric across its configuration knobs: package summaries, function, type, const and var docs, and path scope.
// Additional calibration tests live in comment_rubric_calibration_test.go.
//
// A failure here means a user who turns on the rule's checks would see findings it should skip, or miss ones it should report.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestCommentRubricRulePackageSummary verifies package summary detection across missing, short, and well-formed files.
// A failure means users see a wrong or missing package-summary finding, or one per file when doc.go already holds the summary.
func TestCommentRubricRulePackageSummary(t *testing.T) {
	rule := CommentRubricRule{
		RequirePackageSummary:  true,
		MinPackageCommentLines: 2,
	}

	missing := parseOne(t, "missing.go", `package sample
`)
	findings := rule.AnalyzeProject([]parser.Unit{missing}, Context{})
	if len(findings) != 1 || findings[0].Message != "package summary is missing" {
		t.Fatalf("missing findings = %#v, want one missing package summary finding", findings)
	}

	short := parseOne(t, "short.go", `// Package sample explains too little.
package sample
`)
	findings = rule.AnalyzeProject([]parser.Unit{short}, Context{})
	if len(findings) != 1 || findings[0].Metadata["lines"] != 1 || findings[0].Metadata["threshold"] != 2 {
		t.Fatalf("short findings = %#v, want one line-threshold package summary finding", findings)
	}

	wellFormed := parseOne(t, "ok.go", `// Package sample describes the maintenance boundary for this test fixture.
// It provides enough context for future maintainers to understand ownership.
package sample
`)
	if findings := rule.AnalyzeProject([]parser.Unit{wellFormed}, Context{}); len(findings) != 0 {
		t.Fatalf("ok findings = %#v, want none", findings)
	}

	// Regression coverage: a package-level summary in doc.go should satisfy the
	// whole package instead of producing one missing-summary finding per sibling file.
	docFile := parseOne(t, "internal/sample/doc.go", `// Package sample explains the maintenance boundary for this test fixture.
// It provides enough context for future maintainers to understand ownership.
package sample
`)
	siblingA := parseOne(t, "internal/sample/a.go", `package sample
`)
	siblingB := parseOne(t, "internal/sample/b.go", `package sample
`)
	if findings := rule.AnalyzeProject([]parser.Unit{siblingA, docFile, siblingB}, Context{}); len(findings) != 0 {
		t.Fatalf("multi-file package findings = %#v, want none when one file supplies the summary", findings)
	}
}

// TestCommentRubricRuleFunctionComments checks that function and method declarations require useful comments.
// A missing doc or one that only repeats the name is reported; a failure means one slips through or a real doc is flagged.
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
	// Restated has a doc that only repeats its name, so it is reported alongside the two undocumented declarations.
	findings := CommentRubricRule{RequireFunctionComments: true}.AnalyzeProject([]parser.Unit{unit}, Context{})
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
// A failure means a mode flags a type of a kind it should skip, or misses one with no doc or a name-only doc.
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
	// The grouped block shares one attached doc, so GroupedStruct and GroupedAlias are not reported.
	findings := CommentRubricRule{RequireNamedTypeComments: true}.AnalyzeProject([]parser.Unit{unit}, Context{})
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

	structOnly := CommentRubricRule{RequireStructComments: true}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if got := findingSymbols(structOnly); len(got) != 2 || !got["RestatedStruct"] || !got["MissingStruct"] {
		t.Fatalf("struct-only findings = %#v, want RestatedStruct and MissingStruct", structOnly)
	}
	interfaceOnly := CommentRubricRule{RequireInterfaceComments: true}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if got := findingSymbols(interfaceOnly); len(got) != 1 || !got["MissingInterface"] {
		t.Fatalf("interface-only findings = %#v, want MissingInterface only", interfaceOnly)
	}
}

// TestCommentRubricRuleConstAndVarComments confirms const and var enforcement skips function-local declarations.
// Package-level values with no doc or a name-only doc are reported; a failure means one is missed or a grouped or local value is flagged.
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
	}.AnalyzeProject([]parser.Unit{unit}, Context{})
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
	// Function-local consts and vars are never enforced; only package-scope values need a doc.
	if got["localConst"] || got["localVar"] {
		t.Fatalf("findings = %#v, local values must not be enforced", findings)
	}
}

// TestCommentRubricRuleScopeControlsAndTests verifies include, exclude, and test-skip path controls.
// A failure means IncludePaths, ExcludePaths or IgnoreTests reports a file the user scoped out, or skips one they kept in.
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
	if findings := rule.AnalyzeProject([]parser.Unit{mainUnit}, Context{}); len(findings) != 1 {
		t.Fatalf("included findings = %#v, want one", findings)
	}
	if findings := rule.AnalyzeProject([]parser.Unit{otherUnit}, Context{}); len(findings) != 0 {
		t.Fatalf("non-included findings = %#v, want none", findings)
	}
	// config_test.go also matches IncludePaths, so only the ExcludePaths glob keeps its undocumented helper out of the findings.
	if findings := rule.AnalyzeProject([]parser.Unit{testUnit}, Context{}); len(findings) != 0 {
		t.Fatalf("excluded test findings = %#v, want none", findings)
	}

	noTests := CommentRubricRule{RequireFunctionComments: true, IgnoreTests: true}
	if findings := noTests.AnalyzeProject([]parser.Unit{testUnit}, Context{}); len(findings) != 0 {
		t.Fatalf("ignore-tests findings = %#v, want none", findings)
	}
}

// TestCommentRubricRuleDefaultsConfigured confirms stricter comment-rubric options are threaded from config.
// A failure means findings appear with no config, or a config that turns on the checks still misses the undocumented Missing function.
func TestCommentRubricRuleDefaultsConfigured(t *testing.T) {
	unit := parseOne(t, "sample.go", `package sample

func Missing() {}
`)
	defaults := Defaults()
	// Defaults() leaves every comment-rubric check off, so a user who sets no comment-rubric options sees no comment-rubric findings.
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

// TestCommentRubricRuleRequireFunctionCommentsCoversEveryDeclaration sets only requireFunctionComments, with no includePaths.
//
// Every undocumented top-level function and method must be reported, including unexported names, unexported receivers and generics.
// The same ten symbols must appear under internal/ and a public pkg/ path; a failure means a declaration is missed or wrongly flagged.
func TestCommentRubricRuleRequireFunctionCommentsCoversEveryDeclaration(t *testing.T) {
	source := `package helper

func Exported() {}

func unexported() {}

type Service struct{}

func (Service) Value() {}

func (s *Service) pointer() {}

type hidden struct{}

func (hidden) Exported() {}

func (*hidden) unexported() {}

type Box[T any] struct{ value T }

func (b *Box[T]) Get() T { return b.value }

func (b Box[T]) peek() T { return b.value }

type Pair[K comparable, V any] struct{}

func (Pair[K, V]) Len() int { return 0 }

func Map[T any](items []T) []T { return items }

type Stack[T any] struct{}

// Push adds an item to the top of the stack.
func (s *Stack[T]) Push(item T) {}
`
	registry, err := DefaultsConfigured(Config{
		Options: map[string]map[string]any{
			"docs.comment-rubric": {"requireFunctionComments": true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"Exported", "unexported", "Service.Value", "Service.pointer", "hidden.Exported",
		"hidden.unexported", "Box.Get", "Box.peek", "Pair.Len", "Map",
	}
	for _, path := range []string{"internal/helper/helper.go", "pkg/helper/helper.go"} {
		unit := parseOne(t, path, source)
		got := map[string]bool{}
		// The registry runs other rules too, so only docs.comment-rubric findings are collected.
		for _, item := range registry.Analyze([]parser.Unit{unit}, Context{}) {
			if item.RuleID == "docs.comment-rubric" {
				got[item.Symbol] = true
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%s: comment-rubric symbols = %v, want %v", path, got, want)
		}
		for _, symbol := range want {
			if !got[symbol] {
				t.Fatalf("%s: comment-rubric symbols = %v, missing %s", path, got, symbol)
			}
		}
	}
}

// findingSymbols collects each finding's Symbol into a set so a test can check which declarations a rule reported.
//
// Duplicate symbols in findings collapse to one key, and an empty Symbol becomes the empty-string key.
// It returns a map holding true for every symbol seen; a nil or empty findings slice yields an empty, non-nil map.
func findingSymbols(findings []finding.Finding) map[string]bool {
	out := map[string]bool{}
	for _, item := range findings {
		out[item.Symbol] = true
	}
	return out
}

// findingMessages collects each finding's Message into a set so a test can check which messages a rule reported.
//
// Duplicate messages in findings collapse to one key, and an empty Message becomes the empty-string key.
// It returns a map holding true for every message seen; a nil or empty findings slice yields an empty, non-nil map.
func findingMessages(findings []finding.Finding) map[string]bool {
	out := map[string]bool{}
	for _, item := range findings {
		out[item.Message] = true
	}
	return out
}
