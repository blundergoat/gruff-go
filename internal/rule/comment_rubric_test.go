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

// TestCommentRubricRuleMinWordsBeyondSymbolDefaultUnchanged confirms M26 is opt-in: when the option
// stays zero, behaviour matches today's rule even for paraphrase comments.
func TestCommentRubricRuleMinWordsBeyondSymbolDefaultUnchanged(t *testing.T) {
	unit := parseOne(t, "fns.go", `package sample

// Documented returns the rule metadata for FooRule.
func Documented() {}
`)
	findings := CommentRubricRule{RequireFunctionComments: true}.AnalyzeUnit(unit, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none (option disabled keeps existing behaviour)", findings)
	}
}

// TestCommentRubricRuleMinWordsBeyondSymbolRejectsRestatement confirms M26 rejects sparse comments
// whose non-symbol token count falls below the configured threshold.
func TestCommentRubricRuleMinWordsBeyondSymbolRejectsRestatement(t *testing.T) {
	// Comment yields only {is} beyond the qualified symbol token set {foo, rule, definition}.
	unit := parseOne(t, "fns.go", `package sample

// FooRule is.
func (FooRule) Definition() string { return "" }
`)
	rule := CommentRubricRule{
		RequireFunctionComments: true,
		MinWordsBeyondSymbol:    3,
	}
	findings := rule.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one rejection", findings)
	}
	if findings[0].Symbol != "FooRule.Definition" {
		t.Fatalf("finding = %#v, want FooRule.Definition", findings[0])
	}
}

// TestCommentRubricRuleMinWordsBeyondSymbolAcceptsSubstantive confirms a substantive comment on a
// short symbol still passes at N=3 because it adds many non-symbol tokens.
func TestCommentRubricRuleMinWordsBeyondSymbolAcceptsSubstantive(t *testing.T) {
	unit := parseOne(t, "fns.go", `package sample

// Parse decodes the YAML bytes into a Config and validates required fields.
func Parse() {}
`)
	rule := CommentRubricRule{
		RequireFunctionComments: true,
		MinWordsBeyondSymbol:    3,
	}
	if findings := rule.AnalyzeUnit(unit, Context{}); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none (substantive comment passes)", findings)
	}
}

// TestCommentRubricRuleMinWordsBeyondSymbolUniformAcrossDecls confirms the option fires uniformly
// for functions, methods, named types, package-scope const, and package-scope var declarations.
func TestCommentRubricRuleMinWordsBeyondSymbolUniformAcrossDecls(t *testing.T) {
	// Each comment is intentionally sparse: normalises differently from the symbol but carries
	// fewer than 3 unique tokens that are not part of the symbol's identifier token set.
	unit := parseOne(t, "all.go", `package sample

// Definition is.
func Definition() {}

// Worker uses.
type Worker struct{}

// SingleConst is.
const SingleConst = 1

// SingleVar tracks.
var SingleVar = 2

// Method runs.
func (Worker) Method() {}
`)
	rule := CommentRubricRule{
		RequireFunctionComments:  true,
		RequireNamedTypeComments: true,
		RequireConstComments:     true,
		RequireVarComments:       true,
		MinWordsBeyondSymbol:     3,
	}
	findings := rule.AnalyzeUnit(unit, Context{})
	got := findingSymbols(findings)
	want := []string{"Definition", "Worker", "SingleConst", "SingleVar", "Worker.Method"}
	if len(got) != len(want) {
		t.Fatalf("findings = %#v, want symbols %v", findings, want)
	}
	for _, symbol := range want {
		if !got[symbol] {
			t.Fatalf("findings = %#v, missing %s", findings, symbol)
		}
	}
}

// TestCommentRubricRuleMinWordsBeyondSymbolAcceptsGroupComments confirms substantive group-level
// const/var comments still pass at N=3 for every spec inside the group.
func TestCommentRubricRuleMinWordsBeyondSymbolAcceptsGroupComments(t *testing.T) {
	unit := parseOne(t, "groups.go", `package sample

// Limits tunes runtime quotas applied to every analysis pass downstream.
const (
	First = 1
	Second = 2
)

// Buffers stores the temporary scratch areas re-used across each downstream pass.
var (
	BufferA = []byte{}
	BufferB = []byte{}
)
`)
	rule := CommentRubricRule{
		RequireConstComments: true,
		RequireVarComments:   true,
		MinWordsBeyondSymbol: 3,
	}
	if findings := rule.AnalyzeUnit(unit, Context{}); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none (substantive group comments)", findings)
	}
}

// TestCommentRubricRuleMinWordsBeyondSymbolStopwordsRejectParaphrase confirms common English
// fillers (the, for, of, is, …) are excluded from the substantive-token count so that paraphrase
// boilerplate like `// Definition returns the rule metadata for FooRule.` is rejected at N=3.
func TestCommentRubricRuleMinWordsBeyondSymbolStopwordsRejectParaphrase(t *testing.T) {
	// Symbol tokens after qualification: {foo, rule, definition}.
	// Comment tokens before stopword filter: {definition, returns, the, rule, metadata, for, foo}.
	// After symbol subtraction: {returns, the, metadata, for}.
	// After stopword subtraction (the, for): {returns, metadata} = 2 unique tokens. N=3 rejects.
	unit := parseOne(t, "fns.go", `package sample

// Definition returns the rule metadata for FooRule.
func (FooRule) Definition() string { return "" }
`)
	rule := CommentRubricRule{
		RequireFunctionComments: true,
		MinWordsBeyondSymbol:    3,
	}
	findings := rule.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one rejection of the paraphrase boilerplate", findings)
	}
	if findings[0].Symbol != "FooRule.Definition" {
		t.Fatalf("finding = %#v, want FooRule.Definition", findings[0])
	}
}

// commentRubricTestScopingTestUnit parses the canonical _test.go fixture for M27 scoping tests.
func commentRubricTestScopingTestUnit(t *testing.T) parser.Unit {
	t.Helper()
	return parseOne(t, "internal/sample/sample_test.go", `package sample

const fixtureValue = "x"

var fixtureSlice = []int{1, 2, 3}

func TestSomething() {}

type TestWorker struct{}
`)
}

// commentRubricTestScopingProdUnit parses the canonical production fixture for M27 scoping tests.
func commentRubricTestScopingProdUnit(t *testing.T) parser.Unit {
	t.Helper()
	return parseOne(t, "internal/sample/sample.go", `package sample

const ProductionConst = 1

var productionVar = 2
`)
}

// TestCommentRubricRuleTestFileConstVarSkippedByDefault confirms M27: const and var enforcement is
// suppressed on _test.go files even when ignoreTests is false, while non-test files stay strict.
func TestCommentRubricRuleTestFileConstVarSkippedByDefault(t *testing.T) {
	rule := CommentRubricRule{
		RequireConstComments: true,
		RequireVarComments:   true,
		IgnoreTests:          false,
	}
	if findings := rule.AnalyzeUnit(commentRubricTestScopingTestUnit(t), Context{}); len(findings) != 0 {
		t.Fatalf("test-file const/var findings = %#v, want none", findings)
	}
	findings := rule.AnalyzeUnit(commentRubricTestScopingProdUnit(t), Context{})
	if len(findings) != 2 {
		t.Fatalf("production findings = %#v, want ProductionConst and productionVar", findings)
	}
}

// TestCommentRubricRuleTestFileFunctionCheckStillFires confirms function comment enforcement on
// test files survives M27 (only const/var are scoped away).
func TestCommentRubricRuleTestFileFunctionCheckStillFires(t *testing.T) {
	rule := CommentRubricRule{
		RequireFunctionComments: true,
		IgnoreTests:             false,
	}
	findings := rule.AnalyzeUnit(commentRubricTestScopingTestUnit(t), Context{})
	if len(findings) != 1 || findings[0].Symbol != "TestSomething" {
		t.Fatalf("findings = %#v, want one TestSomething finding", findings)
	}
}

// TestCommentRubricRuleTestFileTypeCheckStillFires confirms named-type enforcement on test files
// survives M27 (only const/var are scoped away).
func TestCommentRubricRuleTestFileTypeCheckStillFires(t *testing.T) {
	rule := CommentRubricRule{
		RequireNamedTypeComments: true,
		IgnoreTests:              false,
	}
	findings := rule.AnalyzeUnit(commentRubricTestScopingTestUnit(t), Context{})
	if len(findings) != 1 || findings[0].Symbol != "TestWorker" {
		t.Fatalf("findings = %#v, want one TestWorker finding", findings)
	}
}

// TestCommentRubricRuleIgnoreTestsStillExemptsEverything confirms the whole-file exemption lever
// from IgnoreTests still wins over every check kind.
func TestCommentRubricRuleIgnoreTestsStillExemptsEverything(t *testing.T) {
	rule := CommentRubricRule{
		RequireFunctionComments:  true,
		RequireNamedTypeComments: true,
		RequireConstComments:     true,
		RequireVarComments:       true,
		IgnoreTests:              true,
	}
	if findings := rule.AnalyzeUnit(commentRubricTestScopingTestUnit(t), Context{}); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none (whole-file exemption)", findings)
	}
}

// TestCommentRubricRuleDefaultPackageSummaryOneLine covers M28: when requirePackageSummary is true
// and no threshold is configured, a single-line package summary now passes by default. A missing
// summary still fails.
func TestCommentRubricRuleDefaultPackageSummaryOneLine(t *testing.T) {
	rule := CommentRubricRule{RequirePackageSummary: true}

	oneLine := parseOne(t, "ok.go", `// Package sample explains the maintenance boundary.
package sample
`)
	if findings := rule.AnalyzeUnit(oneLine, Context{}); len(findings) != 0 {
		t.Fatalf("one-line summary findings = %#v, want none under default threshold", findings)
	}

	missing := parseOne(t, "missing.go", `package sample
`)
	findings := rule.AnalyzeUnit(missing, Context{})
	if len(findings) != 1 || findings[0].Message != "package summary is missing" {
		t.Fatalf("missing findings = %#v, want one missing-summary finding", findings)
	}

	// Explicit MinPackageCommentLines: 2 still rejects the one-line summary.
	strict := CommentRubricRule{
		RequirePackageSummary:  true,
		MinPackageCommentLines: 2,
	}
	if findings := strict.AnalyzeUnit(oneLine, Context{}); len(findings) != 1 {
		t.Fatalf("strict one-line findings = %#v, want one threshold finding", findings)
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
