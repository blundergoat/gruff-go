// Package rule defines gruff-go's rule registry and analysers.
// This file exercises the M26-M28 calibration knobs on docs.comment-rubric:
// minWordsBeyondSymbol token thresholding, _test.go const/var scoping, and the
// one-line default package summary.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
)

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
