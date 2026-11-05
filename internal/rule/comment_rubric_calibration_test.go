// Package rule defines gruff-go's rule registry and analysers.
//
// Comment-rubric calibration tests pin down substantive-token thresholds, _test.go const/var scoping, and the one-line default package summary.
// A failure here changes which comment-rubric findings a user sees for sparse comments, test-file declarations or package summaries.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestCommentRubricRuleMinWordsBeyondSymbolDefaultUnchanged confirms the substantive-token threshold is opt-in.
// With MinWordsBeyondSymbol left at zero, existing paraphrase behaviour is still accepted and the fixture's paraphrase gets no finding.
func TestCommentRubricRuleMinWordsBeyondSymbolDefaultUnchanged(t *testing.T) {
	unit := parseOne(t, "fns.go", `package sample

// Documented returns the rule metadata for FooRule.
func Documented() {}
`)
	findings := CommentRubricRule{RequireFunctionComments: true}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none (option disabled keeps existing behaviour)", findings)
	}
}

// TestCommentRubricRuleMinWordsBeyondSymbolRejectsRestatement confirms the substantive-token threshold rejects sparse comments.
// A comment whose non-symbol token count falls below MinWordsBeyondSymbol 3 gets one finding, reported on FooRule.Definition.
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
	findings := rule.AnalyzeProject([]parser.Unit{unit}, Context{})
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
	if findings := rule.AnalyzeProject([]parser.Unit{unit}, Context{}); len(findings) != 0 {
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
	findings := rule.AnalyzeProject([]parser.Unit{unit}, Context{})
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
	if findings := rule.AnalyzeProject([]parser.Unit{unit}, Context{}); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none (substantive group comments)", findings)
	}
}

// TestCommentRubricRuleMinWordsBeyondSymbolStopwordsRejectParaphrase confirms common English fillers do not count as substantive tokens.
// Fillers like the, for, of and is are not counted, so the paraphrase Definition returns the rule metadata for FooRule fails at N=3.
func TestCommentRubricRuleMinWordsBeyondSymbolStopwordsRejectParaphrase(t *testing.T) {
	// Only two substantive tokens survive, so N=3 rejects the comment.
	//
	//   - Symbol tokens after qualification: {foo, rule, definition}.
	//   - Comment tokens before the stopword filter: {definition, returns, the, rule, metadata, for, foo}.
	//   - After symbol subtraction: {returns, the, metadata, for}.
	//   - After stopword subtraction of the and for: {returns, metadata}, two unique tokens.
	unit := parseOne(t, "fns.go", `package sample

// Definition returns the rule metadata for FooRule.
func (FooRule) Definition() string { return "" }
`)
	rule := CommentRubricRule{
		RequireFunctionComments: true,
		MinWordsBeyondSymbol:    3,
	}
	findings := rule.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one rejection of the paraphrase boilerplate", findings)
	}
	if findings[0].Symbol != "FooRule.Definition" {
		t.Fatalf("finding = %#v, want FooRule.Definition", findings[0])
	}
}

// commentRubricTestScopingTestUnit parses the shared _test.go fixture used by const/var scoping tests.
//
// It returns the unit parsed from internal/sample/sample_test.go, never a zero unit, because parseOne stops the test on any parse failure.
// The fixture holds the uncommented const fixtureValue, var fixtureSlice, function TestSomething and type TestWorker, with no package comment.
func commentRubricTestScopingTestUnit(t *testing.T) parser.Unit {
	t.Helper()
	return parseOne(t, "internal/sample/sample_test.go", `package sample

const fixtureValue = "x"

var fixtureSlice = []int{1, 2, 3}

func TestSomething() {}

type TestWorker struct{}
`)
}

// commentRubricTestScopingProdUnit parses the production fixture paired with the _test.go scoping case.
//
// It returns the unit parsed from internal/sample/sample.go, never a zero unit, because parseOne stops the test on any parse failure.
// The fixture holds the uncommented exported const ProductionConst and unexported var productionVar, with no package comment.
func commentRubricTestScopingProdUnit(t *testing.T) parser.Unit {
	t.Helper()
	return parseOne(t, "internal/sample/sample.go", `package sample

const ProductionConst = 1

var productionVar = 2
`)
}

// TestCommentRubricRuleTestFileConstVarSkippedByDefault confirms const and var enforcement is skipped on _test.go files.
// That holds even when IgnoreTests is false, while the production fixture still gets findings for ProductionConst and productionVar.
func TestCommentRubricRuleTestFileConstVarSkippedByDefault(t *testing.T) {
	rule := CommentRubricRule{
		RequireConstComments: true,
		RequireVarComments:   true,
		IgnoreTests:          false,
	}
	if findings := rule.AnalyzeProject([]parser.Unit{commentRubricTestScopingTestUnit(t)}, Context{}); len(findings) != 0 {
		t.Fatalf("test-file const/var findings = %#v, want none", findings)
	}
	findings := rule.AnalyzeProject([]parser.Unit{commentRubricTestScopingProdUnit(t)}, Context{})
	if len(findings) != 2 {
		t.Fatalf("production findings = %#v, want ProductionConst and productionVar", findings)
	}
}

// TestCommentRubricRuleTestFileFunctionCheckStillFires confirms function
// comment enforcement on test files survives the const/var exemption.
func TestCommentRubricRuleTestFileFunctionCheckStillFires(t *testing.T) {
	rule := CommentRubricRule{
		RequireFunctionComments: true,
		IgnoreTests:             false,
	}
	findings := rule.AnalyzeProject([]parser.Unit{commentRubricTestScopingTestUnit(t)}, Context{})
	if len(findings) != 1 || findings[0].Symbol != "TestSomething" {
		t.Fatalf("findings = %#v, want one TestSomething finding", findings)
	}
}

// TestCommentRubricRuleTestFileTypeCheckStillFires confirms named-type
// enforcement on test files survives the const/var exemption.
func TestCommentRubricRuleTestFileTypeCheckStillFires(t *testing.T) {
	rule := CommentRubricRule{
		RequireNamedTypeComments: true,
		IgnoreTests:              false,
	}
	findings := rule.AnalyzeProject([]parser.Unit{commentRubricTestScopingTestUnit(t)}, Context{})
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
	if findings := rule.AnalyzeProject([]parser.Unit{commentRubricTestScopingTestUnit(t)}, Context{}); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none (whole-file exemption)", findings)
	}
}

// TestCommentRubricRuleDefaultPackageSummaryOneLine covers the default package-summary threshold.
// A single-line summary passes and a missing summary still gets a finding, while an explicit MinPackageCommentLines of 2 rejects the one-liner.
func TestCommentRubricRuleDefaultPackageSummaryOneLine(t *testing.T) {
	rule := CommentRubricRule{RequirePackageSummary: true}

	oneLine := parseOne(t, "ok.go", `// Package sample explains the maintenance boundary.
package sample
`)
	if findings := rule.AnalyzeProject([]parser.Unit{oneLine}, Context{}); len(findings) != 0 {
		t.Fatalf("one-line summary findings = %#v, want none under default threshold", findings)
	}

	missing := parseOne(t, "missing.go", `package sample
`)
	findings := rule.AnalyzeProject([]parser.Unit{missing}, Context{})
	if len(findings) != 1 || findings[0].Message != "package summary is missing" {
		t.Fatalf("missing findings = %#v, want one missing-summary finding", findings)
	}

	// Explicit MinPackageCommentLines: 2 still rejects the one-line summary.
	strict := CommentRubricRule{
		RequirePackageSummary:  true,
		MinPackageCommentLines: 2,
	}
	if findings := strict.AnalyzeProject([]parser.Unit{oneLine}, Context{}); len(findings) != 1 {
		t.Fatalf("strict one-line findings = %#v, want one threshold finding", findings)
	}
}
