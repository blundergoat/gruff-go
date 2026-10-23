// Package rule tests the two bands every size and complexity finding reports in.
// A unit just over its limit gets an advisory notice not to grow; at one and a
// half times the limit it keeps the rule's severity and the advice to split or
// simplify (FAMILY-CONTRACT.md section 12, "Size and complexity findings in two bands").
package rule

import (
	"fmt"
	"go/ast"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// bandCase builds a fixture whose measure for one rule is the given value.
type bandCase struct {
	rule        string
	lowerValue  int
	upperValue  int
	fixture     func(value int) string
	lowerAdvice string
}

// bandCases cover every gruff-go size and complexity rule just over its limit and at twice it.
func bandCases() []bandCase {
	return []bandCase{
		{"size.file-length", fileLengthThreshold + 1, 2 * fileLengthThreshold, fileOfCodeLines, lowerBandFileAdvice},
		{"size.function-length", functionLengthThreshold + 1, 2 * functionLengthThreshold, functionOfCodeLines, lowerBandFunctionAdvice},
		{"complexity.cyclomatic", cyclomaticThreshold + 1, 2 * cyclomaticThreshold, functionWithBranches(-1), lowerBandFunctionAdvice},
		{"complexity.cognitive", cognitiveComplexityThreshold + 1, 2 * cognitiveComplexityThreshold, functionWithBranches(0), lowerBandFunctionAdvice},
		{"complexity.nesting-depth", nestingDepthThreshold + 1, 2 * nestingDepthThreshold, functionNestedTo, lowerBandFunctionAdvice},
		{"size.parameter-count", parameterCountThreshold + 1, 2 * parameterCountThreshold, functionWithParameters, lowerBandParameterAdvice},
	}
}

// fileOfCodeLines returns a Go file of exactly value substantive lines.
func fileOfCodeLines(value int) string {
	var b strings.Builder
	b.WriteString("package sample\n")
	for i := 1; i < value; i++ {
		fmt.Fprintf(&b, "var v%d = %d\n", i, i)
	}
	return b.String()
}

// functionOfCodeLines returns a function of exactly value code lines, its signature and closing brace included.
func functionOfCodeLines(value int) string {
	return "package sample\n\nfunc long(n int) int {\n" + strings.Repeat("\tn++\n", value-3) + "\treturn n\n}\n"
}

// functionWithBranches returns a builder of a function with flat if statements, so that its cyclomatic complexity
// (one plus each branch) or its cognitive complexity (one per flat branch) equals the value; offset picks the measure.
func functionWithBranches(offset int) func(value int) string {
	return func(value int) string {
		return "package sample\n\nfunc branchy(a bool) {\n" + strings.Repeat("\tif a {\n\t\tprintln(1)\n\t}\n", value+offset) + "}\n"
	}
}

// functionNestedTo returns a function whose if statements nest value levels deep.
func functionNestedTo(value int) string {
	return "package sample\n\nfunc nested(a bool) {\n" + strings.Repeat("if a {\n", value) + "println(1)\n" + strings.Repeat("}\n", value) + "}\n"
}

// functionWithParameters returns a function with value int parameters.
func functionWithParameters(value int) string {
	names := make([]string, value)
	for i := range names {
		names[i] = fmt.Sprintf("p%d", i)
	}
	return "package sample\n\nfunc wide(" + strings.Join(names, ", ") + " int) {}\n"
}

// findingFor returns the one finding the named rule reports, failing when there is not exactly one.
func findingFor(t *testing.T, findings []finding.Finding, ruleID string) finding.Finding {
	t.Helper()
	var matched []finding.Finding
	for _, item := range findings {
		if item.RuleID == ruleID {
			matched = append(matched, item)
		}
	}
	if len(matched) != 1 {
		t.Fatalf("%s findings = %#v, want one", ruleID, matched)
	}
	return matched[0]
}

// definitionFor returns the default definition of one rule.
func definitionFor(t *testing.T, ruleID string) Definition {
	t.Helper()
	defaults := Defaults()
	for _, definition := range defaults.Definitions() {
		if definition.ID == ruleID {
			return definition
		}
	}
	t.Fatalf("no definition for %s", ruleID)
	return Definition{}
}

// TestEverySizeAndComplexityRuleReportsInTwoBands checks each rule just over its limit reports the advisory
// do-not-add notice, and at twice its limit reports at the rule's severity with the advice to split or simplify.
func TestEverySizeAndComplexityRuleReportsInTwoBands(t *testing.T) {
	// complexity.cyclomatic is off by default; turning it on shows its bands like any other rule's.
	defaults, err := DefaultsConfigured(Config{Enabled: map[string]bool{"complexity.cyclomatic": true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range bandCases() {
		definition := definitionFor(t, tc.rule)
		for _, band := range []struct {
			name, want, advice string
			value              int
			severity           finding.Severity
		}{
			{"just over", limitBandLower, tc.lowerAdvice, tc.lowerValue, finding.SeverityAdvisory},
			{"twice", limitBandUpper, definition.Remediation, tc.upperValue, definition.Severity},
		} {
			t.Run(tc.rule+"/"+band.name, func(t *testing.T) {
				unit := parseOne(t, "sample.go", tc.fixture(band.value))
				item := findingFor(t, defaults.Analyze([]parser.Unit{unit}, Context{}), tc.rule)
				if item.Metadata[limitBandKey] != band.want {
					t.Fatalf("limitBand = %v, want %s (metadata %#v)", item.Metadata[limitBandKey], band.want, item.Metadata)
				}
				if item.Severity != band.severity {
					t.Fatalf("severity = %s, want %s", item.Severity, band.severity)
				}
				if item.Remediation != band.advice {
					t.Fatalf("remediation = %q, want %q", item.Remediation, band.advice)
				}
				for _, banned := range []string{"helper", "raise", "threshold", "ignore", "disable"} {
					if strings.Contains(strings.ToLower(item.Remediation), banned) && !strings.Contains(item.Remediation, "Moving branches into helpers") {
						t.Fatalf("remediation %q mentions %q", item.Remediation, banned)
					}
				}
			})
		}
	}
}

// TestLowerBandIsAdvisoryEvenWhenSeverityIsConfigured checks a configured severity applies only in the upper band.
func TestLowerBandIsAdvisoryEvenWhenSeverityIsConfigured(t *testing.T) {
	registry, err := DefaultsConfigured(Config{Severities: map[string]finding.Severity{"size.function-length": finding.SeverityError}})
	if err != nil {
		t.Fatal(err)
	}
	for value, want := range map[int]finding.Severity{
		functionLengthThreshold + 1: finding.SeverityAdvisory,
		2 * functionLengthThreshold: finding.SeverityError,
	} {
		unit := parseOne(t, "sample.go", functionOfCodeLines(value))
		item := findingFor(t, registry.Analyze([]parser.Unit{unit}, Context{}), "size.function-length")
		if item.Severity != want {
			t.Fatalf("%d code lines: severity = %s, want %s", value, item.Severity, want)
		}
	}
}

// TestBandBoundaryComparesWithoutRounding pins the boundary at exactly one and a half times the limit.
func TestBandBoundaryComparesWithoutRounding(t *testing.T) {
	for _, tc := range []struct {
		value, limit int
		want         string
	}{
		{119, 80, limitBandLower},
		{120, 80, limitBandUpper},
		{37, 25, limitBandLower},
		{38, 25, limitBandUpper},
		{12, 8, limitBandUpper},
		{11, 8, limitBandLower},
	} {
		if got := limitBand(tc.value, tc.limit); got != tc.want {
			t.Fatalf("limitBand(%d, %d) = %s, want %s", tc.value, tc.limit, got, tc.want)
		}
	}
}

// TestTestFileSizeFindingsStayAdvisoryInBothBands checks gruff-go's test-file softening keeps an upper-band
// test function advisory at medium confidence, while the band key and advice still follow the band.
func TestTestFileSizeFindingsStayAdvisoryInBothBands(t *testing.T) {
	defaults := Defaults()
	for value, want := range map[int]string{functionLengthThreshold + 1: limitBandLower, 2 * functionLengthThreshold: limitBandUpper} {
		unit := parseOne(t, "sample_test.go", functionOfCodeLines(value))
		item := findingFor(t, defaults.Analyze([]parser.Unit{unit}, Context{}), "size.function-length")
		if item.Severity != finding.SeverityAdvisory || item.Confidence != finding.ConfidenceMedium {
			t.Fatalf("%d code lines: severity/confidence = %s/%s, want advisory/medium", value, item.Severity, item.Confidence)
		}
		if item.Metadata[limitBandKey] != want {
			t.Fatalf("%d code lines: limitBand = %v, want %s", value, item.Metadata[limitBandKey], want)
		}
	}
}

// TestFileLengthIgnoresDataFiles checks a long JSON file reports nothing while a long Go file still reports.
func TestFileLengthIgnoresDataFiles(t *testing.T) {
	data := parser.Unit{
		File:      source.File{Path: "fixtures/data.json", Type: source.FileTypeText},
		LineCount: 1600,
		Source:    strings.Repeat("{\"key\": \"value\"},\n", 1600),
	}
	if got := (FileLengthRule{}).AnalyzeUnit(data, Context{}); len(got) != 0 {
		t.Fatalf("data file findings = %#v, want none", got)
	}
	code := parseOne(t, "sample.go", fileOfCodeLines(fileLengthThreshold+100))
	if got := (FileLengthRule{}).AnalyzeUnit(code, Context{}); len(got) != 1 {
		t.Fatalf("Go file findings = %#v, want one", got)
	}
}

// keyedCallsFixture is GO-09's shape: twelve calls, each passing a keyed request struct over five lines.
const keyedCallsFixture = `package sample

type Request struct {
	URL     string
	Method  string
	Retries int
	Timeout int
}

func fetch(ctx int, r Request) error { return nil }

func sequentialFetch(ctx int) error {
` + "%s" + `	return nil
}
`

// keyedCall is one call of GO-09's shape: eight lines, five of them inside the keyed literal after its opening line.
const keyedCall = `	if err := fetch(ctx, Request{
		URL:     "https://example.test",
		Method:  "GET",
		Retries: 3,
		Timeout: 5,
	}); err != nil {
		return err
	}
`

// TestFunctionLengthCountsKeyedLiteralArgumentAsOneLine checks a keyed literal passed to a call counts as one line,
// so GO-09's flat function of twelve calls drops from 99 code lines to 39 and leaves the rule.
func TestFunctionLengthCountsKeyedLiteralArgumentAsOneLine(t *testing.T) {
	for _, path := range []string{"fetch.go", "fetch_test.go"} {
		unit := parseOne(t, path, fmt.Sprintf(keyedCallsFixture, strings.Repeat(keyedCall, 12)))
		if got := (FunctionLengthRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
			t.Fatalf("%s: findings = %#v, want none at the default limit", path, got)
		}
		got := (FunctionLengthRule{MaxLines: 30}).AnalyzeUnit(unit, Context{})
		if len(got) != 1 || got[0].Metadata["lines"] != 39 || got[0].Metadata["literalArgumentLines"] != 60 || got[0].Metadata["rawLines"] != 99 {
			t.Fatalf("%s: findings = %#v, want 39 lines after a 60-line literal discount", path, got)
		}
	}
}

// TestFunctionLengthStillReportsDistinctStatements checks the discount leaves a long run of real statements reported.
func TestFunctionLengthStillReportsDistinctStatements(t *testing.T) {
	unit := parseOne(t, "steps.go", "package sample\n\nfunc steps(n int) int {\n"+strings.Repeat("\tn += n * 2\n", 85)+"\treturn n\n}\n")
	got := (FunctionLengthRule{}).AnalyzeUnit(unit, Context{})
	if len(got) != 1 || got[0].Metadata["lines"] != 88 {
		t.Fatalf("findings = %#v, want one finding of 88 code lines", got)
	}
	if _, discounted := got[0].Metadata["literalArgumentLines"]; discounted {
		t.Fatalf("metadata = %#v, want no literal discount", got[0].Metadata)
	}
}

// TestKeyedLiteralInsideTestTableIsNotDiscountedTwice checks a keyed literal call inside an assigned test table
// is counted once, by the table discount.
func TestKeyedLiteralInsideTestTableIsNotDiscountedTwice(t *testing.T) {
	unit := parseOne(t, "table_test.go", `package sample

type Request struct {
	URL    string
	Method string
}

func build(r Request) Request { return r }

func TestTable(t int) {
	tests := []struct{ in Request }{
		{in: build(Request{
			URL:    "a",
			Method: "GET",
		})},
		{in: build(Request{
			URL:    "b",
			Method: "POST",
		})},
	}
	for range tests {
		t++
	}
}
`)
	got := (FunctionLengthRule{MaxLines: 3}).AnalyzeUnit(unit, Context{})
	if len(got) != 1 {
		t.Fatalf("findings = %#v, want one", got)
	}
	if _, discounted := got[0].Metadata["literalArgumentLines"]; discounted {
		t.Fatalf("metadata = %#v, want the table discount alone", got[0].Metadata)
	}
	if got[0].Metadata["tableFixtureLines"] != 10 || got[0].Metadata["lines"] != 5 {
		t.Fatalf("metadata = %#v, want 10 table lines discounted from 15", got[0].Metadata)
	}
}

// TestComplexityRulesSkipFlatDispatchAndTestFiles pins M14's bounded repairs: a switch over many flat cases
// is one decision, a test file is not measured, and a function of real branches still reports.
func TestComplexityRulesSkipFlatDispatchAndTestFiles(t *testing.T) {
	var dispatch strings.Builder
	dispatch.WriteString("package sample\n\nfunc dispatch(kind int) int {\n\tswitch kind {\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&dispatch, "\tcase %d:\n\t\treturn %d\n", i, i*2)
	}
	dispatch.WriteString("\t}\n\treturn -1\n}\n")
	branchy := functionWithBranches(-1)(2 * cyclomaticThreshold)
	for _, tc := range []struct {
		name, path, source string
		want               int
	}{
		{"flat dispatch", "dispatch.go", dispatch.String(), 0},
		{"branchy function", "branchy.go", branchy, 1},
		{"branchy test function", "branchy_test.go", branchy, 0},
	} {
		unit := parseOne(t, tc.path, tc.source)
		if got := (CyclomaticComplexityRule{}).AnalyzeUnit(unit, Context{}); len(got) != tc.want {
			t.Fatalf("%s: cyclomatic findings = %#v, want %d", tc.name, got, tc.want)
		}
		if tc.name != "flat dispatch" {
			if got := (CognitiveComplexityRule{}).AnalyzeUnit(unit, Context{}); len(got) != tc.want {
				t.Fatalf("%s: cognitive findings = %#v, want %d", tc.name, got, tc.want)
			}
		}
	}
}

// TestCognitiveComplexitySoftensDispatchAndGuards pins the two cognitive shapes M14 softened, and that nested
// logic still pays its nesting penalty.
func TestCognitiveComplexitySoftensDispatchAndGuards(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"guard in a loop pays no nesting penalty", "for {\n\tif a {\n\t\tcontinue\n\t}\n\tif b {\n\t\tbreak\n\t}\n}", 3},
		{"case bodies keep the switch's nesting", "switch {\ncase a:\n\tif b {\n\t\tprintln(1)\n\t}\n}", 2},
		{"nested logic still pays", "if a {\n\tfor {\n\t\tif b {\n\t\t\tprintln(1)\n\t\t}\n\t}\n}", 6},
		{"a guard with an else is not a guard, so it keeps its nesting penalty", "for {\n\tif a {\n\t\treturn\n\t} else {\n\t\tprintln(1)\n\t}\n}", 3},
	} {
		unit := parseOne(t, "shape.go", "package sample\n\nfunc shape(a, b bool) {\n"+tc.body+"\n}\n")
		fn := unit.AST.Decls[0].(*ast.FuncDecl)
		if got := cognitiveComplexity(fn); got != tc.want {
			t.Fatalf("%s: cognitive complexity = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestPackageVarFunctionLiteralIsMeasuredBySizeAndComplexityOnly checks a function literal assigned to a package-level
// var is a unit for the size and complexity rules, named after the var, and that no other rule reports on it.
func TestPackageVarFunctionLiteralIsMeasuredBySizeAndComplexityOnly(t *testing.T) {
	nested := strings.Repeat("\tif seed > 0 {\n", nestingDepthThreshold+1) + "\t\tseed++\n" + strings.Repeat("\t}\n", nestingDepthThreshold+1)
	source := "// Package sample holds one long function literal.\npackage sample\n\n// Mix folds a fixed sequence of offsets into seed.\nvar Mix = func(seed int) int {\n" +
		strings.Repeat("\tseed++\n", functionLengthThreshold) + nested + "\treturn seed\n}\n"
	unit := parseOne(t, "sample.go", source)
	if len(unit.Functions) != 1 || unit.Functions[0].Name != "Mix" || unit.Functions[0].Line != 5 {
		t.Fatalf("functions = %#v, want Mix starting on line 5", unit.Functions)
	}
	defaults := Defaults()
	reported := map[string]bool{}
	for _, item := range defaults.Analyze([]parser.Unit{unit}, Context{}) {
		if item.Symbol != "Mix" {
			continue
		}
		if !strings.HasPrefix(item.RuleID, "size.") && !strings.HasPrefix(item.RuleID, "complexity.") {
			t.Fatalf("%s reports on the literal; only size and complexity rules may: %#v", item.RuleID, item)
		}
		reported[item.RuleID] = true
	}
	for _, ruleID := range []string{"size.function-length", "complexity.nesting-depth"} {
		if !reported[ruleID] {
			t.Fatalf("%s did not measure Mix; reported %v", ruleID, reported)
		}
	}
}
