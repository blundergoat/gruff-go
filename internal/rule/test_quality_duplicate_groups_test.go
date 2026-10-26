package rule

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestDuplicateTestBodyGroups preserves complete groups and source-order anchors.
func TestDuplicateTestBodyGroups(t *testing.T) {
	unit := parseOne(t, "groups_test.go", `package sample
import "testing"
func TestZulu(t *testing.T) { setup(t); warm(t); got := parse("a"); check(got, 1) }
func TestOtherA(t *testing.T) { setup(t); warm(t); got := build("a"); check(got, 1) }
func TestAlpha(t *testing.T) { setup(t); warm(t); got := parse("b"); check(got, 2) }
func TestOtherB(t *testing.T) { setup(t); warm(t); got := build("b"); check(got, 2) }
func TestMiddle(t *testing.T) { setup(t); warm(t); got := parse("c"); check(got, 3) }
func TestOtherC(t *testing.T) { setup(t); warm(t); got := build("c"); check(got, 3) }
func TestLast(t *testing.T) { setup(t); warm(t); got := parse("d"); check(got, 4) }
func TestOtherD(t *testing.T) { setup(t); warm(t); got := build("d"); check(got, 4) }
func TestTail(t *testing.T) { setup(t); warm(t); got := parse("e"); check(got, 5) }
`)
	got := (DuplicateTestBodyRule{}).AnalyzeUnit(unit, Context{})
	wantNames := [][]string{{"TestZulu", "TestAlpha", "TestMiddle", "TestLast", "TestTail"}, {"TestOtherA", "TestOtherB", "TestOtherC", "TestOtherD"}}
	wantLines := [][]int{{3, 5, 7, 9, 11}, {4, 6, 8, 10}}
	if len(got) != len(wantNames) {
		t.Fatalf("groups = %#v, want two complete groups", got)
	}
	for i, names := range wantNames {
		if !strings.Contains(got[i].Message, "Go table-driven case loop with a descriptive label per case") {
			t.Errorf("message omits labelled case advice: %q", got[i].Message)
		}
		wantMembers := make([]map[string]any, len(names))
		for j, name := range names {
			wantMembers[j] = map[string]any{"symbol": name, "line": wantLines[i][j], "column": 6}
			label := fmt.Sprintf("%s (line %d, column 6)", name, wantLines[i][j])
			if !strings.Contains(got[i].Message, label) {
				t.Errorf("message %q omits %q", got[i].Message, label)
			}
		}
		wantLocation := &finding.Location{Line: wantLines[i][0], Column: 6}
		if got[i].File != "groups_test.go" || got[i].Symbol != names[0] || !reflect.DeepEqual(got[i].Location, wantLocation) {
			t.Errorf("group anchor = %#v, want %s at %#v", got[i], names[0], wantLocation)
		}
		if got[i].Metadata["groupSize"] != len(names) || !reflect.DeepEqual(got[i].Metadata["members"], wantMembers) {
			t.Errorf("metadata = %#v, want %d members: %#v", got[i].Metadata, len(names), wantMembers)
		}
	}
}

// TestDuplicateTestBodyNormalization protects value-sensitive literals and structural differences.
func TestDuplicateTestBodyNormalization(t *testing.T) {
	cases := []struct {
		name   string
		first  string
		third  string
		groups int
	}{
		{"numbers and strings", `got := parse("one"); check(got, 1)`, `got := parse("three"); check(got, 3)`, 1},
		{"booleans", `got := parse(true); check(got)`, `got := parse(false); check(got)`, 1},
		{"runes", `got := parse('a'); check(got)`, `got := parse('z'); check(got)`, 1},
		{"literal kinds", `got := parse(1); check(got)`, `got := parse(1.0); check(got)`, 0},
		{"string versus rune", `got := parse("a"); check(got)`, `got := parse('a'); check(got)`, 0},
		{"nil versus boolean", `got := parse(nil); check(got)`, `got := parse(false); check(got)`, 0},
		{"boolean versus identifier", `got := parse(true); check(got)`, `got := parse(boolean); check(got)`, 0},
		{"shadowed boolean", `true := 1; check(true)`, `false := 2; check(false)`, 0},
		{"whitespace string", `got := parse("a b"); check(got)`, `got := parse("a c"); check(got)`, 0},
		{"decoded whitespace", `got := parse("a\tb"); check(got)`, "got := parse(`a\tb`); check(got)", 1},
		{"non ASCII whitespace", `got := parse("a\u00a0b"); check(got)`, `got := parse("c\u00a0d"); check(got)`, 1},
		{"map keys", `got := map[string]int{"a": 1}; check(got)`, `got := map[string]int{"b": 2}; check(got)`, 0},
		{"nested key expression", `got := map[int]int{choose(1): 7}; check(got)`, `got := map[int]int{choose(2): 7}; check(got)`, 0},
		{"map values", `got := map[string]int{"a": 1}; check(got)`, `got := map[string]int{"a": 2}; check(got)`, 1},
		{"struct keys", `got := item{Left: 1}; check(got)`, `got := item{Right: 2}; check(got)`, 0},
		{"index expression", `got := items[choose(1)]; check(got)`, `got := items[choose(2)]; check(got)`, 0},
		{"slice low", `got := items[1:5]; check(got)`, `got := items[2:5]; check(got)`, 0},
		{"slice high", `got := items[:3]; check(got)`, `got := items[:4]; check(got)`, 0},
		{"slice max", `got := items[1:3:5]; check(got)`, `got := items[1:3:6]; check(got)`, 0},
		{"callee", `got := parse(1); check(got)`, `got := build(2); check(got)`, 0},
		{"identifier", `got := parse(1); check(got)`, `result := parse(2); check(result)`, 0},
		{"operator", `got := value + 1; check(got)`, `got := value - 2; check(got)`, 0},
		{"assertion order", `checkLeft(1); checkRight(2)`, `checkRight(3); checkLeft(4)`, 0},
		{"comments and formatting", "got := parse(1)\ncheck(got)", "/* setup */ got:=parse(3); /* assert */ check(got)", 1},
		{"local type struct tag", "type row struct { A int `json:\"a\"` }; check(row{})", "type row struct { A int `json:\"b\"` }; check(row{})", 0},
		{"local type array length", `type window [3]int; check(window{})`, `type window [4]int; check(window{})`, 0},
		{"local type with varying values", `type row struct{ A int }; check(row{A: 1})`, `type row struct{ A int }; check(row{A: 3})`, 1},
		{"local constant", `const limit = 1; check(limit)`, `const limit = 3; check(limit)`, 1},
		{"one statement", `check(1)`, `check(2)`, 0},
		{"empty statement", `; check(1)`, `; check(2)`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := duplicateTestSource("testing", "Test", "*testing.T", []string{tc.first, tc.first, tc.first, tc.third})
			unit := parseOne(t, "sample_test.go", source)
			got := (DuplicateTestBodyRule{}).AnalyzeUnit(unit, Context{})
			if len(got) != tc.groups {
				t.Fatalf("groups = %#v, want %d", got, tc.groups)
			}
		})
	}
}

// TestDuplicateTestBodyDiscovery accepts only runnable tests in the same test file.
func TestDuplicateTestBodyDiscovery(t *testing.T) {
	cases := []struct {
		name, path, imported, prefix, param string
		count, groups                       int
	}{
		{"tests", "sample_test.go", "testing", "Test", "*testing.T", 4, 1},
		{"aliased import", "sample_test.go", `testlib "testing"`, "Test", "*testlib.T", 4, 1},
		{"dot import", "sample_test.go", `. "testing"`, "Test", "*T", 4, 1},
		{"pair", "sample_test.go", "testing", "Test", "*testing.T", 2, 0},
		{"triple", "sample_test.go", "testing", "Test", "*testing.T", 3, 0},
		{"five tests", "sample_test.go", "testing", "Test", "*testing.T", 5, 1},
		{"production file", "sample.go", "testing", "Test", "*testing.T", 4, 0},
		{"benchmarks", "sample_test.go", "testing", "Benchmark", "*testing.B", 4, 0},
		{"fuzz targets", "sample_test.go", "testing", "Fuzz", "*testing.F", 4, 0},
		{"main signature", "sample_test.go", "testing", "TestMain", "*testing.M", 4, 0},
		{"lowercase suffix", "sample_test.go", "testing", "Testhelper", "*testing.T", 4, 0},
		{"wrong package", "sample_test.go", "other", "Test", "*other.T", 4, 0},
		{"methods", "sample_test.go", "testing", "(s *suite) Test", "*testing.T", 4, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bodies := make([]string, tc.count)
			for i := range bodies {
				bodies[i] = fmt.Sprintf("got := parse(%d); check(got)", i)
			}
			unit := parseOne(t, tc.path, duplicateTestSource(tc.imported, tc.prefix, tc.param, bodies))
			if got := (DuplicateTestBodyRule{}).AnalyzeUnit(unit, Context{}); len(got) != tc.groups {
				t.Fatalf("groups = %#v, want %d", got, tc.groups)
			}
		})
	}
	for _, name := range []string{"first_test.go", "second_test.go", "third_test.go"} {
		unit := parseOne(t, name, duplicateTestSource("testing", "Test", "*testing.T", []string{"got := parse(1); check(got)"}))
		if got := (DuplicateTestBodyRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
			t.Fatalf("one test in %s joined another file: %#v", name, got)
		}
	}
}

// TestDuplicateTestBodyCaseLoops keeps existing tables out without exempting unrelated loops.
func TestDuplicateTestBodyCaseLoops(t *testing.T) {
	cases := []struct {
		name, body string
		groups     int
	}{
		{"local slice", `cases := []int{1, 2}; for _, c := range cases { check(c) }`, 0},
		{"local map", `var cases = map[string]int{"a": 1}; for _, c := range cases { check(c) }`, 0},
		{"inline table", `setup(); for _, c := range []int{1, 2} { check(c) }`, 0},
		{"address of array", `setup(); for _, c := range (&[2]int{1, 2}) { check(c) }`, 0},
		{"helper subtests", `cases := loadCases(); for _, c := range cases { t.Run(c.name, c.run) }`, 0},
		{"counted subtests", `setup(); for i := 0; i < 3; i++ { t.Run(name(i), run) }`, 0},
		{"non table loop", `cases := loadCases(); for _, c := range cases { check(c) }`, 1},
		{"reassigned table", `cases := []int{1}; cases = loadCases(); for _, c := range cases { check(c) }`, 1},
		{"conditional table", `cases := loadCases(); if condition { cases = []int{1} }; for _, c := range cases { check(c) }`, 1},
		{"unrelated receiver", `setup(); for i := 0; i < 3; i++ { worker.Run(i) }`, 1},
		{"shadowed receiver", `setup(); for i := 0; i < 3; i++ { t := worker; t.Run(i) }`, 1},
		{"unused closure", `helper := func() { for _, c := range []int{1} { check(c) } }; check(helper)`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unit := parseOne(t, "loops_test.go", duplicateTestSource("testing", "Test", "*testing.T", []string{tc.body, tc.body, tc.body, tc.body}))
			if got := (DuplicateTestBodyRule{}).AnalyzeUnit(unit, Context{}); len(got) != tc.groups {
				t.Fatalf("groups = %#v, want %d", got, tc.groups)
			}
		})
	}
}

// TestDuplicateTestBodyTableBindings protects table variants and unrelated-loop counterexamples.
func TestDuplicateTestBodyTableBindings(t *testing.T) {
	cases := []struct {
		name, declarations, body string
		groups                   int
	}{
		{"parenthesized range", "", `cases := []int{1, 2}; for _, c := range (cases) { t.Log(c) }`, 0},
		{"indexed table", "", `cases := []int{1, 2}; for i := 0; i < len(cases); i++ { t.Log(cases[i]) }`, 0},
		{"parenthesized index operands", "", `cases := []int{1, 2}; for i := 0; i < len((cases)); i++ { t.Log((cases)[(i)]) }`, 0},
		{"integer range", "", `cases := []int{1, 2}; for i := range len(cases) { t.Log(cases[i]) }`, 0},
		{"package table", "var cases = []int{1, 2}", `t.Log("start"); for _, c := range cases { t.Log(c) }`, 0},
		{"package indexed table", "var cases = []int{1, 2}", `t.Log("start"); for i := 0; i < len(cases); i++ { t.Log(cases[i]) }`, 0},
		{"package table reassigned", "var cases = []int{1, 2}", `cases = loadCases(); for _, c := range cases { t.Log(c) }`, 1},
		{"unrelated counted loop", "", `cases := []int{1, 2}; for i := 0; i < len(cases); i++ { t.Log(i) }`, 1},
		{"unrelated integer range", "", `cases := []int{1, 2}; for i := range len(cases) { t.Log(i) }`, 1},
		{"shadowed counter", "", `cases := []int{1, 2}; for i := 0; i < len(cases); i++ { i := value; t.Log(cases[i]) }`, 1},
		{"shadowed table", "", `cases := []int{1, 2}; for i := 0; i < len(cases); i++ { cases := loadCases(); t.Log(cases[i]) }`, 1},
		{"shadowed length", "", `len := length; cases := []int{1, 2}; for i := 0; i < len(cases); i++ { t.Log(cases[i]) }`, 1},
		{"unused indexed closure", "", `cases := []int{1, 2}; for i := 0; i < len(cases); i++ { helper := func() { t.Log(cases[i]) }; t.Log(helper) }`, 1},
		{"string is not a table", "", `cases := "abc"; for i := 0; i < len(cases); i++ { t.Log(cases[i]) }`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := duplicateTestSource("testing", "Test", "*testing.T", []string{tc.body, tc.body, tc.body, tc.body})
			source += tc.declarations + "\n"
			unit := parseOne(t, "tables_test.go", source)
			if got := (DuplicateTestBodyRule{}).AnalyzeUnit(unit, Context{}); len(got) != tc.groups {
				t.Fatalf("groups = %#v, want %d", got, tc.groups)
			}
		})
	}
}

// TestDuplicateTestBodyOptIn verifies configured dispatch and native finding metadata.
func TestDuplicateTestBodyOptIn(t *testing.T) {
	unit := parseOne(t, "opt_in_test.go", duplicateTestSource("testing", "Test", "*testing.T", []string{
		"got := parse(1); check(got)", "got := parse(2); check(got)", "got := parse(3); check(got)",
		"got := parse(4); check(got)",
	}))
	const id = "test-quality.duplicate-test-body"
	for _, enabled := range []bool{false, true} {
		registry, err := DefaultsConfigured(Config{Enabled: map[string]bool{id: enabled}})
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, got := range registry.Analyze([]parser.Unit{unit}, Context{}) {
			if got.RuleID != id {
				continue
			}
			count++
			if got.Severity != finding.SeverityAdvisory || got.Confidence != finding.ConfidenceLow || !strings.HasPrefix(got.Remediation, "Go table-driven case loop:") {
				t.Errorf("native metadata = %#v", got)
			}
		}
		if (count == 1) != enabled || count > 1 {
			t.Errorf("enabled %v: got %d groups", enabled, count)
		}
	}
}

// duplicateTestPrelude opens every generated body with two neutral statements, so a two-statement case body
// meets the four-statement Go minimum while a one-statement body stays below it.
const duplicateTestPrelude = "setup(t); warm(t); "

// duplicateTestSource keeps discovery fixtures consistent while varying runnable signatures.
func duplicateTestSource(imported, prefix, param string, bodies []string) string {
	if !strings.Contains(imported, `"`) {
		imported = fmt.Sprintf("%q", imported)
	}
	var source strings.Builder
	fmt.Fprintf(&source, "package sample\nimport %s\n", imported)
	for i, body := range bodies {
		fmt.Fprintf(&source, "func %s%c(t %s) { %s%s }\n", prefix, 'A'+i, param, duplicateTestPrelude, body)
	}
	return source.String()
}
