package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

func TestParameterCountRule(t *testing.T) {
	unit := parseOne(t, "sample.go", `package sample

type Builder struct{}

func Wide(a, b, c, d, e, f int) {}

func Narrow(a, b, c int) {}

func (Builder) Many(a, b, c, d, e int) {}
`)
	findings := ParameterCountRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "Wide" {
		t.Fatalf("findings = %#v, want one finding on Wide", findings)
	}
	if findings[0].Metadata["parameters"] != 6 {
		t.Fatalf("metadata = %#v, want parameters=6", findings[0].Metadata)
	}

	below := ParameterCountRule{MaxParameters: 6}.AnalyzeUnit(unit, Context{})
	if len(below) != 0 {
		t.Fatalf("threshold-6 findings = %#v, want none", below)
	}

	if findings := (Defaults().Analyze([]parser.Unit{unit}, Context{})); containsRuleID(findings, "size.parameter-count") {
		t.Fatalf("default scan = %#v, want size.parameter-count disabled", findings)
	}
}

func TestNestingDepthRule(t *testing.T) {
	deep := parseOne(t, "deep.go", `package sample

func Deep(a, b, c bool) {
	if a {
		if b {
			if c {
				for i := 0; i < 10; i++ {
					if i > 0 {
						_ = i
					}
				}
			}
		}
	}
}
`)
	findings := NestingDepthRule{}.AnalyzeUnit(deep, Context{})
	if len(findings) != 1 || findings[0].Symbol != "Deep" {
		t.Fatalf("findings = %#v, want one finding on Deep", findings)
	}
	if findings[0].Metadata["depth"] != 5 {
		t.Fatalf("metadata = %#v, want depth=5", findings[0].Metadata)
	}

	shallow := parseOne(t, "shallow.go", `package sample

func Shallow(a, b bool) {
	if a {
		if b {
			_ = a
		}
	}
}
`)
	if findings := (NestingDepthRule{}.AnalyzeUnit(shallow, Context{})); len(findings) != 0 {
		t.Fatalf("shallow findings = %#v, want none", findings)
	}

	withLit := parseOne(t, "lit.go", `package sample

func Outer() {
	f := func() {
		if true {
			if true {
				if true {
					if true {
						if true {
							_ = 1
						}
					}
				}
			}
		}
	}
	_ = f
}
`)
	if findings := (NestingDepthRule{}.AnalyzeUnit(withLit, Context{})); len(findings) != 0 {
		t.Fatalf("func-lit findings = %#v, want outer counted independently of literal", findings)
	}

	if findings := (Defaults().Analyze([]parser.Unit{deep}, Context{})); containsRuleID(findings, "complexity.nesting-depth") {
		t.Fatalf("default scan = %#v, want complexity.nesting-depth disabled", findings)
	}
}

func TestExportedSymbolCommentRule(t *testing.T) {
	unit := parseOne(t, "sample.go", `package sample

// Documented does a thing.
func Documented() {}

func Undocumented() {}

// helper is unexported but documented.
func helper() {}

func unexported() {}

// Greeter does greetings.
type Greeter struct{}

type Plain struct{}

type priv struct{}

// Hello says hi.
func (Greeter) Hello() {}

func (Greeter) Skip() {}

func (Plain) Quiet() {}

func (priv) Stuff() {}

// MaxRetries caps retries.
const MaxRetries = 3

const Timeout = 5

var Buffer = 16
`)
	findings := ExportedSymbolCommentRule{}.AnalyzeUnit(unit, Context{})
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Symbol] = true
	}
	want := []string{"Undocumented", "Plain", "Greeter.Skip", "Plain.Quiet", "Timeout", "Buffer"}
	if len(got) != len(want) {
		t.Fatalf("findings = %#v, want %d symbols: %v", findings, len(want), want)
	}
	for _, name := range want {
		if !got[name] {
			t.Fatalf("findings = %#v, missing %s", findings, name)
		}
	}
	for _, ignored := range []string{"Documented", "helper", "unexported", "Greeter", "Greeter.Hello", "MaxRetries", "priv", "priv.Stuff"} {
		if got[ignored] {
			t.Fatalf("findings = %#v, must not include %s", findings, ignored)
		}
	}

	testFile := parseOne(t, "sample_test.go", `package sample

func ExportedTestHelper() {}
`)
	if findings := (ExportedSymbolCommentRule{}.AnalyzeUnit(testFile, Context{})); len(findings) != 0 {
		t.Fatalf("test-file findings = %#v, want none", findings)
	}

	if findings := (Defaults().Analyze([]parser.Unit{unit}, Context{})); containsRuleID(findings, "docs.exported-symbol-comment") {
		t.Fatalf("default scan = %#v, want docs.exported-symbol-comment disabled", findings)
	}
}

func TestExportedSymbolCommentRuleCanIgnoreInternalPackages(t *testing.T) {
	internalUnit := parseOne(t, "internal/service/service.go", `package service

func VisibleInsideModule() {}
`)
	publicUnit := parseOne(t, "pkg/api/api.go", `package api

func VisibleOutsideModule() {}
`)
	registry, err := DefaultsConfigured(Config{
		Enabled: map[string]bool{"docs.exported-symbol-comment": true, "docs.package-comment": false},
		Options: map[string]map[string]any{
			"docs.exported-symbol-comment": {"ignoreInternalPackages": true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings := registry.Analyze([]parser.Unit{internalUnit, publicUnit}, Context{})
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Symbol] = true
	}
	if got["VisibleInsideModule"] {
		t.Fatalf("findings = %#v, want internal export ignored", findings)
	}
	if !got["VisibleOutsideModule"] || len(got) != 1 {
		t.Fatalf("findings = %#v, want only public package export", findings)
	}
}

func containsRuleID(findings []finding.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
