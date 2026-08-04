// Package rule tests structural metrics shown in gruff-go scan results.
// These fixtures connect parameter, nesting, and documentation findings to fixes.
// Nested Go syntax stays parser-owned so users do not see truncated signatures.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestParameterCountRule verifies the parameter-count threshold and metadata payload.
func TestParameterCountRule(t *testing.T) {
	unit := parseOne(t, "sample.go", `package sample

type Builder struct{}

func Wide(a, b, c, d, e, f, g, h, i int) {}

func Narrow(a, b, c int) {}

func (Builder) Many(a, b, c, d, e int) {}
`)
	findings := ParameterCountRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "Wide" {
		t.Fatalf("findings = %#v, want one finding on Wide", findings)
	}
	if findings[0].Metadata["parameters"] != 9 {
		t.Fatalf("metadata = %#v, want parameters=9", findings[0].Metadata)
	}

	below := ParameterCountRule{MaxParameters: 9}.AnalyzeUnit(unit, Context{})
	if len(below) != 0 {
		t.Fatalf("threshold-9 findings = %#v, want none", below)
	}

	defaults := Defaults()
	if findings := defaults.Analyze([]parser.Unit{unit}, Context{}); !containsRuleID(findings, "size.parameter-count") {
		t.Fatalf("default scan = %#v, want size.parameter-count enabled", findings)
	}
}

// TestParameterCountHandlesNestedSignatureSyntax proves generic, function-typed,
// and grouped parameters stay balanced and that an options type clears the result.
func TestParameterCountHandlesNestedSignatureSyntax(t *testing.T) {
	driftUnit := parseOne(t, "signature.go", `package sample

func Transform[T ~int](x func(int) error, y, z string, value T) error {
	return x(int(value))
}
`)
	findings := (ParameterCountRule{MaxParameters: 3}).AnalyzeUnit(driftUnit, Context{})
	// The nested function type counts once while grouped y and z count separately.
	if len(findings) != 1 || findings[0].Symbol != "Transform" || findings[0].Metadata["parameters"] != 4 {
		t.Fatalf("nested-signature findings = %#v, want Transform with four parameters", findings)
	}

	fixedUnit := parseOne(t, "signature.go", `package sample

type TransformOptions[T ~int] struct {
	Y, Z  string
	Value T
}

func Transform[T ~int](x func(int) error, options TransformOptions[T]) error {
	return x(int(options.Value))
}
`)
	fixedFindings := (ParameterCountRule{MaxParameters: 3}).AnalyzeUnit(fixedUnit, Context{})
	// Grouping related values into options clears the finding as the UI instructs.
	if len(fixedFindings) != 0 {
		t.Fatalf("options remediation findings = %#v, want none", fixedFindings)
	}

	definition := (ParameterCountRule{}).Definition()
	// Catalogue guidance must explain fixed API signatures that users cannot reshape.
	if len(definition.FalsePositiveShapes) == 0 || definition.FalsePositiveShapes[0].Mitigation == "" {
		t.Fatalf("parameter-count false-positive guidance = %#v", definition.FalsePositiveShapes)
	}
}

// TestNestingDepthRule covers deep/shallow/func-lit nesting cases for the rule.
func TestNestingDepthRule(t *testing.T) {
	deep := parseOne(t, "deep.go", `package sample

func Deep(a, b, c bool) {
	if a {
		if b {
			if c {
				for i := 0; i < 10; i++ {
					if i > 0 {
						if i < 5 {
							_ = i
						}
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
	if findings[0].Metadata["depth"] != 6 {
		t.Fatalf("metadata = %#v, want depth=6", findings[0].Metadata)
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

	defaults := Defaults()
	if findings := defaults.Analyze([]parser.Unit{deep}, Context{}); !containsRuleID(findings, "complexity.nesting-depth") {
		t.Fatalf("default scan = %#v, want complexity.nesting-depth enabled", findings)
	}
}

// TestExportedSymbolCommentRule verifies which exported declarations get flagged.
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

	defaults := Defaults()
	if findings := defaults.Analyze([]parser.Unit{unit}, Context{}); !containsRuleID(findings, "docs.exported-symbol-comment") {
		t.Fatalf("default scan = %#v, want docs.exported-symbol-comment enabled", findings)
	}
}

// TestExportedSymbolCommentRuleCanIgnoreInternalPackages exercises the ignoreInternalPackages=true option, asserting an internal/service export is silenced while a public pkg/api export still surfaces.
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

// TestExportedSymbolCommentRuleCanIncludeInternalPackages exercises ignoreInternalPackages=false, asserting an undocumented internal/service export does report a finding once the opt-out is disabled.
func TestExportedSymbolCommentRuleCanIncludeInternalPackages(t *testing.T) {
	internalUnit := parseOne(t, "internal/service/service.go", `package service

func VisibleInsideModule() {}
`)
	registry, err := DefaultsConfigured(Config{
		Enabled: map[string]bool{"docs.exported-symbol-comment": true, "docs.package-comment": false},
		Options: map[string]map[string]any{
			"docs.exported-symbol-comment": {"ignoreInternalPackages": false},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings := registry.Analyze([]parser.Unit{internalUnit}, Context{})
	if !containsRuleID(findings, "docs.exported-symbol-comment") {
		t.Fatalf("findings = %#v, want internal export included when option is false", findings)
	}
}

// containsRuleID reports whether any finding in the slice has the given rule ID.
func containsRuleID(findings []finding.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
