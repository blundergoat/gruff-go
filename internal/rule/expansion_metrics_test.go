// Package rule tests the parameter-count, nesting-depth and exported-symbol doc findings that gruff-go analyse reports.
//
// These fixtures connect parameter, nesting and documentation findings to fixes, and pin the message that lists what a doc must describe.
// Nested Go syntax stays parser-owned, so users never see a truncated generic or function-typed signature.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestParameterCountRule verifies the parameter-count threshold and metadata payload.
// Only the nine-parameter Wide reports, with parameters=9 in its metadata, and size.parameter-count must be on by default.
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

	// A function with exactly MaxParameters parameters is not reported; only counts above the limit are.
	below := ParameterCountRule{MaxParameters: 9}.AnalyzeUnit(unit, Context{})
	if len(below) != 0 {
		t.Fatalf("threshold-9 findings = %#v, want none", below)
	}

	defaults := Defaults()
	if findings := defaults.Analyze([]parser.Unit{unit}, Context{}); !containsRuleID(findings, "size.parameter-count") {
		t.Fatalf("default scan = %#v, want size.parameter-count enabled", findings)
	}
}

// TestParameterCountHandlesNestedSignatureSyntax checks generic, function-typed and grouped parameters count four on Transform.
// It also checks an options struct for y, z and value clears the finding, and the catalogue's first false-positive shape has a mitigation.
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
	// Moving y, z and value into one options struct drops Transform to two parameters and clears the finding.
	if len(fixedFindings) != 0 {
		t.Fatalf("options remediation findings = %#v, want none", fixedFindings)
	}

	definition := (ParameterCountRule{}).Definition()
	// Catalogue guidance must explain fixed API signatures that users cannot reshape.
	if len(definition.FalsePositiveShapes) == 0 || definition.FalsePositiveShapes[0].Mitigation == "" {
		t.Fatalf("parameter-count false-positive guidance = %#v", definition.FalsePositiveShapes)
	}
}

// TestNestingDepthRule checks Deep, six blocks deep, reports depth=6 while Shallow stays quiet, and that the rule is on by default.
// Five nested ifs in a function literal inside Outer also produce no findings with the default rule.
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

// TestExportedSymbolCommentRule checks undocumented exported funcs, types, consts, vars and methods on exported types are reported.
// Documented or unexported symbols, methods on unexported types and exports in a _test.go file must stay quiet; the rule runs by default.
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

// TestGenericMethodsCarryTheirBaseTypeSymbol checks generic methods carry the same Type.Method symbol as methods on plain receivers.
//
// Undocumented methods on an exported generic type are reported, and those on an unexported generic type are not.
// A nesting-depth finding inside a generic method names it Stack.Deep, never the bare method name.
func TestGenericMethodsCarryTheirBaseTypeSymbol(t *testing.T) {
	unit := parseOne(t, "stack.go", `package sample

// Stack is a generic stack.
type Stack[T any] struct{ items []T }

// Pair is a generic pair.
type Pair[K comparable, V any] struct{ key K }

type stack[T any] struct{}

func (s *Stack[T]) Push(item T) {}

func (p Pair[K, V]) Key() K { return p.key }

func (s *stack[T]) Hidden() {}

func (s *Stack[T]) Deep(a, b, c bool) {
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
	got := map[string]bool{}
	for _, f := range (ExportedSymbolCommentRule{}).AnalyzeUnit(unit, Context{}) {
		got[f.Symbol] = true
	}
	for _, name := range []string{"Stack.Push", "Pair.Key", "Stack.Deep"} {
		if !got[name] {
			t.Fatalf("exported-symbol findings = %v, missing %s", got, name)
		}
	}
	if got["stack.Hidden"] || got["Hidden"] || got["Push"] {
		t.Fatalf("exported-symbol findings = %v, want no unexported or bare generic symbol", got)
	}

	nesting := NestingDepthRule{}.AnalyzeUnit(unit, Context{})
	if len(nesting) != 1 || nesting[0].Symbol != "Stack.Deep" {
		t.Fatalf("nesting findings = %#v, want one finding on Stack.Deep", nesting)
	}
}

// TestExportedSymbolCommentRuleCanIgnoreInternalPackages sets ignoreInternalPackages to true in the rule options.
// The findings omit VisibleInsideModule under internal/service and contain only the symbol VisibleOutsideModule under pkg/api.
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

// TestExportedSymbolCommentRuleCanIncludeInternalPackages sets ignoreInternalPackages to false in the rule options.
// An undocumented export under internal/service must then report docs.exported-symbol-comment.
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

// TestExportedSymbolCommentRuleInternalPackagesCoverGenericCallables checks generic exports with ignoreInternalPackages explicitly true and false.
// With true, the default, it reports nothing under internal/; with false it reports exactly Box.Get, Pair.Len and Map.
func TestExportedSymbolCommentRuleInternalPackagesCoverGenericCallables(t *testing.T) {
	unit := parseOne(t, "internal/service/service.go", `package service

// Box holds one value of any type.
type Box[T any] struct{ value T }

func (b *Box[T]) Get() T { return b.value }

// Pair groups a key type with a value type.
type Pair[K comparable, V any] struct{}

func (Pair[K, V]) Len() int { return 0 }

func Map[T any](items []T) []T { return items }
`)
	for _, tc := range []struct {
		ignoreInternal bool
		want           []string
	}{
		{ignoreInternal: true, want: nil},
		{ignoreInternal: false, want: []string{"Box.Get", "Pair.Len", "Map"}},
	} {
		registry, err := DefaultsConfigured(Config{
			Enabled: map[string]bool{"docs.exported-symbol-comment": true, "docs.package-comment": false},
			Options: map[string]map[string]any{
				"docs.exported-symbol-comment": {"ignoreInternalPackages": tc.ignoreInternal},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, f := range registry.Analyze([]parser.Unit{unit}, Context{}) {
			// Other default rules may report on the same fixture, so only docs.exported-symbol-comment symbols are compared.
			if f.RuleID == "docs.exported-symbol-comment" {
				got[f.Symbol] = true
			}
		}
		if len(got) != len(tc.want) {
			t.Fatalf("ignoreInternalPackages=%v: symbols = %v, want %v", tc.ignoreInternal, got, tc.want)
		}
		for _, symbol := range tc.want {
			if !got[symbol] {
				t.Fatalf("ignoreInternalPackages=%v: symbols = %v, missing %s", tc.ignoreInternal, got, symbol)
			}
		}
	}
}

// containsRuleID reports whether any finding in the slice has the given rule ID.
// It compares the RuleID of each element of findings against id, so a nil or empty findings slice reports false.
func containsRuleID(findings []finding.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// exportedFuncMessages runs docs.exported-symbol-comment over src and maps each finding's symbol to its message.
//
// It returns a non-nil map of Symbol to Message, empty when the rule reports nothing, and a later finding on one Symbol overwrites an earlier one.
// The test stops through parseOne when the temp fixture cannot be written or src parses with any diagnostic.
func exportedFuncMessages(t *testing.T, src string) map[string]string {
	t.Helper()
	messages := map[string]string{}
	for _, f := range (ExportedSymbolCommentRule{}).AnalyzeUnit(parseOne(t, "sample.go", src), Context{}) {
		messages[f.Symbol] = f.Message
	}
	return messages
}

// assertExportedFuncMessages fails the test when got and want differ in symbol count or in the message got holds for a symbol in want.
// It reports each mismatch with t.Errorf, so the test keeps running, and a symbol missing from got reads as an empty message.
func assertExportedFuncMessages(t *testing.T, got map[string]string, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("messages = %#v, want %d symbols", got, len(want))
	}
	for symbol, message := range want {
		if got[symbol] != message {
			t.Errorf("message for %s = %q, want %q", symbol, got[symbol], message)
		}
	}
}

// TestExportedFuncMessageNamesEachParameter pins that the default-on message names every parameter of an
// undocumented callable, skipping blank parameters and context, HTTP and testing handles.
func TestExportedFuncMessageNamesEachParameter(t *testing.T) {
	got := exportedFuncMessages(t, `package sample

import (
	"context"
	"net/http"
	"testing"
)

func Bare() {}

func One(name string) {}

func Handler(ctx context.Context, w http.ResponseWriter, r *http.Request, _ int, user, role string) {}

func Check(t *testing.T) {}
`)
	assertExportedFuncMessages(t, got, map[string]string{
		"Bare":    `exported function "Bare" has no doc comment`,
		"One":     `exported function "One" has no doc comment; describe parameter "name"`,
		"Handler": `exported function "Handler" has no doc comment; describe parameters "user", "role"`,
		"Check":   `exported function "Check" has no doc comment`,
	})
}

// TestExportedFuncMessageAsksForReturnValueOnlyWhenOneExists pins that the message asks for the returned
// value(s) only when the signature has a non-error result.
func TestExportedFuncMessageAsksForReturnValueOnlyWhenOneExists(t *testing.T) {
	got := exportedFuncMessages(t, `package sample

// Store holds items.
type Store struct{}

func (Store) Size() int { return 0 }

func Pair() (int, int) { return 0, 0 }

func Reset() {}
`)
	assertExportedFuncMessages(t, got, map[string]string{
		"Store.Size": `exported method "Size" has no doc comment; describe the returned value`,
		"Pair":       `exported function "Pair" has no doc comment; describe the returned values`,
		"Reset":      `exported function "Reset" has no doc comment`,
	})
}

// TestExportedFuncMessageAsksForErrorsOnlyWhenCallableCanFail pins that the message asks when an error is
// returned only when a result has the type error.
func TestExportedFuncMessageAsksForErrorsOnlyWhenCallableCanFail(t *testing.T) {
	got := exportedFuncMessages(t, `package sample

func Close() error { return nil }

func Load(path string) (string, error) { return "", nil }

func Count(items []string) int { return len(items) }
`)
	assertExportedFuncMessages(t, got, map[string]string{
		"Close": `exported function "Close" has no doc comment; say when an error is returned`,
		"Load":  `exported function "Load" has no doc comment; describe parameter "path"; describe the returned value; say when an error is returned`,
		"Count": `exported function "Count" has no doc comment; describe parameter "items"; describe the returned value`,
	})
}
