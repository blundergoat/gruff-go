// Package rule defines gruff-go's rule registry and analysers.
// This file exercises the docs.missing-param-doc and docs.missing-return-doc rules across callable
// forms, skipped handles, result shapes, natural prose, and their opt-in defaults.
package rule

import (
	"strings"
	"testing"
)

// analyseMissingParamDoc parses one source file and runs the docs.missing-param-doc rule over it.
func analyseMissingParamDoc(t *testing.T, path string, source string) []callableDocView {
	t.Helper()
	unit := parseOne(t, path, source)
	views := []callableDocView{}
	for _, current := range (MissingParamDocRule{}).AnalyzeUnit(unit, Context{}) {
		views = append(views, callableDocView{symbol: current.Symbol, message: current.Message, line: current.Location.Line})
	}
	return views
}

// callableDocView keeps the fields these tests assert on.
type callableDocView struct {
	// symbol is the reported callable name.
	symbol string
	// message is the rendered finding message.
	message string
	// line is the reported line.
	line int
}

// TestMissingParamDocRuleIsOptIn pins the rule as shipped off by default, so default scans do not change.
func TestMissingParamDocRuleIsOptIn(t *testing.T) {
	definition := (MissingParamDocRule{}).Definition()
	if definition.ID != "docs.missing-param-doc" || definition.DefaultEnabled {
		t.Fatalf("definition = %#v, want docs.missing-param-doc with DefaultEnabled false", definition)
	}
}

// TestMissingParamDocRuleAcceptsNaturalProse confirms a doc comment that names every parameter in plain
// sentences, in any letter case, produces no finding.
func TestMissingParamDocRuleAcceptsNaturalProse(t *testing.T) {
	findings := analyseMissingParamDoc(t, "pricing/pricing.go", `package pricing

// ConvertCents multiplies an amount in cents by a whole-number rate.
// Amount must not be negative; the rate comes from the [rate] table.
func ConvertCents(amount int, rate int) int { return amount * rate }
`)
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none when prose names every parameter", findings)
	}
}

// TestMissingParamDocRuleNamesEachMissingParameterOnPublicFunction confirms one finding per callable that
// names every parameter the doc comment leaves out, in signature order, without calling the callable public.
func TestMissingParamDocRuleNamesEachMissingParameterOnPublicFunction(t *testing.T) {
	findings := analyseMissingParamDoc(t, "pricing/pricing.go", `package pricing

// ConvertCents converts a value using the amount.
func ConvertCents(amount int, rate int, scale int) int { return amount * rate * scale }
`)
	want := `doc comment on function "ConvertCents" does not name parameters "rate", "scale"`
	if len(findings) != 1 || findings[0].message != want || findings[0].symbol != "ConvertCents" || findings[0].line != 4 {
		t.Fatalf("findings = %#v, want one finding %q on line 4", findings, want)
	}
}

// TestMissingParamDocRuleReportsPrivateFunction confirms unexported functions are inspected and the message
// uses the singular noun without calling the function public or exported.
func TestMissingParamDocRuleReportsPrivateFunction(t *testing.T) {
	findings := analyseMissingParamDoc(t, "internal/pricing/pricing.go", `package pricing

// convertCents converts the amount into cents.
func convertCents(amount int, rate int) int { return amount * rate }
`)
	want := `doc comment on function "convertCents" does not name parameter "rate"`
	if len(findings) != 1 || findings[0].message != want {
		t.Fatalf("findings = %#v, want %q", findings, want)
	}
	if strings.Contains(findings[0].message, "public") || strings.Contains(findings[0].message, "exported") {
		t.Fatalf("message %q must not call a private callable public", findings[0].message)
	}
}

// TestMissingParamDocRuleReportsMethodAsTypeMethod confirms methods, generic receivers included, are
// reported as Type.Method and the receiver is never treated as a parameter.
func TestMissingParamDocRuleReportsMethodAsTypeMethod(t *testing.T) {
	findings := analyseMissingParamDoc(t, "box/box.go", `package box

type Box[T any] struct{ items []T }

// Put stores a value in the box.
func (b *Box[T]) Put(item T, slot int) { b.items = append(b.items, item) }
`)
	want := `doc comment on method "Box.Put" does not name parameters "item", "slot"`
	if len(findings) != 1 || findings[0].message != want || findings[0].symbol != "Box.Put" {
		t.Fatalf("findings = %#v, want %q", findings, want)
	}
}

// TestMissingParamDocRuleReadsPackageLevelFuncLiteralVarDoc confirms a package-level var holding a function
// literal is read through the var's doc comment, ungrouped and grouped, while local closures stay out.
func TestMissingParamDocRuleReadsPackageLevelFuncLiteralVarDoc(t *testing.T) {
	findings := analyseMissingParamDoc(t, "hooks/hooks.go", `package hooks

// format renders the label for display.
var format = func(label string, width int) string { return label }

var (
	// parse reads the raw input text.
	parse = func(raw string, strict bool) error { return nil }
)

// Run executes the job with its options.
func Run(job string, options int) {
	// local closure is not a declaration.
	local := func(unnamed int) int { return unnamed }
	_ = local
}
`)
	want := []string{
		`doc comment on function variable "format" does not name parameter "width"`,
		`doc comment on function variable "parse" does not name parameter "strict"`,
	}
	if len(findings) != len(want) {
		t.Fatalf("findings = %#v, want %d function-variable findings", findings, len(want))
	}
	for index, message := range want {
		if findings[index].message != message {
			t.Fatalf("findings[%d] = %q, want %q", index, findings[index].message, message)
		}
	}
}

// TestMissingParamDocRuleSkipsHandlesBlankAndUnnamedParameters confirms context, HTTP request and response,
// and testing handles, blank parameters, and unnamed parameters never need naming.
func TestMissingParamDocRuleSkipsHandlesBlankAndUnnamedParameters(t *testing.T) {
	findings := analyseMissingParamDoc(t, "server/server.go", `package server

import (
	"context"
	"net/http"
	"testing"
)

// Serve answers the request for the given id.
func Serve(ctx context.Context, w http.ResponseWriter, r *http.Request, id string) {}

// check verifies the fixture named by id.
func check(t *testing.T, tb testing.TB, id string, _ int) {}

// handle reacts to an event without naming its signature.
func handle(int, string) {}
`)
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for handles, blank, and unnamed parameters", findings)
	}
}

// TestMissingParamDocRuleLeavesUndocumentedCallablesToOtherRules confirms a callable with no doc comment,
// or one that only repeats its name, is not reported by this rule.
func TestMissingParamDocRuleLeavesUndocumentedCallablesToOtherRules(t *testing.T) {
	findings := analyseMissingParamDoc(t, "pricing/pricing.go", `package pricing

func ConvertCents(amount int, rate int) int { return amount * rate }

// convert
func convert(amount int) int { return amount }
`)
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for undocumented callables", findings)
	}
}

// analyseMissingReturnDoc parses one source file and runs the docs.missing-return-doc rule over it.
func analyseMissingReturnDoc(t *testing.T, path string, source string) []callableDocView {
	t.Helper()
	unit := parseOne(t, path, source)
	views := []callableDocView{}
	for _, current := range (MissingReturnDocRule{}).AnalyzeUnit(unit, Context{}) {
		views = append(views, callableDocView{symbol: current.Symbol, message: current.Message, line: current.Location.Line})
	}
	return views
}

// assertReturnDocMessages fails unless the findings carry exactly the wanted messages in order.
func assertReturnDocMessages(t *testing.T, findings []callableDocView, want []string) {
	t.Helper()
	if len(findings) != len(want) {
		t.Fatalf("findings = %#v, want %d findings %q", findings, len(want), want)
	}
	for index, message := range want {
		if findings[index].message != message {
			t.Fatalf("findings[%d] = %q, want %q", index, findings[index].message, message)
		}
	}
}

// TestMissingReturnDocRuleIsOptIn pins the return-prose rule as shipped off by default, so default scans do
// not change.
func TestMissingReturnDocRuleIsOptIn(t *testing.T) {
	definition := (MissingReturnDocRule{}).Definition()
	if definition.ID != "docs.missing-return-doc" || definition.DefaultEnabled {
		t.Fatalf("definition = %#v, want docs.missing-return-doc with DefaultEnabled false", definition)
	}
}

// TestMissingReturnDocRuleAcceptsNaturalProse confirms plain sentences that say what comes back and when the
// callable fails, a "reports whether" summary, and a named result all count, with no tag format required.
func TestMissingReturnDocRuleAcceptsNaturalProse(t *testing.T) {
	findings := analyseMissingReturnDoc(t, "config/config.go", `package config

// Load reads the file at path and returns the parsed settings. It fails when the file is missing.
func Load(path string) (map[string]string, error) { return nil, nil }

// Has reports whether key is present.
func Has(key string) bool { return key != "" }

// split cuts the line once; head is the text before the separator.
func split(line string) (head string) { return line }
`)
	assertReturnDocMessages(t, findings, nil)
}

// TestMissingReturnDocRuleSkipsCallablesThatReturnNothing confirms a callable with no results is never asked
// for return or error prose.
func TestMissingReturnDocRuleSkipsCallablesThatReturnNothing(t *testing.T) {
	findings := analyseMissingReturnDoc(t, "cache/cache.go", `package cache

// Reset clears the cache entries.
func Reset() {}

// store saves the value for later.
func store(value int) {}
`)
	assertReturnDocMessages(t, findings, nil)
}

// TestMissingReturnDocRuleAsksOnlyForWhatTheSignatureHas confirms the message asks for the returned value only
// when one exists and for the error case only when a result is an error, across methods and function
// variables, without calling a private callable public.
func TestMissingReturnDocRuleAsksOnlyForWhatTheSignatureHas(t *testing.T) {
	findings := analyseMissingReturnDoc(t, "store/store.go", `package store

// Store keeps rows in memory.
type Store struct{ rows []string }

// Close releases the memory the store holds.
func (s *Store) Close() error { return nil }

// bounds measures the stored rows.
func (s *Store) bounds() (int, int) { return 0, len(s.rows) }

// fetch looks up a row by its index.
var fetch = func(index int) (string, error) { return "", nil }
`)
	assertReturnDocMessages(t, findings, []string{
		`doc comment on method "Store.Close" does not say when an error is returned`,
		`doc comment on method "Store.bounds" does not describe the returned values`,
		`doc comment on function variable "fetch" does not describe the returned value or say when an error is returned`,
	})
	for _, current := range findings {
		if strings.Contains(current.message, "public") || strings.Contains(current.message, "exported") {
			t.Fatalf("message %q must not call a private callable public", current.message)
		}
	}
}

// TestMissingReturnDocRuleReportsWhenOnlyOneHalfOfTheProseIsMissing confirms "returns an error when ..." does
// not describe the returned value, and value prose alone does not explain the error case.
func TestMissingReturnDocRuleReportsWhenOnlyOneHalfOfTheProseIsMissing(t *testing.T) {
	findings := analyseMissingReturnDoc(t, "config/config.go", `package config

// Load returns an error when the file at path is missing.
func Load(path string) (string, error) { return "", nil }

// Parse returns the settings read from the text.
func Parse(text string) (string, error) { return text, nil }
`)
	assertReturnDocMessages(t, findings, []string{
		`doc comment on function "Load" does not describe the returned value`,
		`doc comment on function "Parse" does not say when an error is returned`,
	})
}
