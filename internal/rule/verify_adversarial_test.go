// Package rule exercises the flag / no-flag boundaries and finding metadata of
// test-quality.static-analysis-redundant-test: the adversarial precision coverage
// that backs the opt-in candidate's calibration toward a future default-on decision.
package rule

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// vRun analyses the supplied units with only the rule under test.
func vRun(t *testing.T, units ...parser.Unit) []finding.Finding {
	t.Helper()
	return StaticAnalysisRedundantTestRule{}.AnalyzeProject(units, Context{})
}

// vProd is the canonical same-package production declaration used by probes.
func vProd(t *testing.T) parser.Unit {
	t.Helper()
	return parseOne(t, "pkg/widget/widget.go", `package widget

type Widget struct {
	Name  string
	Count int
}

func NewWidget(name string) Widget { return Widget{Name: name} }

func Parse(in string) (Widget, error) { return Widget{Name: in}, nil }
`)
}

// vTest parses a widget_test.go body in the same dir/package as vProd.
func vTest(t *testing.T, body string) parser.Unit {
	t.Helper()
	return parseOne(t, "pkg/widget/widget_test.go", body)
}

// TestVerifyStaticFactAdversarial pins the rule's flag / no-flag boundary: Group A
// asserts supported reflect and FieldByName shapes are flagged (including aliased,
// dot-import, benchmark, and testify variants); Group B asserts behaviour checks and
// unsupported shapes stay silent; the closing subtests verify external/cross-directory
// package isolation and finding metadata (assertion, staticFact, source proof).
func TestVerifyStaticFactAdversarial(t *testing.T) {
	prod := vProd(t)

	// ---- Group A: MUST FLAG (true positives in supported scope) ----
	flag := []struct {
		name string
		body string
		want int
	}{
		{"kind-reversed-operands", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	if reflect.Struct != reflect.TypeOf(Widget{}).Kind() { t.Fatal("x") }
}`, 1},
		{"aliased-reflect-import", `package widget
import (r "reflect"; "testing")
func TestX(t *testing.T) {
	if r.TypeOf(Widget{}).Kind() != r.Struct { t.Fatal("x") }
}`, 1},
		{"name-check", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	if reflect.TypeOf(Widget{}).Name() != "Widget" { t.Fatal("x") }
}`, 1},
		{"numfield-init-bound-ident", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	if n := reflect.TypeOf(Widget{}).NumField(); n != 2 { t.Fatal("x") }
}`, 1},
		{"fieldbyname-existence", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	if _, ok := reflect.TypeOf(Widget{}).FieldByName("Name"); !ok { t.Fatal("x") }
}`, 1},
		{"dot-import-NAME-flags", `package widget
import (. "reflect"; "testing")
func TestX(t *testing.T) {
	if TypeOf(Widget{}).Name() != "Widget" { t.Fatal("x") }
}`, 1},
		{"benchmark-also-in-scope", `package widget
import ("reflect"; "testing")
func BenchmarkX(b *testing.B) {
	if reflect.TypeOf(Widget{}).Kind() != reflect.Struct { b.Fatal("x") }
}`, 1},
		{"testify-require-failure", `package widget
import ("reflect"; "testing"; "github.com/stretchr/testify/require")
func TestX(t *testing.T) {
	if reflect.TypeOf(Widget{}).Kind() != reflect.Struct { require.Fail(t, "x") }
}`, 1},
	}
	for _, tc := range flag {
		t.Run("FLAG/"+tc.name, func(t *testing.T) {
			got := vRun(t, prod, vTest(t, tc.body))
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d: %#v", len(got), tc.want, got)
			}
		})
	}

	// ---- Group B: MUST NOT FLAG (FP guards + documented limitations) ----
	noflag := []struct {
		name string
		body string
		note string
	}{
		{"behaviour-value-assertion", `package widget
import "testing"
func TestX(t *testing.T) {
	got := NewWidget("real")
	if got.Name != "real" { t.Fatalf("name=%s", got.Name) }
}`, "FP-guard: real behaviour"},
		{"missing-field-ok-branch", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	if _, ok := reflect.TypeOf(Widget{}).FieldByName("Missing"); ok { t.Fatal("x") }
}`, "FP-guard: absence check"},
		{"numfield-wrong-count", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	if reflect.TypeOf(Widget{}).NumField() != 3 { t.Fatal("x") }
}`, "FP-guard: value does not restate the true fact (buggy test)"},
		{"reflect-on-variable", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	var w Widget
	if reflect.TypeOf(w).Kind() != reflect.Struct { t.Fatal("x") }
}`, "FN-conservative: needs T{} composite literal"},
		{"pointer-composite", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	if reflect.TypeOf(&Widget{}).Kind() != reflect.Ptr { t.Fatal("x") }
}`, "FP-guard: &T{} not handled"},
		{"equality-inverted-assertion", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	if reflect.TypeOf(Widget{}).Kind() == reflect.Struct { t.Fatal("x") }
}`, "FN-limitation: only != handled"},
		{"subtest-closure", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	t.Run("s", func(t *testing.T) {
		if reflect.TypeOf(Widget{}).Kind() != reflect.Struct { t.Fatal("x") }
	})
}`, "FN-limitation: FuncLit bodies not descended"},
		{"non-failure-body", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	if reflect.TypeOf(Widget{}).Kind() != reflect.Struct { _ = 1 }
}`, "FP-guard: no failure call"},
		{"separate-statement-assign", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	k := reflect.TypeOf(Widget{}).Kind()
	if k != reflect.Struct { t.Fatal("x") }
}`, "FN-limitation: facts only from if-init clause"},
		{"dot-import-KIND-does-not-flag", `package widget
import (. "reflect"; "testing")
func TestX(t *testing.T) {
	if TypeOf(Widget{}).Kind() != Struct { t.Fatal("x") }
}`, "FN-asymmetry: bare Struct ident not a reflect.Kind selector"},
		{"parsing-error-behaviour", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	v, err := Parse("x")
	if err != nil { t.Fatal(err) }
	if reflect.TypeOf(v).Kind() != reflect.Struct { t.Fatal("not struct") }
}`, "FP-guard: reflection on runtime value, real error check"},
	}
	for _, tc := range noflag {
		t.Run("NOFLAG/"+tc.name, func(t *testing.T) {
			got := vRun(t, prod, vTest(t, tc.body))
			if len(got) != 0 {
				t.Fatalf("got %d findings, want 0 (%s): %#v", len(got), tc.note, got)
			}
		})
	}

	// ---- External _test package: declarations not visible -> 0 ----
	t.Run("NOFLAG/external-test-package", func(t *testing.T) {
		ext := parseOne(t, "pkg/widget/widget_ext_test.go", `package widget_test
import ("reflect"; "testing")
func TestX(t *testing.T) {
	if reflect.TypeOf(Widget{}).Kind() != reflect.Struct { t.Fatal("x") }
}`)
		got := vRun(t, prod, ext)
		if len(got) != 0 {
			t.Fatalf("external _test package flagged: %#v", got)
		}
	})

	// ---- Same package NAME but different DIR: must not merge -> 0 ----
	t.Run("NOFLAG/cross-directory-same-package-name", func(t *testing.T) {
		otherDir := parseOne(t, "pkg/other/widget.go", `package widget
type Widget struct { Name string }`)
		test := parseOne(t, "pkg/widget/widget_test.go", `package widget
import ("reflect"; "testing")
func TestX(t *testing.T) {
	if reflect.TypeOf(Widget{}).Kind() != reflect.Struct { t.Fatal("x") }
}`)
		got := vRun(t, otherDir, test)
		if len(got) != 0 {
			t.Fatalf("cross-dir same-name package merged: %#v", got)
		}
	})

	// ---- Metadata completeness + source-proof correctness ----
	t.Run("METADATA/name-check-proof", func(t *testing.T) {
		got := vRun(t, prod, vTest(t, `package widget
import ("reflect"; "testing")
func TestWidgetName(t *testing.T) {
	if reflect.TypeOf(Widget{}).Name() != "Widget" { t.Fatal("x") }
}`))
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d: %#v", len(got), got)
		}
		f := got[0]
		if f.Symbol != "TestWidgetName" {
			t.Errorf("symbol=%q", f.Symbol)
		}
		if f.Confidence != finding.ConfidenceHigh {
			t.Errorf("confidence=%q", f.Confidence)
		}
		for _, k := range []string{"assertion", "staticFact", "staticFactFile", "staticFactLine", "confidenceReason"} {
			if _, ok := f.Metadata[k]; !ok {
				t.Errorf("missing metadata key %q in %#v", k, f.Metadata)
			}
		}
		if f.Metadata["staticFactFile"] != "pkg/widget/widget.go" {
			t.Errorf("staticFactFile=%#v want production file", f.Metadata["staticFactFile"])
		}
		if got, want := f.Metadata["staticFactLine"], 3; got != want {
			t.Errorf("staticFactLine=%#v want %d (type Widget decl line)", got, want)
		}
		if got := f.Metadata["staticFact"]; got != `Widget is declared with name "Widget"` {
			t.Errorf("staticFact=%#v", got)
		}
		if a, _ := f.Metadata["assertion"].(string); !strings.Contains(a, "Name()") {
			t.Errorf("assertion=%#v should echo the source condition", f.Metadata["assertion"])
		}
	})
}
