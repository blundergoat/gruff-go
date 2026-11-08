// Package rule tests static-analysis-redundant test candidate detection.
//
// The rule flags single assertions about parser-visible declarations, such as a struct's kind, name, field count or a declared field.
// These tests pin when it fires, what evidence each finding carries, and that it stays opt-in.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestStaticAnalysisRedundantTestFlagsReflectShapeAssertions covers direct reflection assertions that restate parser-visible type declarations.
//
// It expects three high-confidence findings on TestWidgetShape that cite pkg/widget/widget.go.
// It rejects empty-string assertion, staticFact and confidenceReason metadata values.
func TestStaticAnalysisRedundantTestFlagsReflectShapeAssertions(t *testing.T) {
	production := parseOne(t, "pkg/widget/widget.go", `package widget

type Widget struct {
	Name string
	Count int
}
`)
	testUnit := parseOne(t, "pkg/widget/widget_test.go", `package widget

import (
	"reflect"
	"testing"
)

func TestWidgetShape(t *testing.T) {
	if got := reflect.TypeOf(Widget{}).Kind(); got != reflect.Struct {
		t.Fatalf("kind = %v", got)
	}
	if got := reflect.TypeOf(Widget{}).Name(); got != "Widget" {
		t.Fatalf("name = %s", got)
	}
	if got := reflect.TypeOf(Widget{}).NumField(); got != 2 {
		t.Fatalf("fields = %d", got)
	}
}
`)
	findings := StaticAnalysisRedundantTestRule{}.AnalyzeProject([]parser.Unit{production, testUnit}, Context{})
	// Each of the three reflect checks restates the Widget declaration, so each one is a separate finding.
	if len(findings) != 3 {
		t.Fatalf("findings = %#v, want three static-shape findings", findings)
	}
	for _, item := range findings {
		if item.Symbol != "TestWidgetShape" {
			t.Fatalf("symbol = %q, want TestWidgetShape", item.Symbol)
		}
		if item.Confidence != finding.ConfidenceHigh {
			t.Fatalf("confidence = %q, want high", item.Confidence)
		}
		if item.Metadata["staticFactFile"] != "pkg/widget/widget.go" {
			t.Fatalf("static fact file = %#v, want production declaration", item.Metadata["staticFactFile"])
		}
		if item.Metadata["assertion"] == "" || item.Metadata["staticFact"] == "" || item.Metadata["confidenceReason"] == "" {
			t.Fatalf("missing metadata in %#v", item.Metadata)
		}
	}
}

// TestStaticAnalysisRedundantTestFlagsFieldByNameAssertions covers direct field-existence checks whose field declaration is visible in the AST.
//
// It expects exactly one finding, whose static fact names the Name field and whose fact line is that field's line.
func TestStaticAnalysisRedundantTestFlagsFieldByNameAssertions(t *testing.T) {
	production := parseOne(t, "pkg/widget/widget.go", `package widget

type Widget struct {
	Name string
}
`)
	testUnit := parseOne(t, "pkg/widget/widget_test.go", `package widget

import (
	"reflect"
	"testing"
)

func TestWidgetHasNameField(t *testing.T) {
	if _, ok := reflect.TypeOf(Widget{}).FieldByName("Name"); !ok {
		t.Fatal("Name field missing")
	}
}
`)
	findings := StaticAnalysisRedundantTestRule{}.AnalyzeProject([]parser.Unit{production, testUnit}, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one field-shape finding", findings)
	}
	if findings[0].Metadata["staticFact"] != "Widget declares field \"Name\"" {
		t.Fatalf("static fact = %#v, want field declaration", findings[0].Metadata["staticFact"])
	}
	// Line 4 is the Name field inside the production fixture, not the type line above it.
	if findings[0].Metadata["staticFactLine"] != 4 {
		t.Fatalf("static fact line = %#v, want field line 4", findings[0].Metadata["staticFactLine"])
	}
}

// TestStaticAnalysisRedundantTestIgnoresBehaviourAssertions confirms value behaviour remains out of scope even when tests mention reflected types.
//
// The FieldByName check asserts absence, a shape this rule does not match; the test expects no findings.
func TestStaticAnalysisRedundantTestIgnoresBehaviourAssertions(t *testing.T) {
	production := parseOne(t, "pkg/widget/widget.go", `package widget

type Widget struct {
	Name string
}

func NewWidget(name string) Widget {
	return Widget{Name: name}
}
`)
	testUnit := parseOne(t, "pkg/widget/widget_test.go", `package widget

import (
	"reflect"
	"testing"
)

func TestWidgetBehaviour(t *testing.T) {
	got := NewWidget("real")
	if got.Name != "real" {
		t.Fatalf("name = %s", got.Name)
	}
	if _, ok := reflect.TypeOf(Widget{}).FieldByName("Missing"); ok {
		t.Fatal("unexpected field")
	}
}
`)
	findings := StaticAnalysisRedundantTestRule{}.AnalyzeProject([]parser.Unit{production, testUnit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for behaviour and missing-field checks", findings)
	}
}

// TestStaticAnalysisRedundantTestIgnoresExternalTestPackages confirms parser-only declaration evidence stays scoped to the package under analysis.
//
// The test file is package widget_test, so its Widget is not proven to be the production type; the test expects no findings.
func TestStaticAnalysisRedundantTestIgnoresExternalTestPackages(t *testing.T) {
	production := parseOne(t, "pkg/widget/widget.go", `package widget

type Widget struct{}
`)
	testUnit := parseOne(t, "pkg/widget/widget_test.go", `package widget_test

import (
	"reflect"
	"testing"
)

func TestWidgetShape(t *testing.T) {
	if got := reflect.TypeOf(Widget{}).Kind(); got != reflect.Struct {
		t.Fatalf("kind = %v", got)
	}
}
`)
	findings := StaticAnalysisRedundantTestRule{}.AnalyzeProject([]parser.Unit{production, testUnit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none without same-package declaration evidence", findings)
	}
}

// TestStaticAnalysisRedundantTestIsOptInCandidate checks the rule stays out of default scans until broader calibration.
//
// It also pins the rule to parser capability and advisory severity.
func TestStaticAnalysisRedundantTestIsOptInCandidate(t *testing.T) {
	def := StaticAnalysisRedundantTestRule{}.Definition()
	if def.DefaultEnabled {
		t.Error("static-analysis-redundant candidate must ship opt-in until calibrated")
	}
	if def.Capability != CapabilityParser {
		t.Errorf("capability = %q, want parser", def.Capability)
	}
	if def.Severity != finding.SeverityAdvisory {
		t.Errorf("severity = %q, want advisory", def.Severity)
	}
}
