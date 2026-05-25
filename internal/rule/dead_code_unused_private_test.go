// Package rule tests the project-level dead-code.unused-private-function rule.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestUnusedPrivateFunctionFlagsAbandonedHelper is the rule's happy path:
// a private function nobody calls, in a single-file package.
func TestUnusedPrivateFunctionFlagsAbandonedHelper(t *testing.T) {
	unit := parseOne(t, "pkg/foo/foo.go", `package foo

func Used() {
	helper()
}

func helper() {}

func abandoned() {}
`)
	findings := UnusedPrivateFunctionRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one abandoned-function finding", findings)
	}
	if findings[0].Symbol != "abandoned" {
		t.Errorf("symbol = %q, want %q", findings[0].Symbol, "abandoned")
	}
}

// TestUnusedPrivateFunctionResolvesAcrossFiles confirms references in a
// sibling file inside the same package suppress the finding. This is the
// case the rule exists to handle that a unit-scoped rule could not.
func TestUnusedPrivateFunctionResolvesAcrossFiles(t *testing.T) {
	declUnit := parseOne(t, "pkg/foo/a.go", `package foo

func helper() {}
`)
	callerUnit := parseOne(t, "pkg/foo/b.go", `package foo

func Public() {
	helper()
}
`)
	findings := UnusedPrivateFunctionRule{}.AnalyzeProject([]parser.Unit{declUnit, callerUnit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for cross-file caller", findings)
	}
}

// TestUnusedPrivateFunctionIgnoresExported confirms exported names are out of scope.
func TestUnusedPrivateFunctionIgnoresExported(t *testing.T) {
	unit := parseOne(t, "pkg/foo/foo.go", `package foo

func Exported() {}
`)
	findings := UnusedPrivateFunctionRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for exported function", findings)
	}
}

// TestUnusedPrivateFunctionIgnoresMethods confirms methods (functions with
// receivers) are out of scope. Method reachability needs interface and
// embedding analysis that parser-only inspection cannot do safely.
func TestUnusedPrivateFunctionIgnoresMethods(t *testing.T) {
	unit := parseOne(t, "pkg/foo/foo.go", `package foo

type T struct{}

func (T) helper() {}
`)
	findings := UnusedPrivateFunctionRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for private method", findings)
	}
}

// TestUnusedPrivateFunctionIgnoresInitAndMain confirms reserved entrypoints
// are not flagged even when no caller references them syntactically.
func TestUnusedPrivateFunctionIgnoresInitAndMain(t *testing.T) {
	unit := parseOne(t, "cmd/sample/main.go", `package main

func init() {}

func main() {}
`)
	findings := UnusedPrivateFunctionRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none for init/main", findings)
	}
}

// TestUnusedPrivateFunctionSkipsReflectivePackages verifies the rule steps
// aside when reflection is in play, because runtime dispatch by name
// would otherwise produce systemic false positives.
func TestUnusedPrivateFunctionSkipsReflectivePackages(t *testing.T) {
	unit := parseOne(t, "pkg/foo/foo.go", `package foo

import "reflect"

var _ = reflect.TypeOf

func dispatched() {}
`)
	findings := UnusedPrivateFunctionRule{}.AnalyzeProject([]parser.Unit{unit}, Context{})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none when package imports reflect", findings)
	}
}

// TestUnusedPrivateFunctionSeparatesExternalTestPackage proves the external
// `_test` package is treated as its own group: a private helper in a
// `foo_test` file does not satisfy a `foo` package's private declaration
// because the two cannot reference each other across the visibility boundary.
func TestUnusedPrivateFunctionSeparatesExternalTestPackage(t *testing.T) {
	mainUnit := parseOne(t, "pkg/foo/foo.go", `package foo

func helper() {}
`)
	testUnit := parseOne(t, "pkg/foo/foo_test.go", `package foo_test

import "testing"

func TestPlaceholder(t *testing.T) {
	_ = t
}

func helper() {}
`)
	findings := UnusedPrivateFunctionRule{}.AnalyzeProject([]parser.Unit{mainUnit, testUnit}, Context{})
	// `foo.helper` is referenced nowhere in `foo`; the external `foo_test`
	// cannot satisfy it. Both helpers are flagged independently because
	// neither package has any other reference to its `helper`.
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want one finding per package", findings)
	}
}

// TestUnusedPrivateFunctionIsDefaultEnabled asserts the rule ships enabled
// with parser capability and low severity (cleanup signal, not a CI gate).
func TestUnusedPrivateFunctionIsDefaultEnabled(t *testing.T) {
	def := UnusedPrivateFunctionRule{}.Definition()
	if !def.DefaultEnabled {
		t.Error("dead-code.unused-private-function must be default-enabled")
	}
	if def.Capability != CapabilityParser {
		t.Errorf("capability = %q, want parser", def.Capability)
	}
	if def.Severity != finding.SeverityAdvisory {
		t.Errorf("severity = %q, want advisory", def.Severity)
	}
}
