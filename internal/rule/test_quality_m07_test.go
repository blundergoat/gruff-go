// Package rule tests additional parser-only test-quality rules.
package rule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestHelperMissingTHelperRule covers helpers that fail tests without t.Helper.
func TestHelperMissingTHelperRule(t *testing.T) {
	unit := parseOne(t, "helpers_test.go", `package sample

import "testing"

func requireNoError(t testing.TB, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func requireEqual(t *testing.T, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("got %d", got)
	}
}

func TestReal(t *testing.T) {
	t.Fatal("not a helper")
}
`)
	findings := HelperMissingTHelperRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "requireNoError" {
		t.Fatalf("findings = %#v, want only requireNoError", findings)
	}
}

// TestParallelRangeCaptureRule covers unsafe table-test captures and explicit shadow copies.
func TestParallelRangeCaptureRule(t *testing.T) {
	captured := parseOne(t, "parallel_test.go", `package sample

import "testing"

func TestTable(t *testing.T) {
	tests := []struct {
		name string
		value int
	}{{name: "one", value: 1}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_ = tc.value
		})
	}
}
`)
	capturedRoot := writeGoModForUnit(t, captured, ".", "module sample\n\ngo 1.21\n")
	if findings := (ParallelRangeCaptureRule{}).AnalyzeUnit(captured, Context{Root: capturedRoot}); len(findings) != 1 {
		t.Fatalf("captured findings = %#v, want one", findings)
	}

	shadowed := parseOne(t, "parallel_test.go", `package sample

import "testing"

func TestTable(t *testing.T) {
	tests := []struct {
		name string
		value int
	}{{name: "one", value: 1}}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_ = tc.value
		})
	}
}
`)
	shadowedRoot := writeGoModForUnit(t, shadowed, ".", "module sample\n\ngo 1.21\n")
	if findings := (ParallelRangeCaptureRule{}).AnalyzeUnit(shadowed, Context{Root: shadowedRoot}); len(findings) != 0 {
		t.Fatalf("shadowed findings = %#v, want none", findings)
	}
}

// TestParallelRangeCaptureRuleRequiresLegacyGoVersion verifies Go 1.22+
// modules use per-iteration range variables and are therefore out of scope.
func TestParallelRangeCaptureRuleRequiresLegacyGoVersion(t *testing.T) {
	unit := parseOne(t, "parallel_test.go", parallelRangeCaptureFixture())
	root := writeGoModForUnit(t, unit, ".", "module sample\n\ngo 1.25.0\n")
	if findings := (ParallelRangeCaptureRule{}).AnalyzeUnit(unit, Context{Root: root}); len(findings) != 0 {
		t.Fatalf("go 1.25 findings = %#v, want none", findings)
	}

	noModule := parseOne(t, "parallel_test.go", parallelRangeCaptureFixture())
	if findings := (ParallelRangeCaptureRule{}).AnalyzeUnit(noModule, Context{}); len(findings) != 0 {
		t.Fatalf("missing go.mod findings = %#v, want none", findings)
	}
}

// TestParallelRangeCaptureRuleUsesNearestGoMod ensures nested modules use their own directive.
func TestParallelRangeCaptureRuleUsesNearestGoMod(t *testing.T) {
	unit := parseOne(t, "legacy/pkg/parallel_test.go", parallelRangeCaptureFixture())
	root := unitRoot(t, unit)
	writeGoMod(t, filepath.Join(root, "go.mod"), "module root\n\ngo 1.25.0\n")
	writeGoMod(t, filepath.Join(root, "legacy", "go.mod"), "module legacy\n\ngo 1.21\n")
	if findings := (ParallelRangeCaptureRule{}).AnalyzeUnit(unit, Context{Root: root}); len(findings) != 1 {
		t.Fatalf("nested module findings = %#v, want one from nearest go.mod", findings)
	}
}

// parallelRangeCaptureFixture returns a table-test shape that is only unsafe before Go 1.22.
func parallelRangeCaptureFixture() string {
	return `package sample

import "testing"

func TestTable(t *testing.T) {
	tests := []struct {
		name string
		value int
	}{{name: "one", value: 1}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_ = tc.value
		})
	}
}
`
}

// writeGoModForUnit writes go.mod relative to the parsed unit's temp root and returns that root.
func writeGoModForUnit(t *testing.T, unit parser.Unit, relDir string, contents string) string {
	t.Helper()
	root := unitRoot(t, unit)
	writeGoMod(t, filepath.Join(root, filepath.FromSlash(relDir), "go.mod"), contents)
	return root
}

// writeGoMod writes one module file for version-sensitive rule tests.
func writeGoMod(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

// unitRoot reconstructs parseOne's temp root from a unit's absolute and relative paths.
func unitRoot(t *testing.T, unit parser.Unit) string {
	t.Helper()
	rel := filepath.FromSlash(unit.File.Path)
	root := strings.TrimSuffix(unit.File.AbsPath, rel)
	if root == unit.File.AbsPath {
		t.Fatalf("could not derive root from %#v", unit.File)
	}
	return filepath.Clean(root)
}
