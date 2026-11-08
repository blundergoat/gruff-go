// Package rule tests the parser-only test-quality rules for test helpers and parallel table subtests.
//
// Helper fixtures check when a failing helper must call t.Helper, and parallel fixtures capture a range variable inside t.Parallel subtests.
// The range-capture rule reads the nearest go.mod: it fires only for modules older than Go 1.22 and stays silent without one.
package rule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
)

// TestHelperMissingTHelperRule covers helpers that fail tests without t.Helper.
// A helper that already calls t.Helper and a Test function that fails directly stay silent, so only requireNoError is reported.
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
// Both fixtures sit in a Go 1.21 module, so the captured tc yields one finding and the tc := tc copy yields none.
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

// TestParallelRangeCaptureRuleRequiresLegacyGoVersion checks that a Go 1.25 module yields no capture finding.
// Without a go.mod the rule stays silent, while a go.mod with no go directive yields one capture finding.
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

	implicitLegacy := parseOne(t, "parallel_test.go", parallelRangeCaptureFixture())
	implicitRoot := writeGoModForUnit(t, implicitLegacy, ".", "module sample\n")
	if findings := (ParallelRangeCaptureRule{}).AnalyzeUnit(implicitLegacy, Context{Root: implicitRoot}); len(findings) != 1 {
		t.Fatalf("go.mod without go directive findings = %#v, want one for implicit Go 1.16", findings)
	}
}

// TestParallelRangeCaptureRuleUsesNearestGoMod ensures nested modules use their own directive.
// The root go.mod says Go 1.25 but legacy/go.mod says Go 1.21, so the fixture under legacy/pkg still yields one finding.
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
// unit supplies the root through unitRoot, relDir is a slash-separated directory relative to that root, and contents is the go.mod text.
// The test fails when the root cannot be derived or go.mod cannot be written.
func writeGoModForUnit(t *testing.T, unit parser.Unit, relDir string, contents string) string {
	t.Helper()
	root := unitRoot(t, unit)
	writeGoMod(t, filepath.Join(root, filepath.FromSlash(relDir), "go.mod"), contents)
	return root
}

// writeGoMod writes one module file for version-sensitive rule tests.
// path is the module file to write, with any missing parent directories created first, and contents replaces whatever the file held.
// The test fails through t.Fatal when the directories or the file cannot be written.
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
// It returns the cleaned directory left after trimming unit.File.Path from the end of unit.File.AbsPath.
// The test fails when that trim changes nothing, such as when AbsPath does not end with the relative path.
func unitRoot(t *testing.T, unit parser.Unit) string {
	t.Helper()
	rel := filepath.FromSlash(unit.File.Path)
	root := strings.TrimSuffix(unit.File.AbsPath, rel)
	if root == unit.File.AbsPath {
		t.Fatalf("could not derive root from %#v", unit.File)
	}
	return filepath.Clean(root)
}

// TestHelperMissingTHelperRuleSkipsTestBodies pins the shapes the helper rule leaves alone; every fixture must yield no finding.
//
// Benchmark bodies with a b.N or b.Loop timing loop and long parameterized bodies named like a test are skipped.
// So are a Helper call reached through an interface assertion and failures raised only through a subtest's own handle.
func TestHelperMissingTHelperRuleSkipsTestBodies(t *testing.T) {
	longBody := strings.Repeat("\t_ = mode\n", 30)
	cases := map[string]string{
		"benchmark body with b.N loop": `func doBenchmark(b *testing.B, n int) {
	if n < 0 {
		b.Fatal("bad")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
	}
}`,
		"benchmark body with b.Loop": `func benchStress(b *testing.B) {
	for b.Loop() {
		b.Fatal("stop")
	}
}`,
		"long parameterized test body": "func testScenario(t *testing.T, mode bool) {\n" + longBody + "\tt.Fatal(\"failed\")\n}",
		"helper reached through an interface assertion": `type tHelper interface{ Helper() }

func callOrderAssert(t *testing.T, want string) {
	var ti interface{} = t
	if h, ok := ti.(tHelper); ok {
		h.Helper()
	}
	if want == "" {
		t.Fatal("empty")
	}
}`,
		"helper called on an asserted value": `func markHelper(t testing.TB) {
	t.(interface{ Helper() }).Helper()
	t.Fatal("failed")
}`,
		"failures only through the subtest's own handle": `func checkRelations(t *testing.T, names []string) {
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			if name == "" {
				t.Errorf("empty")
			}
		})
	}
}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			unit := parseOne(t, "bodies_test.go", "package sample\n\nimport \"testing\"\n\n"+body+"\n")
			if got := (HelperMissingTHelperRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
				t.Fatalf("findings = %#v, want none", got)
			}
		})
	}
}

// TestHelperMissingTHelperRuleKeepsHelpers keeps each skipped shape's near miss reported.
// Every case must yield one finding, so a silent case means a skip in TestHelperMissingTHelperRuleSkipsTestBodies has grown too wide.
func TestHelperMissingTHelperRuleKeepsHelpers(t *testing.T) {
	longBody := strings.Repeat("\t_ = mode\n", 30)
	cases := map[string]string{
		"short helper named like a test":    "func testRouteNotOK(method string, t *testing.T) {\n\tif method == \"\" {\n\t\tt.Fatal(\"empty\")\n\t}\n}",
		"long helper not named like a test": "func checkHeaders(t *testing.T, mode bool) {\n" + longBody + "\tt.Fatal(\"failed\")\n}",
		"long test-named helper that returns a value": "func testServer(t *testing.T, mode bool) int {\n" + longBody +
			"\tt.Fatal(\"failed\")\n\treturn 0\n}",
		"benchmark helper without a timing loop": `func mustOpen(b *testing.B, path string) {
	if path == "" {
		b.Fatal("empty")
	}
}`,
		"closure failing through the helper's handle": `func check(t *testing.T) {
	defer func() { t.Fatal("failed") }()
}`,
		"subtest closure failing through the outer handle": `func checkOuter(t *testing.T) {
	t.Run("x", func(st *testing.T) {
		t.Fatal("outer")
	})
}`,
		"Helper on a value that was not asserted": `type marker struct{}

func (marker) Helper() {}

func checkMarked(t *testing.T, m marker) {
	m.Helper()
	t.Fatal("failed")
}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			unit := parseOne(t, "helpers_test.go", "package sample\n\nimport \"testing\"\n\n"+body+"\n")
			if got := (HelperMissingTHelperRule{}).AnalyzeUnit(unit, Context{}); len(got) != 1 {
				t.Fatalf("findings = %#v, want one", got)
			}
		})
	}
}
