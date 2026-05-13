package rule

import (
	"go/ast"
	"os"
	"path/filepath"
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

func TestDefaultsListRules(t *testing.T) {
	definitions := Defaults().Definitions()
	got := make([]string, 0, len(definitions))
	enabled := map[string]bool{}
	for _, definition := range definitions {
		got = append(got, definition.ID)
		enabled[definition.ID] = definition.DefaultEnabled
	}
	want := []string{
		"complexity.cyclomatic",
		"complexity.nesting-depth",
		"dead-code.empty-block",
		"docs.exported-symbol-comment",
		"docs.package-comment",
		"naming.package-underscore",
		"security.shell-command",
		"sensitive-data.secret-pattern",
		"size.file-length",
		"size.function-length",
		"size.parameter-count",
		"test-quality.skipped-test",
	}
	if len(got) != len(want) {
		t.Fatalf("rules = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rules = %#v, want %#v", got, want)
		}
	}
	for _, id := range []string{
		"complexity.cyclomatic",
		"docs.package-comment",
		"sensitive-data.secret-pattern",
		"size.file-length",
		"size.function-length",
	} {
		if !enabled[id] {
			t.Fatalf("rule %s should be default enabled", id)
		}
	}
	for _, id := range []string{
		"complexity.nesting-depth",
		"dead-code.empty-block",
		"docs.exported-symbol-comment",
		"naming.package-underscore",
		"security.shell-command",
		"size.parameter-count",
		"test-quality.skipped-test",
	} {
		if enabled[id] {
			t.Fatalf("rule %s should be default disabled", id)
		}
	}
}

func TestSizeRules(t *testing.T) {
	unit := parser.Unit{
		File:      source.File{Path: "long.go", Type: source.FileTypeGo},
		LineCount: fileLengthThreshold + 1,
		Functions: []parser.Function{{
			Name:    "Long",
			Line:    1,
			EndLine: functionLengthThreshold + 2,
		}},
	}

	fileFindings := FileLengthRule{}.AnalyzeUnit(unit, Context{})
	if len(fileFindings) != 1 {
		t.Fatalf("file findings = %#v, want one", fileFindings)
	}
	functionFindings := FunctionLengthRule{}.AnalyzeUnit(unit, Context{})
	if len(functionFindings) != 1 || functionFindings[0].Symbol != "Long" {
		t.Fatalf("function findings = %#v, want Long finding", functionFindings)
	}

	shortUnit := parser.Unit{
		File:      source.File{Path: "short.go", Type: source.FileTypeGo},
		LineCount: 10,
		Functions: []parser.Function{{
			Name:    "Short",
			Line:    1,
			EndLine: 5,
		}},
	}
	if got := (FileLengthRule{}).AnalyzeUnit(shortUnit, Context{}); len(got) != 0 {
		t.Fatalf("short file findings = %#v, want none", got)
	}
	if got := (FunctionLengthRule{}).AnalyzeUnit(shortUnit, Context{}); len(got) != 0 {
		t.Fatalf("short function findings = %#v, want none", got)
	}
}

func TestCyclomaticComplexityRule(t *testing.T) {
	unit := parseOne(t, "complex.go", `// Package sample is a test package.
package sample

func risky(a bool) {
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
}`)

	findings := CyclomaticComplexityRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 || findings[0].Symbol != "risky" {
		t.Fatalf("findings = %#v, want risky complexity finding", findings)
	}
}

func TestCyclomaticComplexityCases(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "straight-line", body: `x := 1
_ = x`, want: 1},
		{name: "nested branches", body: `if a {
	if b {}
}`, want: 3},
		{name: "switch", body: `switch {
case a:
case b:
default:
}`, want: 3},
		{name: "loops", body: `for i := 0; i < 1; i++ {}
for range []int{} {}`, want: 3},
		{name: "early return", body: `if a {
	return
}
return`, want: 2},
		{name: "anonymous function skipped", body: `_ = func() {
	if a {}
}`, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parseOne(t, "case.go", `// Package sample is a test package.
package sample

func sample(a bool, b bool) {
`+tt.body+`
}`)
			fn := unit.AST.Decls[0].(*ast.FuncDecl)
			if got := cyclomaticComplexity(fn); got != tt.want {
				t.Fatalf("complexity = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPackageCommentRule(t *testing.T) {
	withComment := parseOne(t, "with/comment.go", `// Package withcomment explains itself.
package withcomment
`)
	withoutComment := parseOne(t, "without/comment.go", `package withoutcomment
`)

	findings := PackageCommentRule{}.AnalyzeProject([]parser.Unit{withComment, withoutComment}, Context{})
	if len(findings) != 1 || findings[0].File != "without/comment.go" {
		t.Fatalf("findings = %#v, want missing package comment finding", findings)
	}
}

func TestSensitiveDataRule(t *testing.T) {
	unit := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "api_key = \"12345678901234567890\"\n",
	}
	findings := SensitiveDataRule{}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one secret finding", findings)
	}
	if findings[0].Metadata["preview"] == "" {
		t.Fatalf("finding preview missing: %#v", findings[0])
	}
	clean := parser.Unit{
		File:   source.File{Path: "config.env", Type: source.FileTypeText},
		Source: "name = \"not-secret\"\n",
	}
	if got := (SensitiveDataRule{}).AnalyzeUnit(clean, Context{}); len(got) != 0 {
		t.Fatalf("clean findings = %#v, want none", got)
	}
}

func TestExpansionRules(t *testing.T) {
	packageUnit := parseOne(t, "bad/package.go", `// Package bad_name is a test package.
package bad_name
`)
	packageFindings := PackageNameUnderscoreRule{}.AnalyzeProject([]parser.Unit{packageUnit}, Context{})
	if len(packageFindings) != 1 || packageFindings[0].RuleID != "" {
		t.Fatalf("package findings = %#v, want one package-name finding before registry metadata", packageFindings)
	}

	emptyUnit := parseOne(t, "empty.go", `// Package sample is a test package.
package sample

func empty(a bool) {
	if a {}
	for {}
}
`)
	emptyFindings := EmptyBlockRule{}.AnalyzeUnit(emptyUnit, Context{})
	if len(emptyFindings) != 2 {
		t.Fatalf("empty block findings = %#v, want two", emptyFindings)
	}

	shellUnit := parseOne(t, "shell.go", `// Package sample is a test package.
package sample

import "os/exec"

func shell() {
	exec.Command("bash", "-c", "echo hi")
	exec.Command("git", "status")
}
`)
	shellFindings := ShellCommandRule{}.AnalyzeUnit(shellUnit, Context{})
	if len(shellFindings) != 1 {
		t.Fatalf("shell findings = %#v, want one", shellFindings)
	}

	skipUnit := parseOne(t, "skip_test.go", `// Package sample is a test package.
package sample

import "testing"

func TestSkipped(t *testing.T) {
	t.Skip("later")
}
`)
	skipFindings := SkippedTestRule{}.AnalyzeUnit(skipUnit, Context{})
	if len(skipFindings) != 1 {
		t.Fatalf("skip findings = %#v, want one", skipFindings)
	}
}

func TestExpansionRulesAreOptIn(t *testing.T) {
	unit := parseOne(t, "empty.go", `// Package sample is a test package.
package sample

func empty(a bool) {
	if a {}
}
`)
	defaults := Defaults()
	if findings := defaults.Analyze([]parser.Unit{unit}, Context{}); len(findings) != 0 {
		t.Fatalf("default findings = %#v, want disabled expansion rules skipped", findings)
	}

	enabledRegistry, err := DefaultsConfigured(Config{
		Enabled: map[string]bool{"dead-code.empty-block": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings := enabledRegistry.Analyze([]parser.Unit{unit}, Context{})
	if len(findings) != 1 || findings[0].RuleID != "dead-code.empty-block" {
		t.Fatalf("enabled findings = %#v, want dead-code.empty-block", findings)
	}
}

func parseOne(t *testing.T, rel string, contents string) parser.Unit {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	units, diagnostics := parser.Parse([]source.File{{Path: rel, AbsPath: path, Type: source.FileTypeGo}})
	if len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	if len(units) != 1 {
		t.Fatalf("units = %d, want 1", len(units))
	}
	return units[0]
}
