// Package rule defines gruff-go's rule registry and analysers.
// This file exercises the builtin rule pack and shared helpers.
package rule

import (
	"go/ast"
	"os"
	"path/filepath"
	"testing"

	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// TestDefaultsListRules verifies the default registry exposes the expected rule IDs.
func TestDefaultsListRules(t *testing.T) {
	defaults := Defaults()
	definitions := defaults.Definitions()
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
		"design.god-function",
		"design.hotspot-file",
		"docs.comment-rubric",
		"docs.config-field-comment",
		"docs.exported-symbol-comment",
		"docs.package-comment",
		"naming.acronym-case",
		"naming.contextual-generic",
		"naming.get-prefix",
		"naming.identifier-quality",
		"naming.misspelling",
		"naming.negated-boolean",
		"naming.package-stutter",
		"naming.package-underscore",
		"naming.receiver-consistency",
		"security.shell-command",
		"sensitive-data.aws-access-key",
		"sensitive-data.connection-string",
		"sensitive-data.jwt-token",
		"sensitive-data.private-key",
		"sensitive-data.secret-pattern",
		"size.file-length",
		"size.function-length",
		"size.parameter-count",
		"test-quality.empty-test",
		"test-quality.no-failure-path",
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
	// docs.config-field-comment ships default-disabled; all other shipped rules are default-enabled.
	defaultDisabled := map[string]bool{"docs.config-field-comment": true}
	for _, id := range want {
		if defaultDisabled[id] {
			if enabled[id] {
				t.Fatalf("rule %s should be default disabled", id)
			}
			continue
		}
		if !enabled[id] {
			t.Fatalf("rule %s should be default enabled", id)
		}
	}
}

// TestSizeRules covers the file-length and function-length rules on long and short units.
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

// TestCyclomaticComplexityRule confirms the rule fires for highly branching functions.
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

// TestCyclomaticComplexityCases exercises the cyclomatic helper across control-flow shapes.
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

// TestPackageCommentRule verifies the rule fires only on packages without a package comment.
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

// TestPackageCommentRuleSkipsExternalTestPackages confirms that an external xxx_test package without its own summary is not reported, while the sibling production package without one still produces a finding.
func TestPackageCommentRuleSkipsExternalTestPackages(t *testing.T) {
	production := parseOne(t, "pkg/prod.go", `package pkg
`)
	externalTest := parseOne(t, "pkg/prod_test.go", `package pkg_test
`)

	findings := PackageCommentRule{}.AnalyzeProject([]parser.Unit{production, externalTest}, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one production package finding", findings)
	}
	if findings[0].File != "pkg/prod.go" || findings[0].Message != "package pkg has no package comment" {
		t.Fatalf("finding = %#v, want production package comment finding", findings[0])
	}
}

// TestSensitiveDataRule verifies the rule flags common secret-like assignment lines.
func TestSensitiveDataRule(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{name: "api key env", line: "api_key = \"12345678901234567890\""},
		{name: "api key short declaration", line: "apiKey := \"12345678901234567890\""},
		{name: "auth token", line: "auth_token = \"abcdefghijklmnopqrstuvwxyz123456\""},
		{name: "access token", line: "access-token = \"abcdefghijklmnopqrstuvwxyz123456\""},
		{name: "refresh token camel", line: "refreshToken = \"abcdefghijklmnopqrstuvwxyz123456\""},
		{name: "client secret", line: "client_secret: \"abcdefghijklmnopqrstuvwxyz123456\""},
		{name: "bearer value", line: "bearer = \"abcdefghijklmnopqrstuvwxyz123456\""},
		{name: "authorization bearer value", line: "authorization = \"Bearer abcdefghijklmnopqrstuvwxyz123456\""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parser.Unit{
				File:   source.File{Path: "config.env", Type: source.FileTypeText},
				Source: tt.line + "\n",
			}
			findings := SensitiveDataRule{}.AnalyzeUnit(unit, Context{})
			if len(findings) != 1 {
				t.Fatalf("findings = %#v, want one secret finding", findings)
			}
			if findings[0].Metadata["preview"] == "" {
				t.Fatalf("finding preview missing: %#v", findings[0])
			}
		})
	}
}

// TestSensitiveDataRuleIgnoresInnocuousKeyShapedConfig avoids false positives on configish lines.
func TestSensitiveDataRuleIgnoresInnocuousKeyShapedConfig(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{name: "plain non secret", line: "name = \"not-secret\""},
		{name: "token refresh bool", line: "enabled_token_refresh = true"},
		{name: "token refresh long value", line: "enabled_token_refresh = \"abcdefghijklmnopqrstuvwxyz123456\""},
		{name: "token ttl", line: "token_ttl = 3600"},
		{name: "access token enabled", line: "access_token_enabled = \"abcdefghijklmnopqrstuvwxyz123456\""},
		{name: "bearer mode", line: "bearer_mode = \"abcdefghijklmnopqrstuvwxyz123456\""},
		{name: "short bearer authorization", line: "authorization = \"Bearer short\""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := parser.Unit{
				File:   source.File{Path: "config.env", Type: source.FileTypeText},
				Source: tt.line + "\n",
			}
			if got := (SensitiveDataRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
				t.Fatalf("findings = %#v, want none", got)
			}
		})
	}
}

// TestExpansionRules covers the expansion rule pack (package name, empty block, shell, skip).
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

	// Confirm Skip-named calls on non-testing receivers do not produce
	// findings. Without the receiver-type check the matcher would treat any
	// .Skip()/.Skipf()/.SkipNow() selector as a testing skip, false-flagging
	// queue clients, table iterators, and similar third-party APIs.
	thirdPartyUnit := parseOne(t, "third_party_test.go", `// Package sample is a test package.
package sample

import "testing"

type Iter struct{}

func (Iter) Skip()         {}
func (Iter) Skipf(string)  {}
func (Iter) SkipNow()      {}

func TestThirdPartySkipIgnored(t *testing.T) {
	iter := Iter{}
	iter.Skip()
	iter.Skipf("x")
	iter.SkipNow()
}
`)
	got := SkippedTestRule{}.AnalyzeUnit(thirdPartyUnit, Context{})
	if len(got) != 0 {
		t.Fatalf("third-party .Skip() calls must not be flagged; got %#v", got)
	}
}

// TestExpansionRulesFireByDefault confirms expansion rules fire under Defaults() and can be disabled.
func TestExpansionRulesFireByDefault(t *testing.T) {
	unit := parseOne(t, "empty.go", `// Package sample is a test package.
package sample

func empty(a bool) {
	if a {}
}
`)
	defaults := Defaults()
	if findings := defaults.Analyze([]parser.Unit{unit}, Context{}); !containsRuleID(findings, "dead-code.empty-block") {
		t.Fatalf("default findings = %#v, want dead-code.empty-block fired", findings)
	}

	disabledRegistry, err := DefaultsConfigured(Config{
		Enabled: map[string]bool{"dead-code.empty-block": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings := disabledRegistry.Analyze([]parser.Unit{unit}, Context{})
	if containsRuleID(findings, "dead-code.empty-block") {
		t.Fatalf("disabled findings = %#v, want dead-code.empty-block silenced", findings)
	}
}

// parseOne writes contents to a temp file and returns the parsed unit; used by rule tests.
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
