// Package rule tests the core findings users receive from gruff-go.
// Fixtures cover size, complexity, documentation, and sensitive-data checks.
// They keep each rule's detection and remediation behavior reviewable.
package rule

import (
	"go/ast"
	"os"
	"path/filepath"
	"strings"
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
	want := defaultRuleIDs()
	if len(got) != len(want) {
		t.Fatalf("rules = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rules = %#v, want %#v", got, want)
		}
	}
	defaultDisabled := defaultDisabledRuleIDs()
	for _, id := range want {
		if enabled[id] == defaultDisabled[id] {
			t.Fatalf("rule %s defaultEnabled = %v, want %v", id, enabled[id], !defaultDisabled[id])
		}
	}
}

// TestSizeRules covers the file-length and function-length rules on long and short units.
func TestSizeRules(t *testing.T) {
	unit := parser.Unit{
		File:      source.File{Path: "long.go", Type: source.FileTypeGo},
		LineCount: fileLengthThreshold + 1,
		Source:    strings.Repeat("line\n", fileLengthThreshold+1),
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

// TestSensitiveDataRuleSkipsGoCommentOnlyLines aligns the generic secret-pattern
// rule with the exact sensitive-data rules' Go comment boundary.
func TestSensitiveDataRuleSkipsGoCommentOnlyLines(t *testing.T) {
	tokenValue := secretPatternFixtureValue()
	cases := map[string]string{
		"line comment":  "package pkg\n\n// auth_token = \"" + tokenValue + "\"\nfunc Run() {}\n",
		"block comment": "/*\nclient_secret: \"" + tokenValue + "\"\n*/\npackage pkg\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			unit := parseOne(t, "pkg/comment.go", src)
			if got := (SensitiveDataRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
				t.Fatalf("comment-only secret assignment should not flag, got %#v", got)
			}
		})
	}
}

// TestSensitiveDataRuleStillFlagsCodeBearingAssignments keeps the generic rule
// strict on real source and config assignments.
//
// The raw-string case changed on 2026-09-07: a backtick literal holds documentation, templates
// and sample payloads, so its interior is no longer scanned. The fixture below names its own
// literal `docs`, which is the case the change is about. Interpreted strings are untouched.
func TestSensitiveDataRuleStillFlagsCodeBearingAssignments(t *testing.T) {
	tokenValue := secretPatternFixtureValue()
	goUnit := parseOne(t, "pkg/secrets.go", "package pkg\n\n"+
		"const authToken = \""+tokenValue+"\"\n"+
		"const accessToken = \""+tokenValue+"\" // fixture comment\n"+
		"const docs = `auth_token = \""+tokenValue+"\"`\n")
	goFindings := SensitiveDataRule{}.AnalyzeUnit(goUnit, Context{})
	if len(goFindings) != 2 {
		t.Fatalf("the two interpreted-string assignments should flag and the raw string should not, got %#v", goFindings)
	}

	textUnit := parser.Unit{
		File:   source.File{Path: "config.yaml", Type: source.FileTypeText},
		Source: "auth_token: " + tokenValue + "\n",
	}
	if got := (SensitiveDataRule{}).AnalyzeUnit(textUnit, Context{}); len(got) != 1 {
		t.Fatalf("text/config assignment should still flag, got %#v", got)
	}
}

// TestSensitiveDataRuleSkipsGoGeneratedSecretValues avoids treating calls that
// produce credentials at runtime as embedded literals.
func TestSensitiveDataRuleSkipsGoGeneratedSecretValues(t *testing.T) {
	unit := parseOne(t, "pkg/secrets.go", `package pkg

func Run(randomBytes []byte) {
	password := base64.RawURLEncoding.EncodeToString(randomBytes)
	accessToken := buildAuthenticationTokenValue()
	_ = password
	_ = accessToken
}
`)
	if got := (SensitiveDataRule{}).AnalyzeUnit(unit, Context{}); len(got) != 0 {
		t.Fatalf("runtime-generated secret values should not flag as embedded literals, got %#v", got)
	}
}

// TestSensitiveDataRuleSkipsPlaceholderExamples confirms OpenAPI-style
// placeholders are documentation, while adjacent raw token values still fire.
func TestSensitiveDataRuleSkipsPlaceholderExamples(t *testing.T) {
	placeholder := parser.Unit{
		File:   source.File{Path: "openapi.yaml", Type: source.FileTypeText},
		Source: "examples:\n  token: ${sessionToken}\n",
	}
	if got := (SensitiveDataRule{}).AnalyzeUnit(placeholder, Context{}); len(got) != 0 {
		t.Fatalf("placeholder example should not flag, got %#v", got)
	}

	raw := parser.Unit{
		File:   source.File{Path: "openapi.yaml", Type: source.FileTypeText},
		Source: "examples:\n  auth_token: " + secretPatternFixtureValue() + "\n",
	}
	if got := (SensitiveDataRule{}).AnalyzeUnit(raw, Context{}); len(got) != 1 {
		t.Fatalf("raw example token should still flag, got %#v", got)
	}
}

// secretPatternFixtureValue builds the token body across literals so dogfood
// scans do not treat this test file itself as containing a credential.
func secretPatternFixtureValue() string {
	return "abcdefghijklmnopqrstuvwxyz" + "123456"
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

// TestPackageNameUnderscoreRuleSkipsExternalTestPackages confirms idiomatic
// black-box test packages (`package foo_test`) are not treated as bad package
// names, while genuinely underscored package names remain in scope.
func TestPackageNameUnderscoreRuleSkipsExternalTestPackages(t *testing.T) {
	externalTest := parseOne(t, "pkg/api_test.go", `package api_test
`)
	badExternalTest := parseOne(t, "bad/bad_pkg_test.go", `package bad_pkg_test
`)
	production := parseOne(t, "bad/bad_pkg.go", `package bad_pkg
`)

	findings := PackageNameUnderscoreRule{}.AnalyzeProject([]parser.Unit{externalTest, badExternalTest, production}, Context{})
	got := map[string]bool{}
	for _, item := range findings {
		got[item.File] = true
	}
	if got["pkg/api_test.go"] {
		t.Fatalf("external api_test package should not be flagged; got %#v", findings)
	}
	if !got["bad/bad_pkg_test.go"] || !got["bad/bad_pkg.go"] {
		t.Fatalf("bad_pkg packages should still be flagged; got %#v", findings)
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

// TestFileLengthAnchorsToSubstantiveThresholdLine pins the finding to the physical
// line where the substantive-line budget is actually spent. Counting skips blanks
// and comments, so a documented file crosses the threshold far below its physical
// line number; anchoring to the raw count would drop the finding outside a
// changed-region scan of the code that caused it.
func TestFileLengthAnchorsToSubstantiveThresholdLine(t *testing.T) {
	var builder strings.Builder
	builder.WriteString("// Package sample is a test package.\npackage sample\n")
	for index := 0; index < 20; index++ {
		builder.WriteString("// filler comment\n")
	}
	for index := 0; index < 8; index++ {
		builder.WriteString("var V" + string(rune('a'+index)) + " = 1\n")
	}
	unit := parseOne(t, "long.go", builder.String())

	findings := FileLengthRule{MaxLines: 5}.AnalyzeUnit(unit, Context{})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	// package + 5 vars = 6 substantive lines; the 6th sits after the comment block.
	const wantLine = 27
	if got := findings[0].Location.Line; got != wantLine {
		t.Fatalf("finding line = %d, want %d (physical line of the 6th substantive line)", got, wantLine)
	}
}
