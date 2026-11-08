// Package cli implements the gruff-go command-line interface.
//
// This file holds golden-file CLI tests that lock down rendered output against files under testdata/golden.
// When an output change is intended, regenerate with UPDATE_GOLDEN=1 go test ./internal/cli/... and review the diff.
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestGoldenAnalysisFormats compares analyse text, summary-json, sarif and github output, plus list-rules text, against golden files.
// Each case also requires its exit code and an empty stderr; an exit mismatch prints both streams to show what changed.
func TestGoldenAnalysisFormats(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
	}{
		{name: "analyse-text.golden", args: []string{"analyse", "--format", "text", "complex.go"}, code: 1},
		{name: "analyse-summary-json.golden", args: []string{"analyse", "--format", "summary-json", "complex.go"}, code: 1},
		{name: "analyse-sarif.golden", args: []string{"analyse", "--format", "sarif", "complex.go"}, code: 1},
		{name: "analyse-github.golden", args: []string{"analyse", "--format", "github", "complex.go"}, code: 1},
		{name: "list-rules-text.golden", args: []string{"list-rules", "--format", "text"}, code: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "complex.go", complexFixture())
			t.Chdir(root)

			stdout, stderr, code := runGoldenCLI(tc.args...)
			if code != tc.code {
				t.Fatalf("exit = %d, want %d\nstderr:\n%s\nstdout:\n%s", code, tc.code, stderr, stdout)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, want empty", stderr)
			}
			assertGolden(t, tc.name, normalizeGoldenOutput(root, stdout))
		})
	}
}

// TestGoldenConfigLoading locks down summary output when a config file is loaded.
func TestGoldenConfigLoading(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	writeFile(t, root, ".gruff-go.yaml", `
schemaVersion: gruff-go.config.v0.1
rules:
  complexity.cognitive:
    threshold: 100
`)
	t.Chdir(root)

	stdout, stderr, code := runGoldenCLI("analyse", "--format", "summary-json", "complex.go")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr:\n%s\nstdout:\n%s", code, stderr, stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	assertGolden(t, "config-summary-json.golden", normalizeGoldenOutput(root, stdout))
}

// TestGoldenBaselineSuppression locks down output for baseline suppression flows.
func TestGoldenBaselineSuppression(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	stdout, stderr, code := runGoldenCLI("baseline", "--out", "baseline.json", "complex.go")
	if code != 0 {
		t.Fatalf("baseline exit = %d, want 0\nstderr:\n%s\nstdout:\n%s", code, stderr, stdout)
	}
	if stderr != "" {
		t.Fatalf("baseline stderr = %q, want empty", stderr)
	}
	assertGolden(t, "baseline-command.golden", stdout)

	stdout, stderr, code = runGoldenCLI("analyse", "--format", "summary-json", "--baseline", "baseline.json", "complex.go")
	if code != 0 {
		t.Fatalf("analyse exit = %d, want 0\nstderr:\n%s\nstdout:\n%s", code, stderr, stdout)
	}
	if stderr != "" {
		t.Fatalf("analyse stderr = %q, want empty", stderr)
	}
	assertGolden(t, "baseline-summary-json.golden", normalizeGoldenOutput(root, stdout))
}

// TestGoldenConfiguredExpansionRules locks down output when expansion rules are configured explicitly.
func TestGoldenConfiguredExpansionRules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "expansion.go", expansionFixture())
	writeFile(t, root, ".gruff-go.yaml", `
schemaVersion: gruff-go.config.v0.1
rules:
  size.parameter-count:
    enabled: true
  complexity.nesting-depth:
    enabled: true
  docs.exported-symbol-comment:
    enabled: true
`)
	t.Chdir(root)

	stdout, stderr, code := runGoldenCLI("analyse", "--format", "summary-json", "expansion.go")
	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstderr:\n%s\nstdout:\n%s", code, stderr, stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	assertGolden(t, "analyse-configured-expansion.golden", normalizeGoldenOutput(root, stdout))
}

// TestGoldenCompositeRuleOutputs locks down output when composite rules fire.
func TestGoldenCompositeRuleOutputs(t *testing.T) {
	cases := []struct {
		name   string
		format string
		code   int
	}{
		{name: "analyse-composite-summary-json.golden", format: "summary-json", code: 1},
		{name: "analyse-composite-sarif.golden", format: "sarif", code: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "composite.go", compositeFixture())
			writeFile(t, root, ".gruff-go.yaml", compositeConfig())
			t.Chdir(root)

			stdout, stderr, code := runGoldenCLI("analyse", "--format", tc.format, "composite.go")
			if code != tc.code {
				t.Fatalf("exit = %d, want %d\nstderr:\n%s\nstdout:\n%s", code, tc.code, stderr, stdout)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, want empty", stderr)
			}
			assertGolden(t, tc.name, normalizeGoldenOutput(root, stdout))
		})
	}
}

// expansionFixture returns Go source for TestGoldenConfiguredExpansionRules: Wide has nine parameters, six nested ifs and no doc comment.
// They target the rules the test config enables: size.parameter-count, complexity.nesting-depth and docs.exported-symbol-comment.
func expansionFixture() string {
	return `// Package sample is a test package.
package sample

func Wide(a, b, c, d, e, f, g, h, i int) {
	if a > 0 {
		if b > 0 {
			if c > 0 {
				if d > 0 {
					if e > 0 {
						if f > 0 {
							_ = g + h + i
						}
					}
				}
			}
		}
	}
}
`
}

// compositeFixture returns a Go source string that triggers composite rule findings.
func compositeFixture() string {
	return `// Package sample is a test package.
package sample

func Hot(a bool, b bool) {
	if a {
		_ = a
	}
	if b {
		_ = b
	}
}
`
}

// compositeConfig returns a YAML config enabling the rules compositeFixture needs to fire design.hotspot-file.
//
// It lowers size.function-length to 4 and complexity.cognitive to 2, and sets hotspot-file to minFindings 2 and minPillars 2.
// With those settings the small Hot function yields the two findings, from two pillars, that keep the golden on a composite rule.
// The default minFindings of 3 would leave the fixture below threshold.
func compositeConfig() string {
	return `
schemaVersion: gruff-go.config.v0.1
rules:
  size.function-length:
    threshold: 4
  complexity.cognitive:
    threshold: 2
  design.hotspot-file:
    enabled: true
    thresholds:
      minFindings: 2
      minPillars: 2
`
}

// TestGoldenDiffMode locks down diff-mode output by setting up a temp git repo.
func TestGoldenDiffMode(t *testing.T) {
	// A machine without git fails here rather than skipping, so diff-mode golden coverage is never lost silently.
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("git is required for diff-mode golden coverage: %v", err)
	}

	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "test@example.invalid")
	runGit(t, root, "config", "user.name", "Test User")
	writeFile(t, root, "complex.go", `// Package sample is a test package.
package sample

func risky(a bool) {}
`)
	runGit(t, root, "add", "complex.go")
	runGit(t, root, "commit", "-q", "-m", "base")
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	stdout, stderr, code := runGoldenCLI("analyse", "--format", "summary-json", "--diff-base", "HEAD", "complex.go")
	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstderr:\n%s\nstdout:\n%s", code, stderr, stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	assertGolden(t, "diff-summary-json.golden", normalizeGoldenOutput(root, stdout))
}

// TestAnalyseRespectsGitignoreByDefault confirms gitignored files are skipped by default.
func TestAnalyseRespectsGitignoreByDefault(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gitignore", "ignored.go\n*.log\n")
	writeFile(t, root, "main.go", "// Package main is a test package.\npackage main\n\nfunc main() {}\n")
	writeFile(t, root, "ignored.go", "// Package main is a test package.\npackage main\n")
	writeFile(t, root, "notes.log", "noise\n")
	t.Chdir(root)

	stdout, stderr, code := runGoldenCLI("analyse", "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr:\n%s\nstdout:\n%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, `"main.go"`) {
		t.Fatalf("main.go should be in scanned paths; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, `"path": "ignored.go"`) || !strings.Contains(stdout, `"reason": "gitignored"`) {
		t.Fatalf("ignored.go should appear in skipped with reason gitignored; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, `"path": "notes.log"`) {
		t.Fatalf("notes.log should appear in skipped; got:\n%s", stdout)
	}
	if strings.Contains(stdout, `"includeIgnored": true`) {
		t.Fatalf("includeIgnored should not be emitted on default analyse; got:\n%s", stdout)
	}
}

// TestAnalyseIncludeIgnoredBypassesGitignore checks that JSON records --include-ignored and names ignored.go without any gitignored skip reason.
func TestAnalyseIncludeIgnoredBypassesGitignore(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gitignore", "ignored.go\n")
	writeFile(t, root, "main.go", "// Package main is a test package.\npackage main\n\nfunc main() {}\n")
	writeFile(t, root, "ignored.go", "// Package main is a test package.\npackage main\n")
	t.Chdir(root)

	stdout, stderr, code := runGoldenCLI("analyse", "--format", "json", "--include-ignored")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr:\n%s\nstdout:\n%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, `"includeIgnored": true`) {
		t.Fatalf("--include-ignored should emit run.includeIgnored=true; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, `"ignored.go"`) {
		t.Fatalf("ignored.go should be scanned with --include-ignored; got:\n%s", stdout)
	}
	if strings.Contains(stdout, `"reason": "gitignored"`) {
		t.Fatalf("--include-ignored must not emit gitignored skipped entries; got:\n%s", stdout)
	}
}

// TestAnalyseIncludeIgnoredPreservesConfigIgnores confirms paths.ignore still applies under --include-ignored.
// secret.go is gitignored and in paths.ignore, so it must stay unscanned, appear in paths.ignoredPaths and keep the config-ignore reason.
func TestAnalyseIncludeIgnoredPreservesConfigIgnores(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gitignore", "secret.go\n")
	writeFile(t, root, ".gruff-go.yaml", "schemaVersion: gruff-go.config.v0.1\npaths:\n  ignore:\n    - secret.go\n")
	writeFile(t, root, "main.go", "// Package main is a test package.\npackage main\n\nfunc main() {}\n")
	writeFile(t, root, "secret.go", "// Package main is a test package.\npackage main\n")
	t.Chdir(root)

	stdout, stderr, code := runGoldenCLI("analyse", "--format", "json", "--include-ignored")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr:\n%s\nstdout:\n%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, `"includeIgnored": true`) {
		t.Fatalf("--include-ignored should emit run.includeIgnored=true; got:\n%s", stdout)
	}
	var parsed struct {
		Paths struct {
			IgnoredPaths []string `json:"ignoredPaths"`
			Details      []struct {
				Path   string `json:"path"`
				Reason string `json:"reason"`
			} `json:"details"`
			Extensions struct {
				Go struct {
					Paths struct {
						Scanned []string `json:"scanned"`
					} `json:"paths"`
				} `json:"go"`
			} `json:"extensions"`
		} `json:"paths"`
	}
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, stdout)
	}
	if slices.Contains(parsed.Paths.Extensions.Go.Paths.Scanned, "secret.go") {
		t.Fatalf("secret.go should not be scanned with config ignore; got %#v", parsed.Paths.Extensions.Go.Paths.Scanned)
	}
	if !slices.Contains(parsed.Paths.IgnoredPaths, "secret.go") {
		t.Fatalf("secret.go should be listed in paths.ignoredPaths; got %#v", parsed.Paths.IgnoredPaths)
	}
	configIgnoreReported := false
	for _, item := range parsed.Paths.Details {
		configIgnoreReported = configIgnoreReported || (item.Path == "secret.go" && item.Reason == "config-ignore")
	}
	if !configIgnoreReported {
		t.Fatalf("secret.go should remain config-ignored with --include-ignored; got %#v", parsed.Paths.Details)
	}
}

// runGoldenCLI invokes Main with args and returns captured stdout, stderr, and exit code.
func runGoldenCLI(args ...string) (string, string, int) {
	var stdout, stderr bytes.Buffer
	code := Main(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

// assertGolden compares got against the named golden file, honouring UPDATE_GOLDEN.
//
// name is the file under testdata/golden, and got is the actual output, compared after CRLF line endings become LF.
// When UPDATE_GOLDEN is 1 it writes the normalized got to the file instead; a read or write failure, or a mismatch, fails the test.
func assertGolden(t *testing.T, name string, got string) {
	t.Helper()
	path := goldenPath(t, name)
	got = normalizeLineEndings(got)
	// With UPDATE_GOLDEN=1 the actual output overwrites the golden file; review the diff, since a wrong output becomes the new expectation.
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	expected, err := os.ReadFile(path)
	// A new case whose golden file does not exist yet fails here; create it with UPDATE_GOLDEN=1 and review it.
	if err != nil {
		t.Fatal(err)
	}
	if want := normalizeLineEndings(string(expected)); got != want {
		t.Fatalf("golden %s mismatch\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

// goldenPath returns the on-disk location of the named golden file.
//
// name is the golden file name, joined under the testdata/golden directory beside this source file.
// The test fails when runtime.Caller cannot resolve that source file.
func goldenPath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve golden test path")
	}
	return filepath.Join(filepath.Dir(file), "testdata", "golden", name)
}

// normalizeGoldenOutput rewrites tmp paths to <WORKDIR> so goldens stay stable across runs.
//
// root is the temporary project directory and value is the CLI output; both the native and slash forms of root are replaced.
// It returns value with CRLF converted to LF and every occurrence of root replaced by <WORKDIR>.
func normalizeGoldenOutput(root string, value string) string {
	value = normalizeLineEndings(value)
	value = strings.ReplaceAll(value, root, "<WORKDIR>")
	value = strings.ReplaceAll(value, filepath.ToSlash(root), "<WORKDIR>")
	return value
}

// normalizeLineEndings rewrites CRLF into LF so goldens stay stable on Windows.
// It returns value with every CRLF pair replaced by LF; lone CR characters are left as they are.
func normalizeLineEndings(value string) string {
	return strings.ReplaceAll(value, "\r\n", "\n")
}

// runGit invokes git inside root and fails the test if the command errors.
// args are the git arguments after the program name, and on failure the message includes them and git's combined output.
func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(output))
	}
}
