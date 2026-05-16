package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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

func TestGoldenConfigLoading(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	writeFile(t, root, ".gruff.yaml", `
rules:
  complexity.cyclomatic:
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

func TestGoldenOptInExpansionRules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "expansion.go", expansionFixture())
	writeFile(t, root, ".gruff.yaml", `
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
	assertGolden(t, "analyse-opt-in-expansion.golden", normalizeGoldenOutput(root, stdout))
}

func expansionFixture() string {
	return `// Package sample is a test package.
package sample

func Wide(a, b, c, d, e, f int) {
	if a > 0 {
		if b > 0 {
			if c > 0 {
				if d > 0 {
					if e > 0 {
						_ = f
					}
				}
			}
		}
	}
}
`
}

func TestGoldenDiffMode(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required for diff-mode golden coverage")
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

func runGoldenCLI(args ...string) (string, string, int) {
	var stdout, stderr bytes.Buffer
	code := Main(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func assertGolden(t *testing.T, name string, got string) {
	t.Helper()
	path := goldenPath(t, name)
	got = normalizeLineEndings(got)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := normalizeLineEndings(string(expected)); got != want {
		t.Fatalf("golden %s mismatch\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

func goldenPath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve golden test path")
	}
	return filepath.Join(filepath.Dir(file), "testdata", "golden", name)
}

func normalizeGoldenOutput(root string, value string) string {
	value = normalizeLineEndings(value)
	value = strings.ReplaceAll(value, root, "<WORKDIR>")
	value = strings.ReplaceAll(value, filepath.ToSlash(root), "<WORKDIR>")
	return value
}

func normalizeLineEndings(value string) string {
	return strings.ReplaceAll(value, "\r\n", "\n")
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(output))
	}
}
