// Package cli implements the gruff-go command-line interface.
// This file covers shared flag parity across commands.
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionFlag verifies both --version and -V emit the tool version string.
func TestVersionFlag(t *testing.T) {
	for _, flag := range []string{"--version", "-V"} {
		var out, errBuf bytes.Buffer
		if code := Main([]string{flag}, &out, &errBuf); code != 0 {
			t.Errorf("%s exit = %d, stderr = %s", flag, code, errBuf.String())
		}
		if !strings.Contains(out.String(), "gruff-go "+toolVersion) {
			t.Errorf("%s output = %q, want version", flag, out.String())
		}
	}
}

// TestQuietSuppressesStdout verifies the --quiet flag silences non-error output.
func TestQuietSuppressesStdout(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"--quiet", "analyse", "."}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("--quiet stdout = %q, want empty", out.String())
	}
}

// TestNoAnsiSuppressesEscapes verifies the --no-ansi flag strips ANSI escapes.
func TestNoAnsiSuppressesEscapes(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := Main([]string{"--no-ansi", "--help"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Errorf("--no-ansi output contains ANSI escapes: %q", out.String())
	}
}

// TestAnsiForcesEscapes verifies the --ansi flag forces ANSI escapes regardless of TTY.
func TestAnsiForcesEscapes(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := Main([]string{"--ansi", "--help"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out.String(), "\x1b[33m") {
		t.Errorf("--ansi output missing yellow escape: %q", out.String())
	}
	if !strings.Contains(out.String(), "\x1b[32m") {
		t.Errorf("--ansi output missing green escape: %q", out.String())
	}
}

// TestHelpForCommandShowsUsage verifies help renders usage for each known subcommand.
func TestHelpForCommandShowsUsage(t *testing.T) {
	for _, cmd := range []string{"analyse", "baseline", "completion", "init", "list-rules", "summary", "report", "dashboard"} {
		var out, errBuf bytes.Buffer
		if code := Main([]string{"help", cmd}, &out, &errBuf); code != 0 {
			t.Errorf("help %s exit = %d, stderr = %s", cmd, code, errBuf.String())
		}
		if !strings.Contains(out.String(), "gruff-go "+cmd) {
			t.Errorf("help %s missing command name; got %q", cmd, out.String())
		}
	}
}

// TestHelpUnknownCommandFails verifies unknown command names produce exit code 2.
func TestHelpUnknownCommandFails(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := Main([]string{"help", "doesnotexist"}, &out, &errBuf); code != 2 {
		t.Errorf("help doesnotexist exit = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "unknown command") {
		t.Errorf("stderr should mention unknown command: %q", errBuf.String())
	}
}

// TestListAliasMatchesUsage verifies list and --help emit identical usage text.
func TestListAliasMatchesUsage(t *testing.T) {
	var listOut, helpOut, errBuf bytes.Buffer
	if code := Main([]string{"list"}, &listOut, &errBuf); code != 0 {
		t.Fatalf("list exit = %d", code)
	}
	if code := Main([]string{"--help"}, &helpOut, &errBuf); code != 0 {
		t.Fatalf("--help exit = %d", code)
	}
	if listOut.String() != helpOut.String() {
		t.Errorf("list and --help should produce identical output")
	}
}

// TestGlobalCompatibilityAliases verifies cross-gruff global aliases are accepted.
func TestGlobalCompatibilityAliases(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := Main([]string{"--silent", "-v", "list"}, &out, &errBuf); code != 0 {
		t.Fatalf("list with compatibility aliases exit = %d, stderr = %s", code, errBuf.String())
	}
	if out.String() != "" {
		t.Fatalf("--silent should suppress normal output, got %q", out.String())
	}
}

// TestCompletionCommand emits a shell completion script.
func TestCompletionCommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := Main([]string{"completion"}, &out, &errBuf); code != 0 {
		t.Fatalf("completion exit = %d, stderr = %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "complete -F _gruff_go_complete gruff-go") {
		t.Fatalf("completion output missing bash registration: %s", out.String())
	}
}

// TestSummaryCommandText verifies the summary text output contains expected fragments.
func TestSummaryCommandText(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"summary", "."}, &out, &errBuf); code != 0 {
		t.Fatalf("summary exit = %d, stderr = %s", code, errBuf.String())
	}
	for _, fragment := range []string{
		"gruff-go summary",
		"scanned: . (in ",
		"files: ",
		" analysed, ",
		" skipped",
		"scan time: ",
		"score:",
		"findings:",
		"severity:",
	} {
		if !strings.Contains(out.String(), fragment) {
			t.Errorf("summary missing %q; got: %s", fragment, out.String())
		}
	}
}

// TestSummaryCommandShowsGitignoredCount gives new users a quick explanation
// for skipped files without changing machine-readable summary JSON.
func TestSummaryCommandShowsGitignoredCount(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gitignore", "ignored.go\n")
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	writeFile(t, root, "ignored.go", "package main\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"summary", "."}, &out, &errBuf); code != 0 {
		t.Fatalf("summary exit = %d, stderr = %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "ignored by .gitignore: 1") {
		t.Fatalf("summary missing gitignored count; got: %s", out.String())
	}
}

// TestSummaryCommandSuggestsGeneratedBaseline checks the text-only fresh-start
// hint appears when a first summary finds existing debt.
func TestSummaryCommandSuggestsGeneratedBaseline(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"summary", "complex.go"}, &out, &errBuf); code != 1 {
		t.Fatalf("summary exit = %d, stderr = %s", code, errBuf.String())
	}
	for _, fragment := range []string{
		"fresh start: gruff-go analyse --generate-baseline gruff-baseline.json complex.go",
		"then scan with: gruff-go analyse --baseline gruff-baseline.json complex.go",
	} {
		if !strings.Contains(out.String(), fragment) {
			t.Fatalf("summary missing %q; got: %s", fragment, out.String())
		}
	}
}

// TestSummaryCommandDefaultPath verifies running summary with no path argument
// scans the current working directory.
func TestSummaryCommandDefaultPath(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"summary"}, &out, &errBuf); code != 0 {
		t.Fatalf("summary (no path) exit = %d, stderr = %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "scanned: . (in ") {
		t.Errorf("summary (no path) missing default-path line; got: %s", out.String())
	}
	if !strings.Contains(out.String(), "files: 1 analysed") {
		t.Errorf("summary (no path) should report 1 file analysed; got: %s", out.String())
	}
}

// TestSummaryRejectsBadFormat verifies summary returns exit code 2 on unknown formats.
func TestSummaryRejectsBadFormat(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"summary", "--format", "yaml", "."}, &out, &errBuf); code != 2 {
		t.Errorf("bad format exit = %d, want 2", code)
	}
}

// TestReportCommandHTMLToFile verifies report --output writes HTML to disk.
func TestReportCommandHTMLToFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Chdir(root)

	outPath := filepath.Join(t.TempDir(), "report.html")
	var out, errBuf bytes.Buffer
	if code := Main([]string{"report", "--format", "html", "--output", outPath, "."}, &out, &errBuf); code != 0 {
		t.Fatalf("report exit = %d, stderr = %s", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("--output should silence stdout, got: %s", out.String())
	}
	content, err := readFileToString(outPath)
	if err != nil {
		t.Fatalf("read %s: %v", outPath, err)
	}
	if !strings.HasPrefix(content, "<!DOCTYPE html>") {
		t.Errorf("report file should start with <!DOCTYPE html>, got: %s", content[:min(120, len(content))])
	}
}

// TestReportRejectsBadFormat verifies report returns exit code 2 on unknown formats.
func TestReportRejectsBadFormat(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"report", "--format", "txt", "."}, &out, &errBuf); code != 2 {
		t.Errorf("bad report format exit = %d, want 2", code)
	}
}

// readFileToString reads path and returns its contents as a string.
func readFileToString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
