package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestNoAnsiSuppressesEscapes(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := Main([]string{"--no-ansi", "--help"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Errorf("--no-ansi output contains ANSI escapes: %q", out.String())
	}
}

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

func TestHelpForCommandShowsUsage(t *testing.T) {
	for _, cmd := range []string{"analyse", "baseline", "list-rules", "summary", "report", "dashboard"} {
		var out, errBuf bytes.Buffer
		if code := Main([]string{"help", cmd}, &out, &errBuf); code != 0 {
			t.Errorf("help %s exit = %d, stderr = %s", cmd, code, errBuf.String())
		}
		if !strings.Contains(out.String(), "gruff-go "+cmd) {
			t.Errorf("help %s missing command name; got %q", cmd, out.String())
		}
	}
}

func TestHelpUnknownCommandFails(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := Main([]string{"help", "doesnotexist"}, &out, &errBuf); code != 2 {
		t.Errorf("help doesnotexist exit = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "unknown command") {
		t.Errorf("stderr should mention unknown command: %q", errBuf.String())
	}
}

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
		"score:",
		"findings:",
		"severity:",
	} {
		if !strings.Contains(out.String(), fragment) {
			t.Errorf("summary missing %q; got: %s", fragment, out.String())
		}
	}
}

func TestSummaryRejectsBadFormat(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"summary", "--format", "yaml", "."}, &out, &errBuf); code != 2 {
		t.Errorf("bad format exit = %d, want 2", code)
	}
}

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

func TestReportRejectsBadFormat(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"report", "--format", "txt", "."}, &out, &errBuf); code != 2 {
		t.Errorf("bad report format exit = %d, want 2", code)
	}
}

func readFileToString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
