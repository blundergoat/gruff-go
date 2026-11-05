// Package cli implements the gruff-go command-line interface.
//
// This file covers shared flag parity across commands: --version, --quiet, --no-ansi, --ansi, help, list, completion, summary and report.
// A failure means a command line that users and scripts rely on changed its output or exit code.
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
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
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

// TestHelpForCommandShowsUsage verifies gruff-go help <command> exits 0 and names the command for each subcommand the test lists.
// For init it also checks that the usage shows --reset nested inside --force.
func TestHelpForCommandShowsUsage(t *testing.T) {
	for _, cmd := range []string{"analyse", "baseline", "completion", "init", "list-rules", "summary", "report", "dashboard"} {
		var out, errBuf bytes.Buffer
		if code := Main([]string{"help", cmd}, &out, &errBuf); code != 0 {
			t.Errorf("help %s exit = %d, stderr = %s", cmd, code, errBuf.String())
		}
		if !strings.Contains(out.String(), "gruff-go "+cmd) {
			t.Errorf("help %s missing command name; got %q", cmd, out.String())
		}
		if cmd == "init" && !strings.Contains(out.String(), "[--force [--reset]]") {
			t.Errorf("help init missing reset usage; got %q", out.String())
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

// TestGlobalCompatibilityAliases verifies the cross-gruff global aliases --silent and -v are accepted and --silent suppresses normal output.
func TestGlobalCompatibilityAliases(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := Main([]string{"--silent", "-v", "list"}, &out, &errBuf); code != 0 {
		t.Fatalf("list with compatibility aliases exit = %d, stderr = %s", code, errBuf.String())
	}
	if out.String() != "" {
		t.Fatalf("--silent should suppress normal output, got %q", out.String())
	}
}

// TestCompletionCommand verifies gruff-go completion with no shell argument exits 0 and prints the bash complete registration line.
func TestCompletionCommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := Main([]string{"completion"}, &out, &errBuf); code != 0 {
		t.Fatalf("completion exit = %d, stderr = %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "complete -F _gruff_go_complete gruff-go") {
		t.Fatalf("completion output missing bash registration: %s", out.String())
	}
}

// TestSummaryCommandText verifies gruff-go summary on a one-file project exits 0 and prints the core lines of the text digest.
// It checks the version header, the scanned path, the file counts, the scan time, and the Composite and Findings lines.
func TestSummaryCommandText(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"summary", "."}, &out, &errBuf); code != 0 {
		t.Fatalf("summary exit = %d, stderr = %s", code, errBuf.String())
	}
	for _, fragment := range []string{
		"gruff-go " + toolVersion + " summary",
		"scanned: . (in ",
		"files: 1 Go parsed, 0 text scanned, 0 failed, 0 skipped",
		"scan time: ",
		"Composite: ",
		"Findings: ",
	} {
		if !strings.Contains(out.String(), fragment) {
			t.Errorf("summary missing %q; got: %s", fragment, out.String())
		}
	}
}

// TestSummaryCommandShowsGitignoredCount verifies the text summary prints "ignored by .gitignore: 1" when one file matches .gitignore.
// The count explains skipped files to a new user without changing machine-readable summary JSON; this test checks the text side only.
func TestSummaryCommandShowsGitignoredCount(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gitignore", "ignored.go\n")
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
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

// TestSummaryCommandSuggestsGeneratedBaseline checks the text-only fresh-start hint a first summary prints for existing debt.
//
// That summary exits 0 because the family CLI contract reserves exit 1 for a gate somebody asked for; with --fail-on advisory it exits 1.
// Both suggested commands quote the spaced file path so the user can paste them as printed.
func TestSummaryCommandSuggestsGeneratedBaseline(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex path.go", complexFixture())
	t.Chdir(root)

	var gatedOut, gatedErr bytes.Buffer
	if code := Main([]string{"summary", "--fail-on", "advisory", "complex path.go"}, &gatedOut, &gatedErr); code != 1 {
		t.Fatalf("summary --fail-on advisory exit = %d, want 1; stderr = %s", code, gatedErr.String())
	}

	var out, errBuf bytes.Buffer
	if code := Main([]string{"summary", "complex path.go"}, &out, &errBuf); code != 0 {
		t.Fatalf("summary exit = %d, want 0 when no gate was asked for; stderr = %s", code, errBuf.String())
	}
	for _, fragment := range []string{
		"fresh start: gruff-go analyse --generate-baseline gruff-baseline.json \"complex path.go\"",
		"then scan with: gruff-go analyse --baseline gruff-baseline.json \"complex path.go\"",
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
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"summary"}, &out, &errBuf); code != 0 {
		t.Fatalf("summary (no path) exit = %d, stderr = %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "scanned: . (in ") {
		t.Errorf("summary (no path) missing default-path line; got: %s", out.String())
	}
	if !strings.Contains(out.String(), "files: 1 Go parsed, 0 text scanned, 0 failed, 0 skipped") {
		t.Errorf("summary (no path) should report the Go/text scan surface; got: %s", out.String())
	}
}

// TestSummaryRejectsBadFormat verifies summary returns exit code 2 on unknown formats.
func TestSummaryRejectsBadFormat(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"summary", "--format", "yaml", "."}, &out, &errBuf); code != 2 {
		t.Errorf("bad format exit = %d, want 2", code)
	}
}

// TestReportCommandHTMLToFile verifies report --format html --output writes an HTML document to that file and leaves stdout empty.
func TestReportCommandHTMLToFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
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
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"report", "--format", "txt", "."}, &out, &errBuf); code != 2 {
		t.Errorf("bad report format exit = %d, want 2", code)
	}
}

// readFileToString reads path and returns its contents as a string.
// When os.ReadFile fails, for example because path does not exist, it returns an empty string and that error unchanged.
func readFileToString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// TestCommandCatalogueReachesEverySurface checks each help.go catalogue entry reaches completion and the help views its metadata enables.
//
// A described entry must appear on the usage screen, and an entry with a flag list must open its own help screen.
// Commands missing from the catalogue are outside this check.
func TestCommandCatalogueReachesEverySurface(t *testing.T) {
	var usage, usageErr bytes.Buffer
	if code := Main([]string{"help"}, &usage, &usageErr); code != 0 {
		t.Fatalf("help exit = %d, stderr = %s", code, usageErr.String())
	}
	var completion, completionErr bytes.Buffer
	if code := Main([]string{"completion", "bash"}, &completion, &completionErr); code != 0 {
		t.Fatalf("completion exit = %d, stderr = %s", code, completionErr.String())
	}

	for _, entry := range commandCatalogue {
		// Every name is completable, aliases included, because a user may type either spelling.
		if !strings.Contains(completion.String(), entry.name) {
			t.Errorf("completion script omits %q", entry.name)
		}
		// A described command is one the usage screen lists; an alias deliberately carries no description.
		if entry.description != "" && !strings.Contains(usage.String(), entry.description) {
			t.Errorf("usage screen omits %q", entry.name)
		}
		// A command with a flag list has a per-command help screen the dispatch can reach.
		if entry.usage != "" {
			var out, errBuf bytes.Buffer
			if code := Main([]string{"help", entry.name}, &out, &errBuf); code != 0 {
				t.Errorf("help %s exit = %d, stderr = %s", entry.name, code, errBuf.String())
			}
		}
	}
}

// TestHookDescriptionNamesTheContractItEmits verifies the usage screen's hook line names the contract version the
// hook actually advertises, which is the drift that left gruff.hook.v1 in the command listing after v2 shipped.
func TestHookDescriptionNamesTheContractItEmits(t *testing.T) {
	for _, entry := range commandCatalogue {
		if entry.name != "hook" {
			continue
		}
		if !strings.Contains(entry.description, hookContractVersion) {
			t.Errorf("hook description = %q, want the emitted contract %q", entry.description, hookContractVersion)
		}
	}
}
