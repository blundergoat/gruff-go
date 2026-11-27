// Package cli tests the command-line behavior exposed by gruff-go.
//
// These tests pin flag placement and end-of-flags behavior for commands that accept positional paths.
// They keep a valid flag typed after a path from being silently forwarded to file discovery as another path.
package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestPathCommandsAcceptFlagsAfterPaths verifies flag placement does not change output or exit status.
// For analyse, baseline, summary, report, hook and check-ignore, flags after main.go must match flags before it in stdout and exit code.
func TestPathCommandsAcceptFlagsAfterPaths(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(projectRoot)

	testCases := []struct {
		name            string
		flagsBeforePath []string
		flagsAfterPath  []string
	}{
		{
			name:            "analyse",
			flagsBeforePath: []string{"analyse", "--no-config", "--fail-on", "none", "--format", "json", "main.go"},
			flagsAfterPath:  []string{"analyse", "main.go", "--no-config", "--fail-on", "none", "--format", "json"},
		},
		{
			name:            "baseline",
			flagsBeforePath: []string{"baseline", "--no-config", "--out", "baseline.json", "main.go"},
			flagsAfterPath:  []string{"baseline", "main.go", "--no-config", "--out", "baseline.json"},
		},
		{
			name:            "summary",
			flagsBeforePath: []string{"summary", "--no-config", "--fail-on", "none", "--format", "json", "main.go"},
			flagsAfterPath:  []string{"summary", "main.go", "--no-config", "--fail-on", "none", "--format", "json"},
		},
		{
			name:            "report",
			flagsBeforePath: []string{"report", "--no-config", "--fail-on", "none", "--format", "json", "main.go"},
			flagsAfterPath:  []string{"report", "main.go", "--no-config", "--fail-on", "none", "--format", "json"},
		},
		{
			name:            "hook",
			flagsBeforePath: []string{"hook", "--no-config", "--format", "json", "main.go"},
			flagsAfterPath:  []string{"hook", "main.go", "--no-config", "--format", "json"},
		},
		{
			name:            "check-ignore",
			flagsBeforePath: []string{"check-ignore", "--no-config", "--format", "json", "main.go"},
			flagsAfterPath:  []string{"check-ignore", "main.go", "--no-config", "--format", "json"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			beforePathExit, beforePathStdout, beforePathStderr := captureCLIResult(testCase.flagsBeforePath)
			afterPathExit, afterPathStdout, afterPathStderr := captureCLIResult(testCase.flagsAfterPath)

			if beforePathExit != afterPathExit {
				t.Errorf("exit codes differ: flags-before-path=%d flags-after-path=%d; before stderr=%q after stderr=%q",
					beforePathExit, afterPathExit, beforePathStderr, afterPathStderr)
			}
			if !bytes.Equal(beforePathStdout, afterPathStdout) {
				t.Errorf("stdout differs: flags-before-path bytes=%d flags-after-path bytes=%d; after stderr=%q",
					len(beforePathStdout), len(afterPathStdout), afterPathStderr)
			}
		})
	}
}

// TestAnalyseRejectsUnknownFlagAfterPath verifies a trailing unknown flag fails during parsing.
// analyse main.go --bogus must exit nonzero with a flag provided but not defined error, not scan --bogus as one more path.
func TestAnalyseRejectsUnknownFlagAfterPath(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(projectRoot)

	var stdout, stderr bytes.Buffer
	exitCode := Main([]string{"analyse", "--no-config", "--fail-on", "none", "main.go", "--bogus"}, &stdout, &stderr)
	if exitCode == 0 {
		t.Fatalf("analyse with trailing --bogus exit = 0; stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined: -bogus") {
		t.Fatalf("stderr = %q, want unknown-flag rejection", stderr.String())
	}
}

// TestDoubleDashPreservesLeadingDashPaths verifies `--` makes later flag-shaped names scannable.
// Directories named -weird-name and --quiet, given after --, must exit 0 with their main.go listed among the JSON scanned paths.
func TestDoubleDashPreservesLeadingDashPaths(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "-weird-name/main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	writeFile(t, projectRoot, "--quiet/main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(projectRoot)

	for _, projectPath := range []string{"-weird-name", "--quiet"} {
		t.Run(projectPath, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exitCode := Main([]string{"analyse", "--no-config", "--fail-on", "none", "--format", "json", "--", projectPath}, &stdout, &stderr)
			if exitCode != 0 {
				t.Fatalf("analyse -- %s exit = %d, stderr=%s stdout=%s", projectPath, exitCode, stderr.String(), stdout.String())
			}
			var scanReport machineAnalysisReport
			if err := json.Unmarshal(stdout.Bytes(), &scanReport); err != nil {
				t.Fatalf("decode analysis JSON: %v\n%s", err, stdout.String())
			}
			expectedScannedPath := projectPath + "/main.go"
			if !slices.Contains(scanReport.Paths.Extensions.Go.Paths.Scanned, expectedScannedPath) {
				t.Fatalf("scanned paths = %#v, want %s", scanReport.Paths.Extensions.Go.Paths.Scanned, expectedScannedPath)
			}
		})
	}
}

// TestBareDashStopsFlagParsing verifies stdin syntax protects every later token as positional input.
// After a bare -, parseCommandArguments must keep --format json as positionals, so the format stays text.
func TestBareDashStopsFlagParsing(t *testing.T) {
	flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	selectedFormat := flagSet.String("format", "text", "output format")
	if err := parseCommandArguments(flagSet, []string{"main.go", "-", "--format", "json"}); err != nil {
		t.Fatalf("parse command arguments: %v", err)
	}
	if *selectedFormat != "text" {
		t.Fatalf("format = %q, want text after bare-dash terminator", *selectedFormat)
	}
	expectedArguments := []string{"main.go", "-", "--format", "json"}
	if !slices.Equal(flagSet.Args(), expectedArguments) {
		t.Fatalf("positionals = %#v, want %#v", flagSet.Args(), expectedArguments)
	}
}

// captureCLIResult runs one gruff-go command through Main with fresh in-memory streams so tests can compare what a user would see.
//
// commandArguments is passed unchanged to Main, starting with the subcommand name.
// It returns the exit code, a copy of the standard-output bytes and the standard-error text.
// A command that prints nothing gives a zero-length slice and an empty string.
func captureCLIResult(commandArguments []string) (int, []byte, string) {
	var stdout, stderr bytes.Buffer
	exitCode := Main(commandArguments, &stdout, &stderr)
	return exitCode, bytes.Clone(stdout.Bytes()), stderr.String()
}

// TestAnalyseAcceptsHistoryFileAsDocumentedNoOp verifies the family flag is accepted without writing a history file.
// FAMILY-CONTRACT section 7 requires every port to accept a family flag it does not implement and to say so in help.
func TestAnalyseAcceptsHistoryFileAsDocumentedNoOp(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(projectRoot)

	plainExit, plainStdout, plainStderr := captureCLIResult([]string{"analyse", "--no-config", "--fail-on", "none", "--format", "json", "main.go"})
	historyExit, historyStdout, historyStderr := captureCLIResult([]string{"analyse", "--no-config", "--fail-on", "none", "--format", "json", "--history-file", "history.json", "main.go"})

	if plainExit != historyExit {
		t.Fatalf("--history-file changed the exit: without=%d with=%d; stderr=%q", plainExit, historyExit, historyStderr)
	}
	if !bytes.Equal(plainStdout, historyStdout) {
		t.Fatalf("--history-file changed stdout: without %d bytes, with %d bytes; stderr=%q", len(plainStdout), len(historyStdout), plainStderr)
	}
	if _, err := os.Stat(filepath.Join(projectRoot, "history.json")); !os.IsNotExist(err) {
		t.Fatalf("--history-file wrote a history file, want none: stat error %v", err)
	}

	_, helpStdout, helpStderr := captureCLIResult([]string{"analyse", "--help"})
	help := string(helpStdout) + helpStderr
	if !strings.Contains(help, "-history-file") || !strings.Contains(help, "accepted for cross-port compatibility; not implemented in gruff-go") {
		t.Fatalf("analyse --help does not document --history-file as the section 7 no-op: %q", help)
	}
}

// TestAnalyseRefusesSeveralTargetsOutsideLaunchDirectoryWithEnvelope verifies the refusal a JSON caller can read.
//
// From a sibling directory, ../a ../b is refused because several targets must all be inside the launch directory, so the run exits 2.
// Its JSON has one run-invalidating discovery target-error and no findings; ../a alone exits 0 with --fail-on none.
func TestAnalyseRefusesSeveralTargetsOutsideLaunchDirectoryWithEnvelope(t *testing.T) {
	workspace := t.TempDir()
	writeFile(t, workspace, "a/main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	writeFile(t, workspace, "b/other.go", "// Package main is a test fixture.\npackage main\n\nfunc other() {}\n")
	sibling := filepath.Join(workspace, "sibling")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sibling)

	exitCode, stdout, stderr := captureCLIResult([]string{"analyse", "--no-config", "--format", "json", "../a", "../b"})
	if exitCode != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%q", exitCode, stderr)
	}
	var envelope struct {
		Diagnostics []struct {
			Type           string `json:"type"`
			Stage          string `json:"stage"`
			InvalidatesRun bool   `json:"invalidatesRun"`
		} `json:"diagnostics"`
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(stdout, &envelope); err != nil {
		t.Fatalf("stdout is not a JSON envelope: %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if len(envelope.Diagnostics) != 1 || envelope.Diagnostics[0].Type != "target-error" || !envelope.Diagnostics[0].InvalidatesRun || envelope.Diagnostics[0].Stage != "discovery" {
		t.Fatalf("diagnostics = %+v, want one run-invalidating target-error at the discovery stage", envelope.Diagnostics)
	}
	if len(envelope.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(envelope.Findings))
	}

	oneExit, _, oneStderr := captureCLIResult([]string{"analyse", "--no-config", "--format", "json", "--fail-on", "none", "../a"})
	if oneExit != 0 {
		t.Fatalf("one target outside the launch directory exit = %d, want 0; stderr=%q", oneExit, oneStderr)
	}
}
