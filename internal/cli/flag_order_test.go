// Package cli tests the command-line behavior exposed by gruff-go.
// These tests pin flag placement and end-of-flags behavior for commands that accept positional
// paths, preventing valid flags from being silently forwarded to file discovery.
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

// captureCLIResult runs one command with in-memory streams for user-visible result comparisons.
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
// From a sibling directory, `../a ../b` has no root the analyzer resolves both against; the run must publish one
// run-invalidating target-error diagnostic and no findings, instead of failing while the report is written.
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
