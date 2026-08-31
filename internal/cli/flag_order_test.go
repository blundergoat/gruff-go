// Package cli tests the command-line behavior exposed by gruff-go.
// These tests pin flag placement and end-of-flags behavior for commands that accept positional
// paths, preventing valid flags from being silently forwarded to file discovery.
package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
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
