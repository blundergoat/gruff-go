// Package cli tests the command-line behavior exposed by gruff-go.
// These tests pin what happens to positional arguments on commands that do not consume them, so a
// named scan target can never be accepted and then silently dropped.
package cli

import (
	"strings"
	"testing"
)

// TestCommandsRejectUnusedPositionalArguments verifies commands that take no operands fail loudly.
// The fixture path is real: rejection must come from the argument contract, not from a missing file.
func TestCommandsRejectUnusedPositionalArguments(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(projectRoot)

	testCases := []struct {
		name            string
		arguments       []string
		expectedMessage string
	}{
		{
			name:            "list-rules",
			arguments:       []string{"list-rules", "--no-config", "main.go"},
			expectedMessage: "list-rules takes no positional arguments",
		},
		{
			// The dashboard names scan targets through flags, so an operand here is a target the
			// user asked for and the server would never scan.
			name:            "dashboard",
			arguments:       []string{"dashboard", "--no-config", "main.go"},
			expectedMessage: "dashboard takes no positional arguments",
		},
		{
			name:            "completion second shell",
			arguments:       []string{"completion", "bash", "zsh"},
			expectedMessage: "completion takes at most one shell argument",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			exitCode, stdout, stderr := captureCLIResult(testCase.arguments)
			if exitCode != 2 {
				t.Fatalf("exit = %d, want 2; stdout=%s stderr=%s", exitCode, stdout, stderr)
			}
			if !strings.Contains(stderr, testCase.expectedMessage) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr, testCase.expectedMessage)
			}
			if len(stdout) != 0 {
				t.Fatalf("stdout = %q, want empty so machine consumers never receive prose", stdout)
			}
		})
	}
}

// TestCommandsStillAcceptTheirSupportedForms verifies the guards reject only surplus operands.
// The dashboard is absent by necessity: its accepted form binds a listener and never returns.
func TestCommandsStillAcceptTheirSupportedForms(t *testing.T) {
	projectRoot := t.TempDir()
	t.Chdir(projectRoot)

	testCases := []struct {
		name      string
		arguments []string
	}{
		{name: "list-rules text", arguments: []string{"list-rules", "--no-config", "--format", "text"}},
		{name: "completion explicit shell", arguments: []string{"completion", "bash"}},
		{name: "completion default shell", arguments: []string{"completion"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			exitCode, stdout, stderr := captureCLIResult(testCase.arguments)
			if exitCode != 0 {
				t.Fatalf("exit = %d, want 0; stderr=%s", exitCode, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("stdout empty, want the command's normal output")
			}
		})
	}
}

// TestCompletionDefaultShellMatchesExplicitBash verifies the operand guard left the default intact.
// A guard written as NArg() > 0 instead of > 1 would silently break the bare-completion form.
func TestCompletionDefaultShellMatchesExplicitBash(t *testing.T) {
	t.Chdir(t.TempDir())

	defaultExit, defaultStdout, defaultStderr := captureCLIResult([]string{"completion"})
	explicitExit, explicitStdout, explicitStderr := captureCLIResult([]string{"completion", "bash"})

	if defaultExit != 0 || explicitExit != 0 {
		t.Fatalf("exits = %d and %d, want 0; stderr=%q and %q",
			defaultExit, explicitExit, defaultStderr, explicitStderr)
	}
	if string(defaultStdout) != string(explicitStdout) {
		t.Fatalf("bare completion and explicit bash differ: %d vs %d bytes",
			len(defaultStdout), len(explicitStdout))
	}
}
