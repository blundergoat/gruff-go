// Package cli implements the gruff-go command-line interface.
// TestMain default-disables the interactive bootstrap so existing tests do
// not see a surprise prompt when go test inherits a real terminal stdin.
// Tests that exercise the prompt path explicitly flip the hooks via
// withFakeTerminalStdin.
package cli

import (
	"os"
	"testing"
)

// TestMain pins stdinTerminalCheck to "no TTY" for the whole package so the
// default test environment matches CI/script behaviour. Tests that need the
// affirmative path opt in by swapping promptStdin and stdinTerminalCheck.
func TestMain(m *testing.M) {
	prev := stdinTerminalCheck
	stdinTerminalCheck = func() bool { return false }
	defer func() { stdinTerminalCheck = prev }()
	os.Exit(m.Run())
}
