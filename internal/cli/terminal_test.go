// Package cli tests the command-line behavior exposed by gruff-go.
//
// These tests open the operating system's null device to tell a real terminal apart from a character device.
// They protect non-interactive containers from the first-run prompt and automatic colour.
package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestConfigPromptSkipsNullDevice verifies redirected null input never triggers first-run setup.
// If the prompt-text check fails, a first run with stdin from /dev/null, as in a container, would print the generate-config prompt.
func TestConfigPromptSkipsNullDevice(t *testing.T) {
	nullDevice, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = nullDevice.Close() })

	// Point stdin at the null device and restore the real terminal probe that TestMain replaces with a constant false.
	originalStdin := os.Stdin
	originalPromptInput := promptStdin
	originalTerminalCheck := stdinTerminalCheck
	os.Stdin = nullDevice
	promptStdin = nullDevice
	stdinTerminalCheck = stdinIsTerminal
	t.Cleanup(func() {
		os.Stdin = originalStdin
		promptStdin = originalPromptInput
		stdinTerminalCheck = originalTerminalCheck
	})

	var promptOutput bytes.Buffer
	if err := maybeBootstrapConfigInRoot(t.TempDir(), "", false, &promptOutput); err != nil {
		t.Fatalf("bootstrap config: %v", err)
	}
	if strings.Contains(promptOutput.String(), "Generate one with default settings") {
		t.Fatalf("/dev/null emitted bootstrap prompt: %q", promptOutput.String())
	}
}

// TestAnsiAutoDetectionRejectsNullDevice verifies redirected output remains free of terminal styling.
// If the isTerminalWriter check fails, output sent to /dev/null passes the terminal gate that automatic colour relies on.
func TestAnsiAutoDetectionRejectsNullDevice(t *testing.T) {
	nullDevice, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer func() { _ = nullDevice.Close() }()

	if isTerminalWriter(nullDevice) {
		t.Fatal("/dev/null reported as a terminal writer")
	}
}
