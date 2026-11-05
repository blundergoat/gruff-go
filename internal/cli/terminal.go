// Package cli implements the gruff-go command-line interface.
//
// Terminal detection is shared by first-run prompts and automatic ANSI output.
// Platform probes reject non-interactive character devices, so a command with redirected stdin skips the first-run prompt instead of waiting.
package cli

import "os"

// isInteractiveTerminal reports whether stream supports terminal control operations.
//
// Prompting and automatic colour use it to reject pipes, files, and character devices such as /dev/null.
// A nil stream gives false. False on stdin skips the first-run prompt; false on an output stream turns off automatic colour for that stream.
func isInteractiveTerminal(stream *os.File) bool {
	// A missing stream cannot accept input or terminal styling.
	if stream == nil {
		return false
	}
	return platformIsInteractiveTerminal(stream)
}
