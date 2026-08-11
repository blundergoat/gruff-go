// Package cli implements the gruff-go command-line interface.
// Terminal detection is shared by first-run prompts and automatic ANSI output. Platform probes
// reject non-interactive character devices so redirected commands never wait for terminal input.
package cli

import "os"

// isInteractiveTerminal reports whether a stream supports terminal control operations.
// Prompting and automatic colour use it to reject pipes, files, and character devices such as /dev/null.
func isInteractiveTerminal(stream *os.File) bool {
	// A missing stream cannot accept input or terminal styling.
	if stream == nil {
		return false
	}
	return platformIsInteractiveTerminal(stream)
}
