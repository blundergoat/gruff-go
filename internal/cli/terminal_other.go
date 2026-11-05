//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !windows

// Fallback terminal detection covers platforms without an in-tree terminal API adapter.
//
// The CLI treats every stream there as non-interactive rather than trust an unverified file-mode heuristic.
// Automation never gets a prompt or automatic colour there, and neither does a user at a real terminal.
package cli

import "os"

// platformIsInteractiveTerminal disables interactive behavior when no verified platform probe exists.
//
// Add a platform adapter before enabling prompts or automatic colour on another operating system.
// Returns false for every stream, so callers on these platforms always treat output as non-interactive.
func platformIsInteractiveTerminal(_ *os.File) bool {
	return false
}
