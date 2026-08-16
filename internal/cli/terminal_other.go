//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !windows

// Fallback terminal detection covers platforms without an in-tree terminal API adapter. The CLI
// chooses non-interactive behavior there so automation never receives prompts or automatic colour
// based on an unverified file-mode heuristic.
package cli

import "os"

// platformIsInteractiveTerminal disables interactive behavior when no verified platform probe exists.
// Add a platform adapter before enabling prompts or automatic colour on another operating system.
func platformIsInteractiveTerminal(_ *os.File) bool {
	return false
}
