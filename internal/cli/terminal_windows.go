//go:build windows

// Windows terminal detection asks the console API for the stream mode instead of relying on file
// metadata. Prompts and automatic colour stay disabled for redirected handles and the null device
// because those handles do not expose a console mode.
package cli

import (
	"os"
	"syscall"
)

// platformIsInteractiveTerminal asks Windows whether the stream belongs to a console.
// Use only behind isInteractiveTerminal; an unavailable console mode means non-interactive input or output.
func platformIsInteractiveTerminal(stream *os.File) bool {
	var consoleMode uint32
	return syscall.GetConsoleMode(syscall.Handle(stream.Fd()), &consoleMode) == nil
}
