//go:build windows

// Windows terminal detection asks the console API for the stream mode instead of relying on file metadata.
//
// Prompts and automatic colour stay disabled for redirected handles and the null device, because those handles do not expose a console mode.
// A redirected stream on Windows, such as output piped to a file or input read from NUL, is therefore treated as non-interactive.
package cli

import (
	"os"
	"syscall"
)

// platformIsInteractiveTerminal asks Windows whether the stream belongs to a console.
// Calling stream.Fd() can detach a pollable handle from Go's I/O completion port and disable I/O deadlines, even if detection returns false.
//
// Use only behind isInteractiveTerminal; an unavailable console mode means non-interactive input or output.
// It reports true when GetConsoleMode succeeds on the stream's handle, and false when that call fails, as for a pipe, a file or NUL.
func platformIsInteractiveTerminal(stream *os.File) bool {
	var consoleMode uint32
	return syscall.GetConsoleMode(syscall.Handle(stream.Fd()), &consoleMode) == nil
}
