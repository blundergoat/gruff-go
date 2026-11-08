//go:build darwin || dragonfly || freebsd || netbsd || openbsd

// BSD-family terminal detection uses TIOCGETA because file mode cannot distinguish terminals from other character devices such as /dev/null.
//
// Prompts and automatic colour stay disabled whenever the kernel rejects TIOCGETA, as it does for a file or a pipe.
package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// platformIsInteractiveTerminal asks a BSD-family kernel whether the stream exposes terminal settings.
//
// Use only behind isInteractiveTerminal; any ioctl error means the stream is non-interactive.
// Returns true when the TIOCGETA ioctl on the stream's file descriptor succeeds, and false whenever the kernel rejects that request.
// Calling stream.Fd() can switch a stream Go put in nonblocking mode to blocking mode for later I/O, even when this returns false.
func platformIsInteractiveTerminal(stream *os.File) bool {
	var terminalSettings syscall.Termios
	// The synchronous ioctl fills terminalSettings before returning, so the stack pointer does not escape.
	_, _, ioctlErrno := syscall.Syscall(
		syscall.SYS_IOCTL,
		stream.Fd(),
		uintptr(syscall.TIOCGETA),
		uintptr(unsafe.Pointer(&terminalSettings)),
	)
	return ioctlErrno == 0
}
