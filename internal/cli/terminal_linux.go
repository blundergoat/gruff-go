//go:build linux

// Linux terminal detection uses TCGETS because file mode cannot distinguish terminals from other
// character devices. Prompts and automatic colour stay disabled whenever the kernel rejects the
// terminal-settings request.
package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// platformIsInteractiveTerminal asks Linux whether the stream exposes terminal settings.
// Use only behind isInteractiveTerminal; any ioctl error means the stream is non-interactive.
func platformIsInteractiveTerminal(stream *os.File) bool {
	var terminalSettings syscall.Termios
	// The synchronous ioctl fills terminalSettings before returning, so the stack pointer does not escape.
	_, _, ioctlErrno := syscall.Syscall(
		syscall.SYS_IOCTL,
		stream.Fd(),
		uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&terminalSettings)),
	)
	return ioctlErrno == 0
}
