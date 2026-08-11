// Package cli implements the gruff-go command-line interface.
// ANSI helpers keep colour policy separate from command parsing and rendering.
package cli

import (
	"io"
	"os"
)

// ansiMode describes the colour-output decision after considering CLI flags,
// the NO_COLOR environment variable, and whether the writer is attached to a
// terminal.
type ansiMode int

// ansiMode constants enumerate the colour decisions the CLI can make.
const (
	ansiAuto ansiMode = iota
	ansiOn
	ansiOff
)

// ANSI escape sequence constants used to style CLI output text.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiYellow = "\x1b[33m"
	ansiGreen  = "\x1b[32m"
)

// extractAnsiFlags removes global colour flags before command dispatch.
// The last explicit preference wins; a bare dash or `--` protects every later positional token.
func extractAnsiFlags(commandArguments []string) ([]string, ansiMode) {
	remainingArguments := make([]string, 0, len(commandArguments))
	requestedMode := ansiAuto
	// Colour flags remain global until the caller explicitly ends flag parsing.
	for argumentIndex, argument := range commandArguments {
		// Protected operands must reach the command parser unchanged, even when they resemble colour flags.
		if argument == "--" || argument == "-" {
			remainingArguments = append(remainingArguments, commandArguments[argumentIndex:]...)
			break
		}
		switch argument {
		case "--ansi":
			// Explicit colour bypasses terminal auto-detection.
			requestedMode = ansiOn
		case "--no-ansi":
			// Explicit opt-out keeps output plain even on a terminal.
			requestedMode = ansiOff
		default:
			// Command and path arguments continue to command-specific parsing.
			remainingArguments = append(remainingArguments, argument)
		}
	}
	return remainingArguments, requestedMode
}

// ansiEnabled decides whether to emit ANSI escapes given the requested mode
// and the writer's terminal status. Honours the NO_COLOR convention.
func ansiEnabled(writer io.Writer, mode ansiMode) bool {
	switch mode {
	case ansiOn:
		return true
	case ansiOff:
		return false
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if value := os.Getenv("TERM"); value == "dumb" {
		return false
	}
	return isTerminalWriter(writer)
}

// isTerminalWriter enables automatic colour only for an os.File backed by a real terminal.
// Buffers, wrapped pipes, and character devices such as /dev/null remain unstyled.
func isTerminalWriter(writer io.Writer) bool {
	stream, isFile := writer.(*os.File)
	// A non-file writer has no terminal descriptor, so automatic colour stays off.
	if !isFile {
		return false
	}
	return isInteractiveTerminal(stream)
}

// ansiStyler conditionally wraps text in ANSI escape sequences.
type ansiStyler struct {
	enabled bool
}

// yellow wraps text in the yellow ANSI escape, or returns it unchanged when
// styling is off. The no-op fallback lets callers wrap unconditionally instead
// of branching on ansiEnabled at every styling site.
func (s ansiStyler) yellow(text string) string {
	if !s.enabled {
		return text
	}
	return ansiYellow + text + ansiReset
}

// green wraps text in the green ANSI escape, or returns it unchanged when
// styling is off. See yellow for the rationale behind the no-op fallback.
func (s ansiStyler) green(text string) string {
	if !s.enabled {
		return text
	}
	return ansiGreen + text + ansiReset
}

// bold wraps text in the bold ANSI escape, or returns it unchanged when
// styling is off. See yellow for the rationale behind the no-op fallback.
func (s ansiStyler) bold(text string) string {
	if !s.enabled {
		return text
	}
	return ansiBold + text + ansiReset
}
