// Package cli implements the gruff-go command-line interface.
//
// ANSI helpers keep colour policy separate from command parsing and rendering.
// They read the global --ansi and --no-ansi flags; without either, colour needs a real terminal, no NO_COLOR and a TERM other than dumb.
package cli

import (
	"io"
	"os"
)

// ansiMode records whether CLI flags force colour on or off or leave the decision to automatic detection.
//
// extractAnsiFlags sets it from --ansi and --no-ansi before any command runs.
// ansiEnabled then resolves ansiAuto against NO_COLOR, TERM and whether the writer is a terminal.
type ansiMode int

// The ansiMode values record the colour flag the user gave; ansiAuto, the zero value, means none and leaves the choice to detection.
// ansiOn comes from --ansi and forces colour; ansiOff comes from --no-ansi and keeps output plain even on a terminal.
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

// extractAnsiFlags removes the global --ansi and --no-ansi flags before command dispatch.
//
// The last explicit preference wins, and a bare dash or -- protects itself and every later token from removal.
// It returns a copy of commandArguments with each such flag removed up to the first protecting token, keeping the rest in order.
// The mode is the last such flag seen, or ansiAuto when none is; an empty commandArguments gives an empty slice and ansiAuto.
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

// ansiEnabled decides whether output to writer gets ANSI escapes, given the colour mode the user's flags requested.
//
// It returns true for ansiOn and false for ansiOff regardless of writer, so either flag overrides NO_COLOR and TERM.
// Otherwise it returns false when NO_COLOR is set, even empty, or TERM is dumb, and else reports whether isTerminalWriter accepts writer.
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
//
// Buffers, wrapped pipes, and character devices such as /dev/null remain unstyled.
// It reports true only when writer is an *os.File that isInteractiveTerminal accepts, and false for a writer of any other type.
func isTerminalWriter(writer io.Writer) bool {
	stream, isFile := writer.(*os.File)
	// A non-file writer has no terminal descriptor, so automatic colour stays off.
	if !isFile {
		return false
	}
	return isInteractiveTerminal(stream)
}

// ansiStyler conditionally wraps text in ANSI escape sequences.
// When enabled is false, every method returns its text unchanged.
type ansiStyler struct {
	enabled bool
}

// yellow wraps text in the yellow ANSI escape, or returns it unchanged when styling is off.
//
// The no-op fallback lets callers wrap unconditionally instead of branching on ansiEnabled at every styling site.
// An empty text still comes back wrapped in the escape pair when styling is on.
func (s ansiStyler) yellow(text string) string {
	if !s.enabled {
		return text
	}
	return ansiYellow + text + ansiReset
}

// green wraps text in the green ANSI escape, or returns it unchanged when styling is off. See yellow for the rationale behind the no-op fallback.
func (s ansiStyler) green(text string) string {
	if !s.enabled {
		return text
	}
	return ansiGreen + text + ansiReset
}

// bold wraps text in the bold ANSI escape, or returns it unchanged when styling is off. See yellow for the rationale behind the no-op fallback.
func (s ansiStyler) bold(text string) string {
	if !s.enabled {
		return text
	}
	return ansiBold + text + ansiReset
}
