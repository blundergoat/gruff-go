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

// extractAnsiFlags removes --ansi and --no-ansi from args and returns the
// requested mode. The flags can appear at any position.
func extractAnsiFlags(args []string) ([]string, ansiMode) {
	out := make([]string, 0, len(args))
	mode := ansiAuto
	for _, arg := range args {
		switch arg {
		case "--ansi":
			mode = ansiOn
		case "--no-ansi":
			mode = ansiOff
		default:
			out = append(out, arg)
		}
	}
	return out, mode
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

// isTerminalWriter probes for a TTY by Stat()'ing the underlying *os.File and
// checking for ModeCharDevice. Any writer that isn't an *os.File (e.g. the
// bytes.Buffer used in tests, or a pipe wrapped through a custom writer)
// returns false, which is the conservative choice - when in doubt, no colour.
func isTerminalWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
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
