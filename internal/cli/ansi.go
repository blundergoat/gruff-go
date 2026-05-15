package cli

import (
	"io"
	"os"
)

// ansiMode describes the colour-output decision after considering CLI flags,
// the NO_COLOR environment variable, and whether the writer is attached to a
// terminal.
type ansiMode int

const (
	ansiAuto ansiMode = iota
	ansiOn
	ansiOff
)

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

type ansiStyler struct {
	enabled bool
}

func (s ansiStyler) yellow(text string) string {
	if !s.enabled {
		return text
	}
	return ansiYellow + text + ansiReset
}

func (s ansiStyler) green(text string) string {
	if !s.enabled {
		return text
	}
	return ansiGreen + text + ansiReset
}

func (s ansiStyler) bold(text string) string {
	if !s.enabled {
		return text
	}
	return ansiBold + text + ansiReset
}
