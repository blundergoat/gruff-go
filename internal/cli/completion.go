// Package cli implements the gruff-go command-line interface.
// The completion command emits small static scripts for the supported shells.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

// completionCommands lists the top-level subcommand names emitted into the
// generated shell completion scripts. Keep this in sync with the dispatch
// switch in cli.go so completion never advertises an unknown command.
var completionCommands = []string{
	"analyse",
	"analyze",
	"baseline",
	"completion",
	"dashboard",
	"help",
	"init",
	"list",
	"list-rules",
	"report",
	"summary",
}

// runCompletion prints a shell completion script for the requested shell.
func runCompletion(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("completion", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	shell := "bash"
	if flags.NArg() > 0 {
		shell = flags.Arg(0)
	}
	script, err := completionScript(shell)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if _, err := fmt.Fprint(stdout, script); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}

// completionScript returns the inline completion script for the requested
// shell. Supports bash, zsh, and fish; any other value returns an error so the
// CLI can exit with a clear message rather than emitting an empty script.
func completionScript(shell string) (string, error) {
	commands := strings.Join(completionCommands, " ")
	switch shell {
	case "bash":
		return fmt.Sprintf(`_gruff_go_complete()
{
	local cur="${COMP_WORDS[COMP_CWORD]}"
	if [ "${COMP_CWORD}" -eq 1 ]; then
		COMPREPLY=( $(compgen -W "%s" -- "${cur}") )
	fi
}
complete -F _gruff_go_complete gruff-go
`, commands), nil
	case "zsh":
		return fmt.Sprintf(`#compdef gruff-go
_arguments '1:command:(%s)'
`, commands), nil
	case "fish":
		var builder strings.Builder
		for _, command := range completionCommands {
			fmt.Fprintf(&builder, "complete -c gruff-go -f -n '__fish_use_subcommand' -a %s\n", command)
		}
		return builder.String(), nil
	default:
		return "", fmt.Errorf("unsupported shell %q (want bash, zsh, or fish)", shell)
	}
}
