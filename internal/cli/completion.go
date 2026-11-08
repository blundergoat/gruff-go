// Package cli implements the gruff-go command-line interface.
//
// The completion command prints a small static script for bash, zsh or fish, with bash when the user names no shell.
// Each script completes only the subcommand name, the first word after gruff-go.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

// completionCommands lists the top-level subcommand names emitted into the generated shell completion scripts,
// derived from the one catalogue in help.go so completion can never advertise fewer commands than the port ships.
var completionCommands = buildCompletionCommands()

// buildCompletionCommands reads every catalogue name, aliases included, since a user may type either spelling.
// It returns one name per commandCatalogue entry, in catalogue order, as a non-nil slice that is empty only when the catalogue is empty.
func buildCompletionCommands() []string {
	names := make([]string, 0, len(commandCatalogue))
	for _, entry := range commandCatalogue {
		names = append(names, entry.name)
	}
	return names
}

// runCompletion prints a shell completion script for the requested shell.
// args holds the arguments after the completion subcommand; its one optional operand names the shell, and bash is used when it is absent.
// It returns 0 once the script is on stdout, or 2 after reporting the failure on stderr, such as a parse error, extra operand or unsupported shell.
func runCompletion(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("completion", flag.ContinueOnError)
	flags.SetOutput(stderr)
	// A flag such as --shell zsh lands here, since completion defines none, and the command exits 2 without printing a script.
	if err := parseCommandArguments(flags, args); err != nil {
		return 2
	}
	// Only the first operand names a shell; a second is input this command would silently drop.
	if flags.NArg() > 1 {
		fmt.Fprintln(stderr, "completion takes at most one shell argument")
		return 2
	}
	shell := "bash"
	if flags.NArg() > 0 {
		shell = flags.Arg(0)
	}
	script, err := completionScript(shell)
	// An unsupported shell, such as gruff-go completion powershell, lands here; stderr names bash, zsh and fish and the command exits 2.
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

// completionScript returns the inline completion script for shell, the operand of gruff-go completion or bash when none was given.
//
// Supports bash, zsh and fish; each script offers every completionCommands name as the first word after gruff-go.
// Any other shell returns an error and an empty string, so runCompletion exits 2 with a clear message rather than an empty script.
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
