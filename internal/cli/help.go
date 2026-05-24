// Package cli implements the gruff-go command-line interface.
// Help text lives here so command usage, examples, and flag descriptions stay consistent across entrypoints.
package cli

import (
	"fmt"
	"io"
	"strings"
)

// commandDescription pairs a subcommand name with its short help text.
type commandDescription struct {
	name        string
	description string
}

// optionDescription pairs a flag name with its short help text.
type optionDescription struct {
	flag        string
	description string
}

// commandList enumerates the subcommands shown in the top-level usage screen.
var commandList = []commandDescription{
	{"analyse", "Run the rule registry over the supplied paths and emit a report."},
	{"baseline", "Write a JSON baseline of current findings for use with --baseline."},
	{"completion", "Dump a shell completion script."},
	{"dashboard", "Serve the local gruff-go dashboard."},
	{"help", "Display help for a command, or the command list if none is given."},
	{"init", "Generate a default .gruff-go.yaml mirroring the built-in registry defaults."},
	{"list", "List the available commands."},
	{"list-rules", "List gruff rule metadata."},
	{"report", "Render a gruff report to stdout or a file."},
	{"summary", "Print a compact digest of a scan: score, per-pillar counts, top rules and offenders."},
}

// globalOptions enumerates the cross-command flags shown in the usage screen.
var globalOptions = []optionDescription{
	{"-h, --help", "Display help. Use \"gruff-go help <command>\" for command-specific help."},
	{"-V, --version", "Display the gruff-go version."},
	{"-q, --quiet", "Only errors are displayed; non-error output is suppressed."},
	{"    --silent", "Alias for --quiet."},
	{"-n, --no-interaction", "Skip the bootstrap prompt when no .gruff-go.yaml is found."},
	{"    --ansi", "Force ANSI colour output."},
	{"    --no-ansi", "Disable ANSI colour output."},
	{"-v, --verbose", "Accepted for cross-gruff parity; currently no output change."},
}

// commandNameWidth is the column width used when aligning subcommand names.
const commandNameWidth = 10

// optionFlagWidth is the column width used when aligning option flag names.
// The longest global option name (`-n, --no-interaction`) sets the floor.
const optionFlagWidth = 20

// usage prints the top-level help screen describing commands and global options.
func usage(writer io.Writer, style ansiStyler) {
	fmt.Fprintf(writer, "%s %s\n\n", style.bold("gruff-go"), toolVersion)
	fmt.Fprintln(writer, style.yellow("Usage:"))
	fmt.Fprintln(writer, "  gruff-go [--version] [-q|--quiet|--silent] [-n|--no-interaction] [--ansi|--no-ansi] [-v|--verbose] <command> [options] [arguments]")
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, style.yellow("Available commands:"))
	for _, cmd := range commandList {
		fmt.Fprintf(writer, "  %s  %s\n", padCommandName(style.green(cmd.name), cmd.name), cmd.description)
	}
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, style.yellow("Global options:"))
	for _, opt := range globalOptions {
		fmt.Fprintf(writer, "  %s  %s\n", padOptionName(style.green(opt.flag), opt.flag), opt.description)
	}
	fmt.Fprintln(writer)
	fmt.Fprintf(writer, "Run %s for the per-command flag list.\n", style.green("\"gruff-go help <command>\""))
}

// helpForCommand prints the usage line for a specific subcommand.
func helpForCommand(name string, stdout, stderr io.Writer, stdoutStyle, stderrStyle ansiStyler) int {
	commandUsage, ok := commandUsages[name]
	if !ok {
		fmt.Fprintf(stderr, "unknown command %q\n", name)
		usage(stderr, stderrStyle)
		return 2
	}
	fmt.Fprintf(stdout, "  %s %s\n", stdoutStyle.green("gruff-go "+name), commandUsage)
	return 0
}

// commandUsages maps each subcommand to its concrete usage flag list.
var commandUsages = map[string]string{
	"analyse":    "[--format text|json|summary-json|sarif|github|html] [--fail-on severity|--min-severity severity] [--report-editor-link none|vscode|phpstorm] [--report-interactive] [--config path|--no-config] [--baseline path|--generate-baseline path] [--diff-base ref] [--include-rules ids] [--exclude-rules ids] [--include-pillars names] [--exclude-pillars names] [--include-ignored] [path ...]",
	"analyze":    "[--format text|json|summary-json|sarif|github|html] [--fail-on severity|--min-severity severity] [--report-editor-link none|vscode|phpstorm] [--report-interactive] [--config path|--no-config] [--baseline path|--generate-baseline path] [--diff-base ref] [--include-rules ids] [--exclude-rules ids] [--include-pillars names] [--exclude-pillars names] [--include-ignored] [path ...]",
	"baseline":   "--out path [--config path|--no-config] [--include-ignored] [path ...]",
	"completion": "[bash|zsh|fish]",
	"init":       "[--force [--reset]]",
	"list-rules": "[--format text|json] [--config path|--no-config]",
	"summary":    "[--format text|json] [--top N] [--fail-on severity|--min-severity severity] [--config path|--no-config] [--include-ignored] [path ...]",
	"report":     "[--format html|json] [--output path] [--report-editor-link none|vscode|phpstorm] [--report-interactive] [--config path|--no-config] [--baseline path] [--diff-base ref] [--fail-on severity|--min-severity severity] [--include-rules ids] [--exclude-rules ids] [--include-pillars names] [--exclude-pillars names] [--include-ignored] [path ...]",
	"dashboard":  "[--host host] [--port port] [--scan-timeout seconds] [--project path] [--paths csv] [--config path|--no-config] [--baseline path|--no-baseline] [--diff] [--include-ignored] [--fail-on severity] [--report-interactive] [--report-editor-link none|vscode|phpstorm] [--allow-public]",
}

// padCommandName right-pads a command name to commandNameWidth for table layout.
func padCommandName(coloured, plain string) string {
	if width := commandNameWidth - len(plain); width > 0 {
		return coloured + strings.Repeat(" ", width)
	}
	return coloured
}

// padOptionName right-pads an option flag name to optionFlagWidth for table layout.
func padOptionName(coloured, plain string) string {
	if width := optionFlagWidth - len(plain); width > 0 {
		return coloured + strings.Repeat(" ", width)
	}
	return coloured
}
