// Package cli implements the gruff-go command-line interface.
// Help text lives here so command usage, examples, and flag descriptions stay consistent across entrypoints.
package cli

import (
	"fmt"
	"io"
	"strings"
)

// commandEntry is one subcommand as every public surface sees it: the usage screen, the shell completion script,
// and the per-command flag list. Keeping the three views in one place is what stops a command being registered in
// the dispatch and missing from completion, which is how check-ignore and migrate-config went unadvertised.
//
// An empty description means the name is an alias and the usage screen does not list it; an empty usage means the
// command takes no flags worth a per-command screen.
type commandEntry struct {
	name        string
	description string
	usage       string
}

// optionDescription pairs a flag name with its short help text.
type optionDescription struct {
	flag        string
	description string
}

// commandCatalogue is the one list of subcommands gruff-go ships, in the order the usage screen prints them.
// Every entry must have a case in the dispatch switch in cli.go, and every case must have an entry here.
var commandCatalogue = []commandEntry{
	{name: "analyse", description: "Run the rule registry over the supplied paths and emit a report.", usage: "[--format text|json|summary-json|sarif|github|html|markdown] [--fail-on severity|--min-severity severity] [--deep-scan-budget lines:bytes|off] [--report-editor-link none|vscode|phpstorm] [--report-interactive] [--config path|--no-config] [--baseline path|--no-baseline|--generate-baseline path] [--baseline-show] [--changed-ranges ranges|--since ref|--diff mode] [--changed-scope symbol|hunk] [--diff-base ref] [--show-rule ids] [--hide-rule ids] [--show-pillar names] [--hide-pillar names] [--include-rule ids] [--exclude-rule ids] [--include-pillar names] [--exclude-pillar names] [--min-confidence low|medium|high] [--fail-on-new] [--scan-timeout duration (accepted for cross-port compatibility)] [--include-ignored] [path ...]"},
	{name: "analyze", usage: "[--format text|json|summary-json|sarif|github|html|markdown] [--fail-on severity|--min-severity severity] [--deep-scan-budget lines:bytes|off] [--report-editor-link none|vscode|phpstorm] [--report-interactive] [--config path|--no-config] [--baseline path|--no-baseline|--generate-baseline path] [--baseline-show] [--changed-ranges ranges|--since ref|--diff mode] [--changed-scope symbol|hunk] [--diff-base ref] [--show-rule ids] [--hide-rule ids] [--show-pillar names] [--hide-pillar names] [--include-rule ids] [--exclude-rule ids] [--include-pillar names] [--exclude-pillar names] [--min-confidence low|medium|high] [--fail-on-new] [--scan-timeout duration (accepted for cross-port compatibility)] [--include-ignored] [path ...]"},
	{name: "baseline", description: "Write a JSON baseline of current findings for use with --baseline.", usage: "--out path [--migrate-baseline path] [--force] [--config path|--no-config] [--deep-scan-budget lines:bytes|off] [--include-ignored] [path ...]"},
	{name: "check-ignore", description: "Report whether paths.ignore / gitignore would exclude given paths, and why.", usage: "[--format text|json] [--config path|--no-config] [--include-ignored] <path> ..."},
	{name: "completion", description: "Dump a shell completion script.", usage: "[bash|zsh|fish]"},
	{name: "dashboard", description: "Serve the local gruff-go dashboard.", usage: "[--host host] [--port port] [--scan-timeout seconds] [--project path] [--paths csv] [--config path|--no-config] [--deep-scan-budget lines:bytes|off] [--baseline path|--no-baseline] [--diff] [--include-ignored] [--fail-on severity] [--report-interactive] [--report-editor-link none|vscode|phpstorm] [--allow-public]"},
	{name: "help", description: "Display help for a command, or the command list if none is given."},
	{name: "hook", description: "Emit the gruff.hook.v2 agent-hook JSON contract for edited regions.", usage: "[--format json] [--capabilities] [--config path|--no-config] [--deep-scan-budget lines:bytes|off] [--changed-ranges ranges] [--diff ref|working-tree|staged|unstaged|-] [--baseline path] [--fail-on severity] [--min-confidence low|medium|high] [--fail-on-new] [--fail-on-diagnostics] [--include-ignored] [path ...]"},
	{name: "init", description: "Generate a default .gruff-go.yaml mirroring the built-in registry defaults.", usage: "[--force [--reset]]"},
	{name: "list", description: "List the available commands."},
	{name: "list-rules", description: "List gruff rule metadata.", usage: "[--format text|json] [--config path|--no-config]"},
	{name: "migrate-config", description: "Rewrite a 0.5 config for the current schema, writing the result to a different file.", usage: "--config path --output path [--dry-run]"},
	{name: "report", description: "Render a gruff report to stdout or a file.", usage: "[--format html|json] [--output path] [--deep-scan-budget lines:bytes|off] [--report-editor-link none|vscode|phpstorm] [--report-interactive] [--config path|--no-config] [--baseline path] [--diff-base ref] [--fail-on severity|--min-severity severity] [--include-rules ids] [--exclude-rules ids] [--include-pillars names] [--exclude-pillars names] [--include-ignored] [path ...]"},
	{name: "summary", description: "Print a compact digest of a scan: score, per-pillar counts, top rules and offenders.", usage: "[--format text|json] [--top N] [--fail-on severity|--min-severity severity] [--deep-scan-budget lines:bytes|off] [--config path|--no-config] [--include-ignored] [path ...]"},
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
	for _, entry := range commandCatalogue {
		// An entry with no description is an alias the usage screen deliberately does not repeat.
		if entry.description != "" {
			fmt.Fprintf(writer, "  %s  %s\n", padCommandName(style.green(entry.name), entry.name), entry.description)
		}
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
	writeCommandHelp(name, commandUsage, stdout, stdoutStyle)
	return 0
}

// commandUsages maps each subcommand that has a per-command flag list to it, derived from the catalogue so a new
// command cannot reach the dispatch with a usage screen nobody wrote.
var commandUsages = buildCommandUsages()

// buildCommandUsages collects the catalogue entries that carry a flag list.
func buildCommandUsages() map[string]string {
	usages := make(map[string]string, len(commandCatalogue))
	for _, entry := range commandCatalogue {
		// A command with no flags of its own has no usage screen, and an empty line would read as a missing one.
		if entry.usage != "" {
			usages[entry.name] = entry.usage
		}
	}
	return usages
}

// writeCommandHelp renders the stable one-line command usage. It intentionally
// advertises GNU double-dash flags even though Go's flag package also accepts
// single-dash forms for backward compatibility.
func writeCommandHelp(name, commandUsage string, writer io.Writer, style ansiStyler) {
	fmt.Fprintf(writer, "  %s %s\n", style.green("gruff-go "+name), commandUsage)
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
