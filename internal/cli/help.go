package cli

import (
	"fmt"
	"io"
	"strings"
)

type commandDescription struct {
	name        string
	description string
}

type optionDescription struct {
	flag        string
	description string
}

var commandList = []commandDescription{
	{"analyse", "Run the rule registry over the supplied paths and emit a report."},
	{"baseline", "Write a JSON baseline of current findings for use with --baseline."},
	{"dashboard", "Serve the local gruff-go dashboard."},
	{"help", "Display help for a command, or the command list if none is given."},
	{"list", "List the available commands."},
	{"list-rules", "List gruff rule metadata."},
	{"report", "Render a gruff report to stdout or a file."},
	{"summary", "Print a compact digest of a scan: score, per-pillar counts, top rules and offenders."},
}

var globalOptions = []optionDescription{
	{"-h, --help", "Display help. Use \"gruff-go help <command>\" for command-specific help."},
	{"-V, --version", "Display the gruff-go version."},
	{"-q, --quiet", "Only errors are displayed; non-error output is suppressed."},
	{"    --ansi", "Force ANSI colour output."},
	{"    --no-ansi", "Disable ANSI colour output."},
}

const commandNameWidth = 10
const optionFlagWidth = 13

func usage(writer io.Writer, style ansiStyler) {
	fmt.Fprintf(writer, "%s %s\n\n", style.bold("gruff-go"), toolVersion)
	fmt.Fprintln(writer, style.yellow("Usage:"))
	fmt.Fprintln(writer, "  gruff-go [--version] [-q|--quiet] [--ansi|--no-ansi] <command> [options] [arguments]")
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

var commandUsages = map[string]string{
	"analyse":    "[--format text|json|summary-json|sarif|github|html] [--report-editor-link none|vscode|phpstorm] [--report-interactive] [--config path|--no-config] [--baseline path] [--diff-base ref] [--include-rules ids] [--exclude-rules ids] [--include-pillars names] [--exclude-pillars names] [path ...]",
	"analyze":    "[--format text|json|summary-json|sarif|github|html] [--report-editor-link none|vscode|phpstorm] [--report-interactive] [--config path|--no-config] [--baseline path] [--diff-base ref] [--include-rules ids] [--exclude-rules ids] [--include-pillars names] [--exclude-pillars names] [path ...]",
	"baseline":   "--out path [--config path|--no-config] [path ...]",
	"list-rules": "[--format text|json] [--config path|--no-config]",
	"summary":    "[--format text|json] [--top N] [--config path|--no-config] [--include-ignored] [path ...]",
	"report":     "[--format html|json] [--output path] [--report-editor-link none|vscode|phpstorm] [--report-interactive] [--config path|--no-config] [--baseline path] [--diff-base ref] [--min-severity severity] [--include-rules ids] [--exclude-rules ids] [--include-pillars names] [--exclude-pillars names] [path ...]",
	"dashboard":  "[--host host] [--port port] [--scan-timeout seconds] [--project path] [--paths csv] [--config path|--no-config] [--baseline path|--no-baseline] [--diff] [--include-ignored] [--fail-on severity] [--report-interactive] [--report-editor-link none|vscode|phpstorm] [--allow-public]",
}

func padCommandName(coloured, plain string) string {
	if width := commandNameWidth - len(plain); width > 0 {
		return coloured + strings.Repeat(" ", width)
	}
	return coloured
}

func padOptionName(coloured, plain string) string {
	if width := optionFlagWidth - len(plain); width > 0 {
		return coloured + strings.Repeat(" ", width)
	}
	return coloured
}
