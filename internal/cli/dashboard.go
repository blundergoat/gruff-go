// Package cli implements the gruff-go command-line interface.
//
// This file runs gruff-go dashboard, converting its flags into the browser scan defaults served over HTTP.
// A flag parse or startup check failure, a stray operand or a failed config bootstrap exits 2 before serving; a dashboard.Serve error exits 1.
// A value this file does not check, such as --deep-scan-budget, is passed on unvalidated and can fail later, when a browser scan runs.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blundergoat/gruff-go/internal/dashboard"
	"github.com/blundergoat/gruff-go/internal/finding"
)

// runDashboard parses the gruff-go dashboard flags and starts the local HTTP dashboard.
//
// args holds flags only; a positional operand is rejected because scan targets come from --project and --paths.
// stdout goes to dashboard.Serve; stderr receives flag usage, validation messages, the bootstrap prompt and any serve error.
//
// When interactive is true, the config bootstrap runs before the server starts; when false no bootstrap runs.
//
// It returns 0 when dashboard.Serve finishes without error and 1 when Serve fails.
// It returns 2, before the server starts, for a flag parse or validation failure, a positional operand, or a config bootstrap error.
func runDashboard(args []string, stdout, stderr io.Writer, interactive bool) int {
	flags := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	flags.SetOutput(stderr)
	host := flags.String("host", dashboard.DefaultHost, "dashboard bind host (default 127.0.0.1)")
	port := flags.Int("port", dashboard.DefaultPort, "dashboard bind port")
	scanTimeout := flags.String("scan-timeout", "120", "scan deadline in seconds; 0 disables")
	project := flags.String("project", "", "initial project root for scans")
	paths := flags.String("paths", "", "comma-separated initial paths to analyse")
	configPath := flags.String("config", "", "initial gruff config file")
	noConfig := flags.Bool("no-config", false, "skip auto-loading default gruff config")
	baselinePath := flags.String("baseline", "", "initial baseline file")
	noBaseline := flags.Bool("no-baseline", false, "skip applying any baseline")
	diff := flags.Bool("diff", false, "start dashboard in diff-only scan mode")
	includeIgnored := flags.Bool("include-ignored", false, "include gitignored and default-ignored files; paths.ignore still applies")
	deepScanBudget := flags.String("deep-scan-budget", "", "override both deep-scan bounds as LINES:BYTES, or disable with off")
	// The --help default tracks the binary dashboard default so --help reads truthfully; flags.Visit below detects whether the user set --fail-on.
	// Unset leaves opts.FailOn empty so defaultState can consult the dashboard entry in config.FailOn, per ADR-010.
	failOn := flags.String("fail-on", string(finding.DefaultFailThresholdFor("dashboard")), "minimum severity that fails a scan; use none to disable the gate")
	reportInteractive := flags.Bool("report-interactive", false, "enable interactive findings filter UI in the report")
	editorLink := flags.String("report-editor-link", "none", "html file:line link mode: none, vscode, or phpstorm")
	allowPublic := flags.Bool("allow-public", false, "allow binding to non-loopback hosts")
	// A typo such as --prot or a non-number --port lands here; the flag package already wrote the message and usage to stderr.
	if err := parseCommandArguments(flags, args); err != nil {
		return 2
	}

	// Scan targets arrive through flags here, so an operand names a target the server would never
	// scan. Rejecting beats guessing between --project and --paths.
	if flags.NArg() > 0 {
		fmt.Fprintln(stderr, "dashboard takes no positional arguments; name scan targets with --project and --paths")
		return 2
	}

	if *port < 1 || *port > 65535 {
		fmt.Fprintln(stderr, "--port must be an integer from 1 to 65535")
		return 2
	}

	timeout, err := parseDashboardTimeout(*scanTimeout)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	if !supportedEditorLink(*editorLink) {
		fmt.Fprintf(stderr, "unsupported --report-editor-link %q (want none, vscode, or phpstorm)\n", *editorLink)
		return 2
	}

	// ADR-010 precedence: opts.FailOn carries --fail-on only when the user set it; otherwise defaultState consults config, then the binary default.
	// The value is always parsed, so a --fail-on value ParseFailThreshold rejects exits 2 here, before the server starts.
	parsedFailOn, err := finding.ParseFailThreshold(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	failOnExplicit := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "fail-on" {
			failOnExplicit = true
		}
	})

	if interactive {
		// Accepting the prompt in a read-only project directory, where the default config cannot be written, exits 2 with a config: line.
		if err := maybeBootstrapDashboardConfig(*project, *configPath, *noConfig, stderr); err != nil {
			fmt.Fprintf(stderr, "config: %v\n", err)
			return 2
		}
	}

	opts := dashboard.Options{
		Host:              *host,
		Port:              *port,
		ScanTimeout:       timeout,
		ProjectRoot:       *project,
		Paths:             splitComma(*paths),
		ConfigPath:        *configPath,
		SkipConfig:        *noConfig,
		BaselinePath:      *baselinePath,
		SkipBaseline:      *noBaseline,
		IncludeIgnored:    *includeIgnored,
		DeepScanBudget:    *deepScanBudget,
		DiffMode:          *diff,
		FailOn:            optsFailOnFromCLI(failOnExplicit, parsedFailOn),
		ReportInteractive: *reportInteractive,
		EditorLink:        *editorLink,
		AllowPublic:       *allowPublic,
	}

	if err := dashboard.Serve(context.Background(), stdout, stderr, opts); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// maybeBootstrapDashboardConfig runs the same interactive config bootstrap as analyse, summary and report, for the dashboard's project root.
//
// The dashboard loads config lazily per scan, so the prompt must fire before the HTTP server starts to remain usable.
//
// projectRoot is the --project value, and an empty one selects the working directory.
// configPath and noConfig carry --config and --no-config, and a non-empty configPath or a true noConfig skips the bootstrap.
// promptWriter receives the y/N question, the success line and the setup hint.
//
// It returns the os.Getwd error when projectRoot is empty and the working directory cannot be resolved.
// It also fails when the config lookup under the root, the default config write, or a write of the success line or hint to promptWriter fails.
// It returns nil when bootstrap is skipped, stdin is no terminal, a config exists, the prompt does not get a yes, or the file is written.
func maybeBootstrapDashboardConfig(projectRoot, configPath string, noConfig bool, promptWriter io.Writer) error {
	root := projectRoot
	if root == "" {
		cwd, err := os.Getwd()
		// A shell whose working directory was deleted makes os.Getwd fail here, and runDashboard exits 2 with a config: line.
		if err != nil {
			return err
		}
		root = cwd
	}
	return maybeBootstrapConfigInRoot(root, configPath, noConfig, promptWriter)
}

// optsFailOnFromCLI returns the parsed --fail-on value only when the user explicitly set the flag.
//
// The empty result for an unset flag lets defaultState consult the dashboard entry of config.FailOn, then the binary default, per ADR-010.
// explicit is true when the user set --fail-on, and parsed is the threshold from finding.ParseFailThreshold, ignored when explicit is false.
func optsFailOnFromCLI(explicit bool, parsed finding.FailThreshold) string {
	if explicit {
		return string(parsed)
	}
	return ""
}

// parseDashboardTimeout turns the --scan-timeout flag text into the scan deadline handed to the dashboard.
//
// raw is the flag text, read as a whole number of seconds.
// It returns raw seconds as a time.Duration; raw 0 gives a zero duration, which the --scan-timeout help describes as disabled.
// It returns an error, and a zero duration, when raw is not an integer or is negative.
func parseDashboardTimeout(raw string) (time.Duration, error) {
	seconds, err := strconv.Atoi(raw)
	// A unit suffix such as --scan-timeout 2m, or a negative number, lands here and runDashboard exits 2 before the server starts.
	if err != nil || seconds < 0 {
		return 0, fmt.Errorf("--scan-timeout must be a non-negative integer of seconds")
	}
	if seconds == 0 {
		return 0, nil
	}
	return time.Duration(seconds) * time.Second, nil
}

// splitComma splits raw on commas and drops empty entries after trimming whitespace.
// It returns the trimmed non-empty parts in input order; an empty raw gives nil, while a raw with no non-blank parts gives an empty slice.
func splitComma(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
