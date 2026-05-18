package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/blundergoat/gruff-go/internal/dashboard"
	"github.com/blundergoat/gruff-go/internal/finding"
)

func runDashboard(args []string, stdout, stderr io.Writer) int {
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
	failOn := flags.String("fail-on", string(finding.SeverityMedium), "minimum severity that fails a scan")
	reportInteractive := flags.Bool("report-interactive", false, "enable interactive findings filter UI in the report")
	editorLink := flags.String("report-editor-link", "none", "html file:line link mode: none, vscode, or phpstorm")
	allowPublic := flags.Bool("allow-public", false, "allow binding to non-loopback hosts")
	if err := flags.Parse(args); err != nil {
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

	parsedFailOn, err := finding.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
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
		Diff:              *diff,
		FailOn:            string(parsedFailOn),
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

func parseDashboardTimeout(raw string) (time.Duration, error) {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("--scan-timeout must be a non-negative integer of seconds")
	}
	if value == 0 {
		return 0, nil
	}
	return time.Duration(value) * time.Second, nil
}

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
