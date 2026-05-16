package dashboard

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
)

// NewHandler returns the dashboard HTTP handler that owns / and /scan routes.
func NewHandler(opts Options) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/" {
			http.NotFound(writer, request)
			return
		}
		if request.Method != http.MethodGet {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		state := stateFromQuery(opts, request.URL.Query())
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = report.WriteDashboard(writer, state)
	})
	mux.HandleFunc("/scan", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleScan(writer, request, opts)
	})
	return mux
}

func handleScan(writer http.ResponseWriter, request *http.Request, opts Options) {
	query := request.URL.Query()
	state := stateFromQuery(opts, query)
	scanOpts := buildScanOptions(opts, state)

	ctx := request.Context()
	timeout := opts.ScanTimeout
	if timeout <= 0 {
		timeout = DefaultScanTimeout
	}
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")

	started := time.Now()
	reportData, runErr := runScan(scanCtx, scanOpts)
	duration := time.Since(started)
	durationMs := int(duration.Milliseconds())

	if runErr != nil {
		_ = report.WriteDashboardError(writer, "Scan failed.", runErr.Error(), 2, durationMs)
		return
	}

	if scanCtx.Err() == context.DeadlineExceeded {
		_ = report.WriteDashboardError(
			writer,
			fmt.Sprintf("Scan exceeded %ds timeout.", int(timeout.Seconds())),
			"The dashboard cancelled the scan before it completed. Increase --scan-timeout to allow longer runs.",
			124,
			durationMs,
		)
		return
	}

	var buffer bytes.Buffer
	if err := report.WriteHTML(&buffer, reportData, report.HTMLOptions{
		EditorLink:  opts.EditorLink,
		ProjectRoot: scanOpts.projectRoot,
		Interactive: scanOpts.reportInteractive,
	}); err != nil {
		_ = report.WriteDashboardError(writer, "Render failed.", err.Error(), 2, durationMs)
		return
	}

	metadata := report.ScanMetadata{
		ExitCode:    reportData.Summary.ExitCode,
		DurationMs:  durationMs,
		ProjectRoot: scanOpts.projectRoot,
		Command:     displayCommand(state),
	}
	_, _ = writer.Write([]byte(report.InjectScanMetadata(buffer.String(), metadata)))
}

type scanRunOptions struct {
	projectRoot       string
	paths             []string
	failOn            finding.Severity
	configPath        string
	noConfig          bool
	baselinePath      string
	noBaseline        bool
	includeIgnored    bool
	diffBase          string
	reportInteractive bool
}

func buildScanOptions(opts Options, state report.DashboardState) scanRunOptions {
	projectRoot := strings.TrimSpace(state.Project)
	if projectRoot == "" {
		projectRoot = opts.ProjectRoot
	}
	paths := splitPaths(state.Paths)
	if len(paths) == 0 {
		paths = append([]string(nil), opts.Paths...)
	}

	configPath := strings.TrimSpace(state.Config)
	if configPath == "" {
		configPath = opts.ConfigPath
	}
	noConfig := state.NoConfig == "1" || opts.NoConfig

	baselinePath := strings.TrimSpace(state.Baseline)
	if baselinePath == "" {
		baselinePath = opts.BaselinePath
	}
	noBaseline := state.NoBaseline == "1" || opts.NoBaseline
	if noBaseline {
		baselinePath = ""
	}

	failOn, _ := finding.ParseSeverity(strings.TrimSpace(state.FailOn))
	if !failOn.Valid() {
		parsed, err := finding.ParseSeverity(opts.FailOn)
		if err == nil {
			failOn = parsed
		} else {
			failOn = finding.SeverityMedium
		}
	}

	diffBase := ""
	if state.ScanScope == "diff" {
		diffBase = "HEAD"
	}

	includeIgnored := state.IncludeIgnored == "1" || opts.IncludeIgnored

	return scanRunOptions{
		projectRoot:       projectRoot,
		paths:             paths,
		failOn:            failOn,
		configPath:        configPath,
		noConfig:          noConfig,
		baselinePath:      baselinePath,
		noBaseline:        noBaseline,
		includeIgnored:    includeIgnored,
		diffBase:          diffBase,
		reportInteractive: state.ReportInteractive == "1" || opts.ReportInteractive,
	}
}

func runScan(_ context.Context, scanOpts scanRunOptions) (analysis.Report, error) {
	if scanOpts.projectRoot != "" {
		if err := changeDir(scanOpts.projectRoot); err != nil {
			return analysis.Report{}, err
		}
	}
	return analysis.Run(analysis.Options{
		Paths:          scanOpts.paths,
		Format:         "html",
		FailOn:         scanOpts.failOn,
		BaselinePath:   scanOpts.baselinePath,
		DiffBase:       scanOpts.diffBase,
		IncludeIgnored: scanOpts.includeIgnored,
	})
}

func splitPaths(raw string) []string {
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

func displayCommand(state report.DashboardState) string {
	args := []string{"gruff-go", "analyse", "--format", "html"}
	if state.Config != "" {
		args = append(args, "--config", state.Config)
	}
	if state.NoConfig == "1" {
		args = append(args, "--no-config")
	}
	if state.Baseline != "" && state.NoBaseline != "1" {
		args = append(args, "--baseline", state.Baseline)
	}
	if state.ScanScope == "diff" {
		args = append(args, "--diff-base", "HEAD")
	}
	if state.FailOn != "" {
		args = append(args, "--min-severity", state.FailOn)
	}
	paths := splitPaths(state.Paths)
	args = append(args, paths...)
	return strings.Join(args, " ")
}

// stateFromQuery decodes the form state from a /scan query string.
// Falls back to the dashboard's initial defaults for missing keys.
func stateFromQuery(opts Options, values url.Values) report.DashboardState {
	defaults := defaultState(opts)
	get := func(key, fallback string) string {
		value := values.Get(key)
		if value == "" {
			return fallback
		}
		return value
	}
	return report.DashboardState{
		Project:           get("project", defaults.Project),
		Paths:             get("paths", defaults.Paths),
		ScanScope:         get("scanScope", defaults.ScanScope),
		FailOn:            get("failOn", defaults.FailOn),
		Config:            get("config", defaults.Config),
		Baseline:          get("baseline", defaults.Baseline),
		NoBaseline:        get("noBaseline", defaults.NoBaseline),
		NoConfig:          get("noConfig", defaults.NoConfig),
		IncludeIgnored:    get("includeIgnored", defaults.IncludeIgnored),
		ReportInteractive: get("reportInteractive", defaults.ReportInteractive),
	}
}
