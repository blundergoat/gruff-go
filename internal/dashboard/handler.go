// Package dashboard holds the HTTP handlers behind the gruff-go dashboard page.
//
// They translate the form's query parameters into analysis options, run the scan, and render the HTML report.
// An expired scan timeout shows an error page with exit code 124, and a returned scan error or render failure shows one with exit code 2.
// Findings that fail the exit gate still render the normal report.
package dashboard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blundergoat/gruff-go/internal/analysis"
	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// NewHandler returns the dashboard HTTP handler that owns the / and /scan routes.
//
// opts supplies the dashboard defaults: / renders the form state built from opts and the query, and /scan hands opts to handleScan.
// The / route answers any path other than / with 404 before checking the method, and both routes reject methods other than GET with 405.
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

// handleScan reads the /scan query parameters from request, runs the analysis, and writes the HTML report or an error page to writer.
//
// opts supplies the form defaults, the ScanTimeout that bounds the scan when positive, and the EditorLink for the rendered report.
// A timeout writes an error page with exit code 124, and a returned scan error or render failure writes one with exit code 2.
// Findings that fail the exit gate still get the normal report, with their exit code in its metadata.
func handleScan(writer http.ResponseWriter, request *http.Request, opts Options) {
	query := request.URL.Query()
	state := stateFromQuery(opts, query)
	scanOpts := buildScanOptions(opts, state)

	scanCtx, cancel := scanContext(request.Context(), opts.ScanTimeout)
	defer cancel()

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")

	started := time.Now()
	reportData, runErr := runScan(scanCtx, scanOpts)
	duration := time.Since(started)
	durationMs := int(duration.Milliseconds())

	// A scan that outlasts the scan timeout lands here, even one that returned just past the deadline, and the page shows exit code 124.
	if errors.Is(runErr, context.DeadlineExceeded) || scanCtx.Err() == context.DeadlineExceeded {
		_ = report.WriteDashboardError(
			writer,
			fmt.Sprintf("Scan exceeded %ds timeout.", int(opts.ScanTimeout.Seconds())),
			"The dashboard cancelled the scan before it completed. Increase --scan-timeout to allow longer runs.",
			124,
			durationMs,
		)
		return
	}
	// A config file that fails to load, a malformed deep-scan budget, or an analysis error lands here, and the page shows exit code 2.
	if runErr != nil {
		_ = report.WriteDashboardError(writer, "Scan failed.", runErr.Error(), 2, durationMs)
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
		Command:     displayCommand(state, opts),
	}
	_, _ = writer.Write([]byte(report.InjectScanMetadata(buffer.String(), metadata)))
}

// scanContext derives the context one dashboard scan runs under, adding the per-scan timeout when one is set.
//
// parent is the request context, which ends when the browser disconnects; timeout is the per-scan limit, and zero or less means none.
// It returns the derived context and its cancel function, which the caller must call once the scan ends.
func scanContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout > 0 {
		return context.WithTimeout(parent, timeout)
	}
	return context.WithCancel(parent)
}

// scanRunOptions captures the resolved inputs for a single dashboard scan.
//
// buildScanOptions fills it from the submitted form and the dashboard defaults, and runScan turns it into analysis options.
// deepScanBudget holds the dashboard's raw deep-scan override text, which dashboardRegistry parses as empty, off or LINES:BYTES.
type scanRunOptions struct {
	projectRoot       string
	paths             []string
	failOn            finding.FailThreshold
	configPath        string
	noConfig          bool
	baselinePath      string
	noBaseline        bool
	includeIgnored    bool
	diffBase          string
	reportInteractive bool
	deepScanBudget    string
}

// buildScanOptions merges dashboard defaults with form state into runScan inputs.
//
// state holds the submitted form values, and opts fills a blank project, paths, config or baseline value.
// A skip, include-ignored or interactive flag set in either state or opts is on, and deepScanBudget always comes from opts.
//
// It returns the resolved scanRunOptions; baselinePath is empty when the baseline is skipped, and diffBase is HEAD only for the diff scan scope.
// A state.FailOn that does not parse to a valid threshold, such as a typo, is not reported; opts.FailOn is tried, then the dashboard default.
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
	noConfig := state.SkipConfig == "1" || opts.SkipConfig

	baselinePath := strings.TrimSpace(state.Baseline)
	if baselinePath == "" {
		baselinePath = opts.BaselinePath
	}
	noBaseline := state.SkipBaseline == "1" || opts.SkipBaseline
	if noBaseline {
		baselinePath = ""
	}

	failOn, _ := finding.ParseFailThreshold(strings.TrimSpace(state.FailOn))
	if !failOn.Valid() {
		parsed, err := finding.ParseFailThreshold(opts.FailOn)
		if err == nil {
			failOn = parsed
		} else {
			failOn = finding.DefaultFailThresholdFor("dashboard")
		}
	}

	diffBase := ""
	// The diff scope always diffs against HEAD; the form has no field for another base.
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
		deepScanBudget:    opts.DeepScanBudget,
	}
}

// runScan loads the registry and runs analysis.Analyze for the given scan options.
//
// scanOpts carries the resolved root, paths, threshold, config, budget, baseline and diff settings, and ctx bounds the HTML-format analysis.
// It returns the report from analysis.Analyze together with any error that call gives.
//
// It fails with a zero report when the root cannot be made absolute, or with an error prefixed with config: when dashboardRegistry fails.
func runScan(ctx context.Context, scanOpts scanRunOptions) (analysis.Report, error) {
	root, err := dashboardRoot(scanOpts.projectRoot)
	if err != nil {
		return analysis.Report{}, err
	}
	registry, ignorePaths, sensitiveExclusions, deepScanBudget, err := dashboardRegistry(root, scanOpts.configPath, scanOpts.noConfig, scanOpts.deepScanBudget)
	if err != nil {
		return analysis.Report{}, fmt.Errorf("config: %w", err)
	}
	return analysis.Analyze(analysis.Options{
		Context:             ctx,
		Root:                root,
		Paths:               scanOpts.paths,
		Format:              "html",
		FailOn:              scanOpts.failOn,
		Registry:            registry,
		IgnorePaths:         ignorePaths,
		SensitiveExclusions: sensitiveExclusions,
		DeepScanBudget:      deepScanBudget,
		BaselinePath:        scanOpts.baselinePath,
		DiffBase:            scanOpts.diffBase,
		IncludeIgnored:      scanOpts.includeIgnored,
	})
}

// dashboardRoot resolves the requested project root to an absolute path or empty string.
//
// It returns an empty string and a nil error when root is blank or whitespace; any other root goes to filepath.Abs untrimmed.
// A relative root resolves against the dashboard server's working directory, and the error is non-nil only when filepath.Abs fails.
func dashboardRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", nil
	}
	return filepath.Abs(root)
}

// dashboardRegistry loads project config and returns the rule registry, discovery ignore patterns and sensitive exclusions the scan must honour.
//
// root and configPath tell cfgpkg.LoadAuto where to find the config, and noConfig asks it to skip loading one.
// override is the requested deep-scan budget, either empty for no override, off, or LINES:BYTES, and wins over the config's own budget.
// It also returns that deep-scan budget; with no config file loaded it returns the default registry and nil ignore patterns and exclusions.
//
// It fails with zero values when the config fails to load, override is malformed, or the configured rule options are rejected.
func dashboardRegistry(root, configPath string, noConfig bool, override string) (rule.Registry, []string, []analysis.SensitiveExclusion, analysis.DeepScanBudget, error) {
	defaults := rule.Defaults()
	loaded, err := cfgpkg.LoadAuto(root, configPath, noConfig, defaults.Definitions())
	if err != nil {
		return rule.Registry{}, nil, nil, analysis.DeepScanBudget{}, err
	}
	deepScanBudget, err := dashboardDeepScanBudget(loaded.Config, override)
	if err != nil {
		return rule.Registry{}, nil, nil, analysis.DeepScanBudget{}, err
	}
	// With no config file in use, the scan runs the default rule set and no config ignore patterns or sensitive exclusions apply.
	if loaded.Path == "" {
		return defaults, nil, nil, deepScanBudget, nil
	}
	registry, err := rule.DefaultsConfigured(loaded.Config.RuleOptions())
	if err != nil {
		return rule.Registry{}, nil, nil, analysis.DeepScanBudget{}, err
	}
	return registry, loaded.Config.IgnorePaths, dashboardSensitiveExclusions(loaded.Config), deepScanBudget, nil
}

// dashboardDeepScanBudget mirrors CLI-over-config precedence for dashboard requests.
//
// cfg supplies any configured enabled flag, line cap and byte cap over the built-in defaults, and a non-empty override takes precedence.
// It returns the budget with Override set to default, config or cli; override off disables it, and LINES:BYTES sets both caps.
//
// It fails with a zero budget when a non-empty override is neither off nor two positive integers joined by a single colon.
func dashboardDeepScanBudget(cfg cfgpkg.Config, override string) (analysis.DeepScanBudget, error) {
	budget := analysis.DeepScanBudget{Enabled: true, MaxLines: cfgpkg.DefaultDeepScanMaxLines, MaxBytes: cfgpkg.DefaultDeepScanMaxBytes, Override: "default"}
	if cfg.DeepScanBudget.Enabled != nil || cfg.DeepScanBudget.MaxLines != nil || cfg.DeepScanBudget.MaxBytes != nil {
		budget.Override = "config"
		if cfg.DeepScanBudget.Enabled != nil {
			budget.Enabled = *cfg.DeepScanBudget.Enabled
		}
		if cfg.DeepScanBudget.MaxLines != nil {
			budget.MaxLines = *cfg.DeepScanBudget.MaxLines
		}
		if cfg.DeepScanBudget.MaxBytes != nil {
			budget.MaxBytes = *cfg.DeepScanBudget.MaxBytes
		}
	}
	if override == "" {
		return budget, nil
	}
	if override == "off" {
		budget.Enabled = false
		budget.Override = "cli"
		return budget, nil
	}
	linesRaw, bytesRaw, ok := strings.Cut(override, ":")
	maxLines, linesErr := strconv.Atoi(linesRaw)
	maxBytes, bytesErr := strconv.Atoi(bytesRaw)
	// An override such as 5000, 0:100 or 1:2:3 lands here, and every dashboard scan then fails with exit code 2.
	if !ok || strings.Contains(bytesRaw, ":") || linesErr != nil || bytesErr != nil || maxLines <= 0 || maxBytes <= 0 {
		return analysis.DeepScanBudget{}, fmt.Errorf("--deep-scan-budget must be two positive integers as LINES:BYTES, or off")
	}
	// A LINES:BYTES override replaces the config's budget outright, so it turns the budget back on even when the config disabled it.
	return analysis.DeepScanBudget{Enabled: true, MaxLines: maxLines, MaxBytes: maxBytes, Override: "cli"}, nil
}

// dashboardSensitiveExclusions converts the loaded config's validated section 13a entries into analysis-side scopes for the dashboard's own scan.
//
// cfg is the loaded config; it returns one exclusion per entry with Rule, Path, Symbol and Reason copied, or an empty slice when there are none.
func dashboardSensitiveExclusions(cfg cfgpkg.Config) []analysis.SensitiveExclusion {
	exclusions := make([]analysis.SensitiveExclusion, 0, len(cfg.SensitiveExclusions))
	for _, entry := range cfg.SensitiveExclusions {
		exclusions = append(exclusions, analysis.SensitiveExclusion{
			Rule:   entry.Rule,
			Path:   entry.Path,
			Symbol: entry.Symbol,
			Reason: entry.Reason,
		})
	}
	return exclusions
}

// splitPaths breaks a comma-separated path query value into trimmed entries.
// raw is the paths form value; it returns the non-empty entries in order, nil when raw is empty, and an empty slice when every entry is blank.
func splitPaths(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	paths := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			paths = append(paths, trimmed)
		}
	}
	return paths
}

// displayCommand formats selected scan settings from state as a gruff-go analyse command for display.
//
// opts contributes only the editor link, added unless empty or none; state supplies the other flags and the trailing paths.
// It returns the space-joined command, which always starts with gruff-go analyse --format html and is not shell-quoted.
//
// The project root and the dashboard's deep-scan budget are not included, so the command can differ from the scan that ran.
// Values the scan took from opts instead of the form are left out too, and a fail-on value the scan rejected is still shown as typed.
func displayCommand(state report.DashboardState, opts Options) string {
	args := []string{"gruff-go", "analyse", "--format", "html"}
	if state.ReportInteractive == "1" {
		args = append(args, "--report-interactive")
	}
	if opts.EditorLink != "" && opts.EditorLink != "none" {
		args = append(args, "--report-editor-link", opts.EditorLink)
	}
	if state.Config != "" {
		args = append(args, "--config", state.Config)
	}
	if state.SkipConfig == "1" {
		args = append(args, "--no-config")
	}
	if state.Baseline != "" && state.SkipBaseline != "1" {
		args = append(args, "--baseline", state.Baseline)
	}
	if state.ScanScope == "diff" {
		args = append(args, "--diff-base", "HEAD")
	}
	if state.IncludeIgnored == "1" {
		args = append(args, "--include-ignored")
	}
	if state.FailOn != "" {
		args = append(args, "--fail-on", state.FailOn)
	}
	paths := splitPaths(state.Paths)
	args = append(args, paths...)
	return strings.Join(args, " ")
}

// stateFromQuery decodes the dashboard form state from the / or /scan query string, falling back to the dashboard's initial defaults.
//
// values is the parsed query and opts seeds the defaults; it returns the state with each empty or missing key replaced by its default.
// A field the user clears in the form therefore comes back as its default rather than blank.
func stateFromQuery(opts Options, values url.Values) report.DashboardState {
	defaults := defaultState(opts)
	valueOrDefault := func(key, fallback string) string {
		value := values.Get(key)
		if value == "" {
			return fallback
		}
		return value
	}
	return report.DashboardState{
		Project:           valueOrDefault("project", defaults.Project),
		Paths:             valueOrDefault("paths", defaults.Paths),
		ScanScope:         valueOrDefault("scanScope", defaults.ScanScope),
		FailOn:            valueOrDefault("failOn", defaults.FailOn),
		Config:            valueOrDefault("config", defaults.Config),
		Baseline:          valueOrDefault("baseline", defaults.Baseline),
		SkipBaseline:      valueOrDefault("noBaseline", defaults.SkipBaseline),
		SkipConfig:        valueOrDefault("noConfig", defaults.SkipConfig),
		IncludeIgnored:    valueOrDefault("includeIgnored", defaults.IncludeIgnored),
		ReportInteractive: valueOrDefault("reportInteractive", defaults.ReportInteractive),
	}
}
