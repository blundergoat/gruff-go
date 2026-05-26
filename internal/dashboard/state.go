// Package dashboard state helpers build the initial form state for new sessions.
// They translate dashboard Options into the report.DashboardState payload.
package dashboard

import (
	"os"
	"strings"

	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/report"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// defaultState builds the dashboard form state used on first load.
func defaultState(opts Options) report.DashboardState {
	scope := "full"
	if opts.DiffMode {
		scope = "diff"
	}
	// ADR-010 precedence: opts.FailOn (server --min-severity flag at dashboard
	// startup) > config.MinimumSeverity["dashboard"] > binary default. The URL
	// form input wins above all of these (handled in stateFromQuery, which uses
	// this value only as a fallback when ?failOn= is absent).
	failOn := opts.FailOn
	if failOn == "" {
		if cfgValue := loadDashboardConfigForDefault(opts).MinimumSeverity["dashboard"]; cfgValue != "" {
			failOn = cfgValue
		} else {
			failOn = string(finding.DefaultFailThresholdFor("dashboard"))
		}
	}
	state := report.DashboardState{
		Project:      firstNonEmpty(opts.ProjectRoot, currentWorkingDirectory()),
		Paths:        strings.Join(opts.Paths, ","),
		ScanScope:    scope,
		FailOn:       failOn,
		Config:       opts.ConfigPath,
		Baseline:     opts.BaselinePath,
		SkipBaseline: boolFlag(opts.SkipBaseline),
		SkipConfig:   boolFlag(opts.SkipConfig),
	}
	if opts.IncludeIgnored {
		state.IncludeIgnored = "1"
	}
	if opts.ReportInteractive {
		state.ReportInteractive = "1"
	}
	return state
}

// dashboardQueryFromState encodes the dashboard state as a URL query string.
func dashboardQueryFromState(state report.DashboardState) string {
	return report.DashboardScanQuery(state)
}

// firstNonEmpty returns the first non-empty value or "" when all are empty.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// boolFlag returns "1" for true and "" for false, matching the dashboard form contract.
func boolFlag(value bool) string {
	if value {
		return "1"
	}
	return ""
}

// loadDashboardConfigForDefault loads the project config so defaultState can
// consult minimumSeverity.dashboard. Best-effort: any error (missing file,
// invalid YAML, walk failure) returns a zero-value Config, which makes the
// caller fall back to DefaultFailThresholdFor. Per-request load is cheap and
// keeps the dashboard reactive to mid-session config edits.
func loadDashboardConfigForDefault(opts Options) cfgpkg.Config {
	if opts.SkipConfig {
		return cfgpkg.Config{}
	}
	root := strings.TrimSpace(opts.ProjectRoot)
	if root == "" {
		var err error
		root, err = os.Getwd()
		if err != nil {
			return cfgpkg.Config{}
		}
	}
	defaults := rule.Defaults()
	loaded, err := cfgpkg.LoadAuto(root, opts.ConfigPath, opts.SkipConfig, defaults.Definitions())
	if err != nil {
		return cfgpkg.Config{}
	}
	return loaded.Config
}

// currentWorkingDirectory returns os.Getwd or empty string on error.
func currentWorkingDirectory() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return wd
}
