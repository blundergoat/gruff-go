// Package dashboard state helpers build the initial form state for new sessions.
//
// They translate dashboard Options into the report.DashboardState payload that fills the dashboard form on first load.
// Fail-on comes from the --fail-on flag, then the config's failOn.dashboard value, then the binary default.
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
//
// opts supplies the project root, scan paths, diff mode, fail-on flag, config and baseline paths, and the boolean toggles copied into the form.
// It returns a state whose FailOn is opts.FailOn, else the config's dashboard threshold, else the binary default for the dashboard.
// Project falls back to the working directory when opts.ProjectRoot is empty, and stays empty only if that lookup also fails.
func defaultState(opts Options) report.DashboardState {
	scope := "full"
	if opts.DiffMode {
		scope = "diff"
	}
	// ADR-010 precedence: the --fail-on flag given at dashboard startup, then failOn.dashboard in the config, then the binary default.
	// A non-empty failOn value in the dashboard URL beats all three; stateFromQuery uses this value when failOn is absent or empty.
	failOn := opts.FailOn
	if failOn == "" {
		// An invalid or skipped config, or one without failOn.dashboard, yields no value here and the form falls back to the binary default.
		if cfgValue := loadDashboardConfigForDefault(opts).FailOn["dashboard"]; cfgValue != "" {
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
// It returns the query text that report.DashboardScanQuery builds from state; this wrapper adds no fields or encoding of its own.
func dashboardQueryFromState(state report.DashboardState) string {
	return report.DashboardScanQuery(state)
}

// firstNonEmpty returns the first non-empty value or "" when all are empty.
// values are checked in argument order, and a string holding only whitespace still counts as non-empty.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// boolFlag returns "1" for true and "" for false, matching the dashboard form contract.
// value is the option being encoded; true marks the form field as set and false leaves it blank.
func boolFlag(value bool) string {
	if value {
		return "1"
	}
	return ""
}

// loadDashboardConfigForDefault loads the project config so defaultState can consult failOn.dashboard.
//
// Best-effort: any config path, read, parse or validation error, or a failed os.Getwd, gives a zero-value Config.
// defaultState then falls back to DefaultFailThresholdFor rather than reporting the config problem.
// Loading per request is cheap and keeps the dashboard reactive to config edits made mid-session.
//
// opts supplies the project root, read from the working directory when it is blank after trimming, plus the explicit config path and SkipConfig.
// When opts.SkipConfig is set the result is a zero-value Config and no file is read.
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

// currentWorkingDirectory returns os.Getwd, or an empty string on error.
// defaultState uses its value only when no project root was given, so an error leaves the form's Project field blank.
func currentWorkingDirectory() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return wd
}
