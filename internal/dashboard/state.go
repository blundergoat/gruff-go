// Package dashboard state helpers build the initial form state for new sessions.
// They translate dashboard Options into the report.DashboardState payload.
package dashboard

import (
	"os"
	"strings"

	"github.com/blundergoat/gruff-go/internal/report"
)

// defaultState builds the dashboard form state used on first load.
func defaultState(opts Options) report.DashboardState {
	scope := "full"
	if opts.DiffMode {
		scope = "diff"
	}
	failOn := opts.FailOn
	if failOn == "" {
		failOn = "medium"
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

// currentWorkingDirectory returns os.Getwd or empty string on error.
func currentWorkingDirectory() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return wd
}
