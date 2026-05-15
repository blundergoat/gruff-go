package dashboard

import (
	"os"
	"strings"

	"github.com/blundergoat/gruff-go/internal/report"
)

// defaultState builds the dashboard form state used on first load.
func defaultState(opts Options) report.DashboardState {
	scope := "full"
	if opts.Diff {
		scope = "diff"
	}
	failOn := opts.FailOn
	if failOn == "" {
		failOn = "medium"
	}
	state := report.DashboardState{
		Project:    firstNonEmpty(opts.ProjectRoot, currentWorkingDirectory()),
		Paths:      strings.Join(opts.Paths, ","),
		ScanScope:  scope,
		FailOn:     failOn,
		Config:     opts.ConfigPath,
		Baseline:   opts.BaselinePath,
		NoBaseline: boolFlag(opts.NoBaseline),
		NoConfig:   boolFlag(opts.NoConfig),
	}
	if opts.IncludeIgnored {
		state.IncludeIgnored = "1"
	}
	if opts.ReportInteractive {
		state.ReportInteractive = "1"
	}
	return state
}

func dashboardQueryFromState(state report.DashboardState) string {
	return report.DashboardScanQuery(state)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func boolFlag(value bool) string {
	if value {
		return "1"
	}
	return ""
}

func currentWorkingDirectory() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return wd
}

func changeDir(path string) error {
	return os.Chdir(path)
}
