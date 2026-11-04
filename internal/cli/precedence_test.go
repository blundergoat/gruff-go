// Package cli precedence tests lock the --fail-on precedence ladder that resolveFailOn applies.
//
// The ladder is an explicit --fail-on flag, then the config failOn entry for that command, then the built-in default for that command.
// The dashboard command resolves its own gate separately, so the dashboard case here covers only the helper's default fallback.
// This file calls resolveFailOn directly so the helper's precedence rules are tested in one place.
package cli

import (
	"bytes"
	"testing"

	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestResolveFailOnPrecedence checks the three precedence levels for the analyse, summary, report and dashboard command names.
//
// An explicit flag beats config, config beats the default when no flag is given, and the default applies when neither supplies a value.
// A failing case means resolveFailOn rejected a valid value or chose a different threshold than the expected flag, config entry or default.
func TestResolveFailOnPrecedence(t *testing.T) {
	cfg := cfgpkg.Config{
		FailOn: cfgpkg.CommandThresholds{
			"analyse": "error",
			"summary": "error",
			"report":  "warning",
			// dashboard intentionally omitted - exercises the
			// "fall back to DefaultFailThresholdFor" branch.
		},
	}
	cases := []struct {
		name     string
		rawValue string
		explicit bool
		cmd      string
		want     finding.FailThreshold
	}{
		{
			name: "explicit flag beats config (analyse)", rawValue: "warning", explicit: true, cmd: "analyse",
			want: finding.FailThresholdWarning,
		},
		{
			name: "explicit flag beats config (summary)", rawValue: "advisory", explicit: true, cmd: "summary",
			want: finding.FailThresholdAdvisory,
		},
		{
			name: "explicit flag beats config (report)", rawValue: "none", explicit: true, cmd: "report",
			want: finding.FailThresholdNone,
		},
		// Without an explicit flag, rawValue is the command's default, standing in for a --fail-on the user never typed.
		{
			name: "config overrides default (analyse error)", rawValue: string(finding.DefaultFailThresholdFor("analyse")), explicit: false, cmd: "analyse",
			want: finding.FailThresholdError,
		},
		{
			name: "config overrides default (summary error)", rawValue: string(finding.DefaultFailThresholdFor("summary")), explicit: false, cmd: "summary",
			want: finding.FailThresholdError,
		},
		{
			name: "config overrides default (report warning)", rawValue: string(finding.DefaultFailThresholdFor("report")), explicit: false, cmd: "report",
			want: finding.FailThresholdWarning,
		},
		{
			name: "default applies when no config entry (dashboard)", rawValue: string(finding.DefaultFailThresholdFor("dashboard")), explicit: false, cmd: "dashboard",
			want: finding.FailThresholdNone,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stderr bytes.Buffer
			got, ok := resolveFailOn(c.rawValue, c.explicit, cfg, c.cmd, &stderr)
			if !ok {
				t.Fatalf("resolveFailOn unexpectedly failed: %s", stderr.String())
			}
			if got != c.want {
				t.Errorf("got = %q, want %q", got, c.want)
			}
		})
	}
}

// TestResolveFailOnRejectsBadConfigValue confirms a config failOn entry with an unknown threshold fails instead of falling back to a default.
//
// Parse validation is the primary gate and this is the defence in depth: the Config literal slips the legacy medium value past Parse.
// A failure means resolveFailOn accepted the value or its stderr message stopped naming the unknown threshold.
func TestResolveFailOnRejectsBadConfigValue(t *testing.T) {
	cfg := cfgpkg.Config{
		FailOn: cfgpkg.CommandThresholds{
			"analyse": "medium", // legacy 5-bucket name; post-ADR-009 invalid
		},
	}
	var stderr bytes.Buffer
	_, ok := resolveFailOn(string(finding.DefaultFailThresholdFor("analyse")), false, cfg, "analyse", &stderr)
	if ok {
		t.Fatal("resolveFailOn should have rejected legacy `medium` value")
	}
	if !contains(stderr.String(), `unknown threshold "medium"`) {
		t.Errorf("stderr = %q, want containing `unknown threshold \"medium\"`", stderr.String())
	}
}

// contains is a tiny local helper avoiding a strings import for one call.
// It reports whether needle occurs anywhere in haystack; an empty needle gives true and a needle longer than haystack gives false.
func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

// indexOf is the linear substring search used by contains.
// It returns the byte offset of the first occurrence of needle in haystack, or -1 when needle does not occur; an empty needle gives 0.
func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
