// Package cli precedence tests lock the ADR-010 minimumSeverity resolution
// ladder: explicit CLI flag > config minimumSeverity.<cmd> > binary default.
// resolveFailOn is the single helper every CLI consumer routes through; this
// file exercises it directly so the precedence semantics live in one place.
package cli

import (
	"bytes"
	"testing"

	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestResolveFailOnPrecedence covers the three precedence levels for all four
// command names. Cases combine: (a) explicit flag overrides config, (b) config
// overrides default when no flag, (c) default applies when neither flag nor
// config supply a value.
func TestResolveFailOnPrecedence(t *testing.T) {
	cfg := cfgpkg.Config{
		MinimumSeverity: map[string]string{
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

// TestResolveFailOnRejectsBadConfigValue confirms that a config entry with an
// invalid threshold value (which slipped past Parse validation, e.g. via a
// programmatic Config{} literal) surfaces an error rather than silently
// applying a default. Parse validation is the primary gate; this is the
// defence-in-depth gate.
func TestResolveFailOnRejectsBadConfigValue(t *testing.T) {
	cfg := cfgpkg.Config{
		MinimumSeverity: map[string]string{
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
func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

// indexOf is the linear substring search used by contains.
func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
