// Package finding tests cover the FailThreshold gate behind --fail-on: its four-value vocabulary, its parser and the per-command defaults.
//
// The CLI commands and the dashboard read these gates; a failure means a run could gate on the wrong severity or accept an unlisted value.
package finding

import (
	"strings"
	"testing"
)

// TestParseFailThresholdAcceptsCanonicalValues checks that advisory, warning, error and none each parse to their FailThreshold constant.
// A failure means a documented --fail-on value is rejected or parsed as the wrong threshold.
func TestParseFailThresholdAcceptsCanonicalValues(t *testing.T) {
	cases := []struct {
		input string
		want  FailThreshold
	}{
		{"advisory", FailThresholdAdvisory},
		{"warning", FailThresholdWarning},
		{"error", FailThresholdError},
		{"none", FailThresholdNone},
	}
	for _, c := range cases {
		got, err := ParseFailThreshold(c.input)
		if err != nil {
			t.Errorf("ParseFailThreshold(%q) returned error: %v", c.input, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseFailThreshold(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// TestParseFailThresholdRejectsLegacyAndJunk checks that legacy severity names, rejected off-switch names, wrong casing and typos fail to parse.
// Per no-legacy-compat, a user who copies an old "medium" config in must see an error listing the four accepted values, not a silent map.
func TestParseFailThresholdRejectsLegacyAndJunk(t *testing.T) {
	rejected := []string{
		// Pre-ADR-009 severity names (5-bucket model).
		"medium", "low", "critical", "high", "info", "notice", "warn",
		// Rejected off-switch names from the wording brainstorm.
		"never", "off", "disabled",
		// Casing and typos.
		"", "Advisory", "ERROR", "noen",
		// Adjacent-looking but invalid.
		"failure", "ok",
	}
	for _, input := range rejected {
		_, err := ParseFailThreshold(input)
		if err == nil {
			t.Errorf("ParseFailThreshold(%q) should have returned an error", input)
			continue
		}
		msg := err.Error()
		// The error is what the user reads after a bad value, so it must name every value they can use instead.
		for _, want := range []string{"advisory", "warning", "error", "none"} {
			if !strings.Contains(msg, want) {
				t.Errorf("ParseFailThreshold(%q) error %q missing accepted value %q",
					input, msg, want)
			}
		}
	}
}

// TestFailThresholdIsTriggeredBy locks which finding severities trigger each --fail-on threshold.
//
// None never triggers, advisory triggers on every valid severity, warning on warning or error, and error on error only.
// The table covers every current pair; add rows for a new Severity, because the table cannot detect an omission.
func TestFailThresholdIsTriggeredBy(t *testing.T) {
	cases := []struct {
		threshold FailThreshold
		severity  Severity
		want      bool
	}{
		// None never triggers.
		{FailThresholdNone, SeverityAdvisory, false},
		{FailThresholdNone, SeverityWarning, false},
		{FailThresholdNone, SeverityError, false},
		// Advisory triggers on every valid Severity.
		{FailThresholdAdvisory, SeverityAdvisory, true},
		{FailThresholdAdvisory, SeverityWarning, true},
		{FailThresholdAdvisory, SeverityError, true},
		// Warning triggers on warning and error.
		{FailThresholdWarning, SeverityAdvisory, false},
		{FailThresholdWarning, SeverityWarning, true},
		{FailThresholdWarning, SeverityError, true},
		// Error triggers on error only.
		{FailThresholdError, SeverityAdvisory, false},
		{FailThresholdError, SeverityWarning, false},
		{FailThresholdError, SeverityError, true},
	}
	for _, c := range cases {
		got := c.threshold.IsTriggeredBy(c.severity)
		if got != c.want {
			t.Errorf("FailThreshold(%q).IsTriggeredBy(%q) = %v, want %v",
				c.threshold, c.severity, got, c.want)
		}
	}
}

// TestFailThresholdIsTriggeredByRejectsInvalidSeverity asserts that an invalid Severity, such as legacy "medium", never triggers a threshold.
// Defensive against a future caller passing an empty or unknown Severity by mistake.
func TestFailThresholdIsTriggeredByRejectsInvalidSeverity(t *testing.T) {
	invalid := Severity("medium") // legacy 5-bucket name, post-ADR-009 invalid
	for _, threshold := range []FailThreshold{
		FailThresholdAdvisory, FailThresholdWarning, FailThresholdError,
	} {
		if threshold.IsTriggeredBy(invalid) {
			t.Errorf("FailThreshold(%q).IsTriggeredBy(invalid Severity %q) = true, want false",
				threshold, invalid)
		}
	}
}

// TestDefaultFailThresholdFor locks the default fail threshold each command starts from.
//
// analyse defaults to advisory and fails on any finding; summary, report and dashboard default to none and never fail on findings.
// An unknown or empty command name falls back to advisory, the conservative gating choice.
func TestDefaultFailThresholdFor(t *testing.T) {
	cases := []struct {
		cmd  string
		want FailThreshold
	}{
		{"analyse", FailThresholdAdvisory},
		{"summary", FailThresholdNone},
		{"report", FailThresholdNone},
		{"dashboard", FailThresholdNone},
		// Unknown commands fall back to Advisory; empty also falls back.
		{"unknown", FailThresholdAdvisory},
		{"", FailThresholdAdvisory},
	}
	for _, c := range cases {
		got := DefaultFailThresholdFor(c.cmd)
		if got != c.want {
			t.Errorf("DefaultFailThresholdFor(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
}

// TestFailThresholdValid checks that Valid accepts the four canonical thresholds and rejects empty, legacy, off-switch and wrongly cased values.
func TestFailThresholdValid(t *testing.T) {
	valid := []FailThreshold{
		FailThresholdAdvisory, FailThresholdWarning,
		FailThresholdError, FailThresholdNone,
	}
	for _, v := range valid {
		if !v.Valid() {
			t.Errorf("FailThreshold(%q).Valid() = false, want true", v)
		}
	}
	for _, v := range []FailThreshold{"", "medium", "never", "ERROR"} {
		if v.Valid() {
			t.Errorf("FailThreshold(%q).Valid() = true, want false", v)
		}
	}
}
