// Package finding tests cover the FailThreshold gate vocabulary, parser, and
// default helper. They guard the contract M02 wires into the CLI consumers
// and M03 wires into the dashboard.
package finding

import (
	"strings"
	"testing"
)

// TestParseFailThresholdAcceptsCanonicalValues asserts every canonical value
// round-trips. Locks the four-value vocabulary the wording brainstorm settled.
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

// TestParseFailThresholdRejectsLegacyAndJunk asserts no aliasing of legacy
// severity names or rejected off-switch names. Per no-legacy-compat: a user
// who copies an old "medium" config in must see an error, not a silent map.
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
		for _, want := range []string{"advisory", "warning", "error", "none"} {
			if !strings.Contains(msg, want) {
				t.Errorf("ParseFailThreshold(%q) error %q missing accepted value %q",
					input, msg, want)
			}
		}
	}
}

// TestFailThresholdIsTriggeredBy locks the four trigger semantics: None never,
// Advisory always (for any valid Severity), Warning at warning+, Error at
// error only. The 12-case matrix exhaustively covers every (threshold,
// severity) pair so any future Severity addition will fail noisily.
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

// TestFailThresholdIsTriggeredByRejectsInvalidSeverity asserts that an invalid
// Severity value never triggers regardless of threshold. Defensive against a
// future caller passing an empty or unknown Severity by mistake.
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

// TestDefaultFailThresholdFor locks the user-philosophy defaults:
// analyse/summary fail on any finding (gating commands), report/dashboard
// never fail (artifact generators). Unknown command names fall back to
// Advisory - the conservative gating choice.
func TestDefaultFailThresholdFor(t *testing.T) {
	cases := []struct {
		cmd  string
		want FailThreshold
	}{
		{"analyse", FailThresholdAdvisory},
		{"summary", FailThresholdAdvisory},
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

// TestFailThresholdValid asserts Valid is consistent with the parser. Catches
// drift between ParseFailThreshold's rejection set and Valid's acceptance set.
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
