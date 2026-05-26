// Package finding's FailThreshold vocabulary controls process exit codes.
// FailThreshold is the gate "fail the run when a finding at or above tier X
// fires"; Severity is the per-finding urgency tag. They share the three
// shipping Severity names (advisory/warning/error) plus one extra value None
// that disables the gate without disabling the report.
package finding

import "fmt"

// FailThreshold is the exit-gate vocabulary for "fail the run on findings at
// or above this Severity". It is a separate type from Severity because it
// carries one value Severity cannot - None - meaning "report findings, never
// exit 1". Mirrors gruff-rs's FailThreshold enum (see ADR-010). Keeping the
// types distinct also prevents a meaningless "Severity: None" tag from being
// attached to a finding - findings always carry a real Severity; only the
// process gate has an opt-out.
type FailThreshold string

// FailThreshold value constants. Names match the corresponding Severity
// constants by string value so a FailThreshold above None can be compared
// against a Severity via the existing severityRank ordering.
const (
	FailThresholdAdvisory FailThreshold = "advisory"
	FailThresholdWarning  FailThreshold = "warning"
	FailThresholdError    FailThreshold = "error"
	FailThresholdNone     FailThreshold = "none"
)

// ParseFailThreshold converts a raw string into a known FailThreshold value.
// Accepts only the four canonical values; rejects pre-ADR-009 severity names
// (medium / low / critical / high / info / notice / warn) and rejected
// off-switch names (never / off / disabled) per the no-legacy-compat policy.
// The error message lists the accepted values verbatim so users see them
// without having to read source.
func ParseFailThreshold(input string) (FailThreshold, error) {
	threshold := FailThreshold(input)
	if !threshold.Valid() {
		return "", fmt.Errorf("unknown threshold %q: want one of advisory, warning, error, none", input)
	}
	return threshold, nil
}

// Valid reports whether the FailThreshold matches a known value.
func (t FailThreshold) Valid() bool {
	switch t {
	case FailThresholdAdvisory, FailThresholdWarning, FailThresholdError, FailThresholdNone:
		return true
	default:
		return false
	}
}

// IsTriggeredBy reports whether a finding at the given Severity should cause
// exit code 1 under this threshold. None always returns false (the gate is
// disabled); Advisory always returns true for any valid Severity; Warning and
// Error compare against severityRank via Severity.AtLeast so the ordering
// stays in one place. Mirrors gruff-rs's is_triggered_by_severity semantics.
func (t FailThreshold) IsTriggeredBy(s Severity) bool {
	switch t {
	case FailThresholdNone:
		return false
	case FailThresholdAdvisory:
		return s.Valid()
	case FailThresholdWarning:
		return s.Valid() && s.AtLeast(SeverityWarning)
	case FailThresholdError:
		return s.Valid() && s.AtLeast(SeverityError)
	default:
		return false
	}
}

// DefaultFailThresholdFor returns the canonical out-of-the-box FailThreshold
// for a CLI command. Both the analysis runner fallback (empty Options.FailOn)
// and the dashboard state default consume this single source - keeping the
// defaults in one map closes the dashboard-vs-CLI drift footgun in
// .goat-flow/footguns/severity.md by construction.
//
// Unknown command names fall back to Advisory rather than erroring - callers
// shouldn't treat an unrecognised command as a fatal validation failure, and
// "fail on anything" is the conservative choice when intent is unclear. The
// helper deliberately does no logging; callers that want to surface "unknown
// command" as a user-visible warning should validate the command name at
// their own boundary.
func DefaultFailThresholdFor(cmd string) FailThreshold {
	switch cmd {
	case "analyse", "summary":
		return FailThresholdAdvisory
	case "report", "dashboard":
		return FailThresholdNone
	default:
		return FailThresholdAdvisory
	}
}
