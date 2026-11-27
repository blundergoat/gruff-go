// Package finding's FailThreshold vocabulary is the severity gate that decides whether findings make a gruff-go run exit 1.
//
// FailThreshold is the gate "fail the run when a finding at or above tier X fires"; Severity is the per-finding urgency tag.
// They share the Severity names advisory, warning and error; none, the extra value, turns the severity gate off but leaves reporting on.
package finding

import "fmt"

// FailThreshold is the exit-gate vocabulary for "fail the run on findings at or above this Severity".
//
// It is separate from Severity because it carries one value Severity cannot: None, which turns off the severity gate but not reporting.
// Mirrors gruff-rs's FailThreshold enum (see ADR-010).
//
// Keeping the types distinct also stops a meaningless "Severity: None" tag from being attached to a finding.
// Findings always carry a real Severity; only the process gate has an opt-out.
type FailThreshold string

// FailThreshold value constants, the four values ParseFailThreshold accepts.
//
// Names match the Severity constants by string value, so a FailThreshold above None can be compared with a Severity through severityRank.
const (
	FailThresholdAdvisory FailThreshold = "advisory"
	FailThresholdWarning  FailThreshold = "warning"
	FailThresholdError    FailThreshold = "error"
	FailThresholdNone     FailThreshold = "none"
)

// ParseFailThreshold converts a raw string into a known FailThreshold value.
//
// Pre-ADR-009 severity names (medium, low, critical, high, info, notice, warn) are rejected per the no-legacy-compat policy.
// Off-switch names never, off and disabled are rejected for the same reason; none is the accepted way to turn the gate off.
//
// The input string must equal advisory, warning, error or none exactly; no trimming or case folding is applied, so an empty input is rejected too.
// It returns the matching FailThreshold and a nil error for a valid input; for any other input the error is returned with the empty FailThreshold.
// The error message lists the four accepted values, so a user who typed an old name such as warn sees the choices without reading source.
func ParseFailThreshold(input string) (FailThreshold, error) {
	threshold := FailThreshold(input)
	if !threshold.Valid() {
		return "", fmt.Errorf("unknown threshold %q: want one of advisory, warning, error, none", input)
	}
	return threshold, nil
}

// Valid reports whether the FailThreshold matches a known value: advisory, warning, error or none.
// It reports false for anything else, including the empty FailThreshold; ParseFailThreshold rejects every input that fails this check.
func (t FailThreshold) Valid() bool {
	switch t {
	case FailThresholdAdvisory, FailThresholdWarning, FailThresholdError, FailThresholdNone:
		return true
	default:
		return false
	}
}

// IsTriggeredBy reports whether a finding at Severity s should make the run exit 1 under this threshold.
//
// Mirrors gruff-rs's is_triggered_by_severity: None always gives false because the gate is off, and Advisory gives true for any valid Severity.
// Warning and Error compare through Severity.AtLeast so the severityRank ordering stays in one place.
//
// It reports false when s is not a valid Severity or the threshold is not one of the four known values.
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

// DefaultFailThresholdFor returns the canonical out-of-the-box FailThreshold for a CLI command.
//
// Both the analysis runner fallback (empty Options.FailOn) and the dashboard state default consume this single source.
// Keeping defaults together prevents the drift described in .goat-flow/learning-loop/footguns/severity.md.
//
// The cmd value is compared exactly, without case folding: analyse gives Advisory and summary, report and dashboard give None.
// Any other cmd, including an empty string or a differently cased name such as Analyse, gives Advisory.
// That fallback is the conservative fail-on-anything choice, not an error, and nothing is logged; a caller that wants a warning checks cmd first.
func DefaultFailThresholdFor(cmd string) FailThreshold {
	switch cmd {
	case "analyse":
		return FailThresholdAdvisory
	// summary is the first command a new user runs, and the family CLI contract reserves exit 1 for a gate somebody asked for.
	// Findings alone therefore do not make it exit 1 until --fail-on or failOn.summary says otherwise.
	case "summary", "report", "dashboard":
		return FailThresholdNone
	default:
		return FailThresholdAdvisory
	}
}
