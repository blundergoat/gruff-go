// Package finding defines scanner finding payloads and quality enums.
//
// It owns the Severity, Confidence, and Pillar vocabularies plus location data.
// The Severity and Pillar strings appear verbatim in reports, such as the HTML report's filter options, so renaming one changes output.
package finding

import "fmt"

// Severity is the ordered urgency tier attached to a finding.
//
// The 3-bucket vocabulary matches the sibling gruff-rs, gruff-ts, gruff-py and gruff-php ports, as ADR-009 sets out.
// ParseSeverity rejects any other tier name, so a 5-bucket name is an error rather than a silent remap.
type Severity string

// Severity tier constants ordered from informational to error.
//
// These lowercase strings are the only spellings ParseSeverity accepts, and AtLeast ranks them in this same order.
const (
	SeverityAdvisory Severity = "advisory"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
)

// severityRank maps each Severity to its numeric comparison order.
// Its keys are the tiers Valid accepts, and a lookup of any other value yields 0, the same rank as advisory.
var severityRank = map[Severity]int{
	SeverityAdvisory: 0,
	SeverityWarning:  1,
	SeverityError:    2,
}

// ParseSeverity converts a raw string into a known Severity value.
//
// It returns input converted to a Severity when it equals advisory, warning or error exactly, with no case folding or trimming.
// Any other input, including the empty string, returns the empty Severity and an error that quotes the input.
func ParseSeverity(input string) (Severity, error) {
	severity := Severity(input)
	if !severity.Valid() {
		return "", fmt.Errorf("unknown severity %q", input)
	}
	return severity, nil
}

// Valid reports whether the Severity matches a known tier.
// It is false for the empty Severity and for anything other than advisory, warning or error, including Warning with a capital letter.
func (s Severity) Valid() bool {
	_, ok := severityRank[s]
	return ok
}

// AtLeast reports whether the Severity is greater than or equal to threshold.
// Unknown values rank as advisory, so an unknown severity passes an advisory or unknown threshold, and any severity passes an unknown one.
func (s Severity) AtLeast(threshold Severity) bool {
	return severityRank[s] >= severityRank[threshold]
}

// Confidence captures how certain a rule is about the finding it emitted.
type Confidence string

// Confidence tier constants in ascending order of certainty.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Valid reports whether the Confidence matches a known tier.
// It is false for the empty Confidence and for anything other than low, medium or high.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	default:
		return false
	}
}

// Pillar names the broad quality category a finding belongs to.
//
// The HTML report offers each pillar present in its findings as a filter option, spelled exactly as the constant's string.
type Pillar string

// Pillar constants covering every quality category gruff-go reports against.
const (
	PillarSize          Pillar = "size"
	PillarComplexity    Pillar = "complexity"
	PillarDocumentation Pillar = "documentation"
	PillarSensitiveData Pillar = "sensitive-data"
	PillarSecurity      Pillar = "security"
	PillarTestQuality   Pillar = "test-quality"
	PillarNaming        Pillar = "naming"
	PillarMaintain      Pillar = "maintainability"
	PillarDesign        Pillar = "design"
	PillarDeadCode      Pillar = "dead-code"
	PillarModernisation Pillar = "modernisation"
)

// Valid reports whether the Pillar matches a known quality category.
// It is false for the empty Pillar and for any string not among the Pillar constants, such as maintain instead of maintainability.
func (p Pillar) Valid() bool {
	switch p {
	case PillarSize, PillarComplexity, PillarDocumentation, PillarSensitiveData,
		PillarSecurity, PillarTestQuality, PillarNaming, PillarMaintain,
		PillarDesign, PillarDeadCode, PillarModernisation:
		return true
	default:
		return false
	}
}

// Location pins a finding to a span of source lines and columns.
//
// Zero fields are left out when a Location is encoded as JSON, so an unknown line shows as a missing line key rather than 0.
type Location struct {
	// Line is the 1-based start line within the source file; zero when unknown.
	Line int `json:"line,omitempty"`
	// Column is the 1-based start column within Line; zero when unknown.
	Column int `json:"column,omitempty"`
	// EndLine is the inclusive 1-based end line of the span; zero or less than Line means single-line.
	EndLine int `json:"endLine,omitempty"`
}
