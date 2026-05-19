// Package finding defines scanner finding payloads and quality enums.
// It owns the Severity, Confidence, and Pillar vocabularies plus location data.
package finding

import "fmt"

// Severity is the ordered urgency tier attached to a finding.
type Severity string

// Severity tier constants ordered from informational to critical.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityRank maps each Severity to its numeric comparison order.
var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// ParseSeverity converts a raw string into a known Severity value.
func ParseSeverity(input string) (Severity, error) {
	severity := Severity(input)
	if !severity.Valid() {
		return "", fmt.Errorf("unknown severity %q", input)
	}
	return severity, nil
}

// Valid reports whether the Severity matches a known tier.
func (s Severity) Valid() bool {
	_, ok := severityRank[s]
	return ok
}

// AtLeast reports whether the Severity is greater than or equal to threshold.
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
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	default:
		return false
	}
}

// Pillar names the broad quality category a finding belongs to.
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
type Location struct {
	// Line is the 1-based start line within the source file; zero when unknown.
	Line int `json:"line,omitempty"`
	// Column is the 1-based start column within Line; zero when unknown.
	Column int `json:"column,omitempty"`
	// EndLine is the inclusive 1-based end line of the span; zero or less than Line means single-line.
	EndLine int `json:"endLine,omitempty"`
}
