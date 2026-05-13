// Package finding defines scanner finding payloads and quality enums.
package finding

import "fmt"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

func ParseSeverity(input string) (Severity, error) {
	severity := Severity(input)
	if !severity.Valid() {
		return "", fmt.Errorf("unknown severity %q", input)
	}
	return severity, nil
}

func (s Severity) Valid() bool {
	_, ok := severityRank[s]
	return ok
}

func (s Severity) AtLeast(threshold Severity) bool {
	return severityRank[s] >= severityRank[threshold]
}

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	default:
		return false
	}
}

type Pillar string

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

type Location struct {
	Line    int `json:"line,omitempty"`
	Column  int `json:"column,omitempty"`
	EndLine int `json:"endLine,omitempty"`
}
