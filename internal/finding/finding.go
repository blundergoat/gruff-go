// Package finding defines the Finding payload and fingerprint helpers.
// Findings carry rule output, location, severity, and identity hash data.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Finding is a single rule result emitted by the analyser pipeline.
type Finding struct {
	// RuleID is the identifier of the rule that produced the finding.
	RuleID string `json:"ruleId"`
	// Message is the human-readable description of what the rule detected.
	Message string `json:"message"`
	// File is the repo-relative path of the source file the finding targets.
	File string `json:"file"`
	// Location pins the finding to a span within File; nil when the rule reports the file as a whole.
	Location *Location `json:"location,omitempty"`
	// Symbol is the optional named subject (function, type, identifier) the finding is anchored to.
	Symbol string `json:"symbol,omitempty"`
	// Severity is the urgency tier reported for the finding.
	Severity Severity `json:"severity"`
	// Confidence is the rule's certainty in the finding.
	Confidence Confidence `json:"confidence"`
	// Pillar is the primary quality category the finding belongs to.
	Pillar Pillar `json:"pillar"`
	// SecondaryPillars lists additional quality categories the finding touches.
	SecondaryPillars []Pillar `json:"secondaryPillars,omitempty"`
	// Remediation is a short suggested fix or pointer to remediation guidance.
	Remediation string `json:"remediation,omitempty"`
	// Metadata carries rule-specific structured data (thresholds, measured values, etc.).
	Metadata map[string]any `json:"metadata,omitempty"`
	// Fingerprint is the stable identity hash used by baseline matching.
	Fingerprint string `json:"fingerprint"`
}

// WithFingerprint returns a copy of the finding with Fingerprint populated.
func (f Finding) WithFingerprint() Finding {
	f.Fingerprint = f.ComputeFingerprint()
	return f
}

// ComputeFingerprint hashes the finding identity fields into a stable short ID.
func (f Finding) ComputeFingerprint() string {
	line, column, endLine := 0, 0, 0
	if f.Location != nil {
		line = f.Location.Line
		column = f.Location.Column
		endLine = f.Location.EndLine
	}
	identity := struct {
		RuleID  string `json:"ruleId"`
		File    string `json:"file"`
		Line    int    `json:"line"`
		Column  int    `json:"column"`
		EndLine int    `json:"endLine"`
		Symbol  string `json:"symbol"`
		Message string `json:"message"`
	}{
		RuleID:  f.RuleID,
		File:    f.File,
		Line:    line,
		Column:  column,
		EndLine: endLine,
		Symbol:  f.Symbol,
		Message: f.Message,
	}
	payload, err := json.Marshal(identity)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])[:16]
}
