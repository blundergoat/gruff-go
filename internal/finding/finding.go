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
	RuleID           string         `json:"ruleId"`
	Message          string         `json:"message"`
	File             string         `json:"file"`
	Location         *Location      `json:"location,omitempty"`
	Symbol           string         `json:"symbol,omitempty"`
	Severity         Severity       `json:"severity"`
	Confidence       Confidence     `json:"confidence"`
	Pillar           Pillar         `json:"pillar"`
	SecondaryPillars []Pillar       `json:"secondaryPillars,omitempty"`
	Remediation      string         `json:"remediation,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	Fingerprint      string         `json:"fingerprint"`
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
