// Package finding defines the Finding payload and fingerprint helpers.
// Findings carry rule output, location, severity, and identity hash data.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// DefaultTier is the current rule maturity tier emitted for findings.
const DefaultTier = "v0.1"

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
	// Tier is the rule catalogue maturity tier that owns the finding.
	Tier string `json:"tier,omitempty"`
	// Remediation is a short suggested fix or pointer to remediation guidance.
	Remediation string `json:"remediation,omitempty"`
	// Metadata carries rule-specific structured data (thresholds, measured values, etc.).
	Metadata map[string]any `json:"metadata,omitempty"`
	// Fingerprint is the stable identity hash used by baseline matching.
	Fingerprint string `json:"fingerprint"`
	// StableIdentity is the line-insensitive identity used by external diff tooling.
	StableIdentity string `json:"stableIdentity,omitempty"`
	// SymbolOrdinal is the 1-based rank of this finding's declaration among
	// same-named symbols in File, assigned after analysis. It separates two
	// functions of one name for the baseline identity and is never serialised:
	// the v3 finding shape is frozen and the ordinal lives inside the identity.
	SymbolOrdinal int `json:"-"`
	// BaselineStatus is what an applied baseline made of this finding: "new", "collision" or "notEligible".
	// It is empty when no baseline ran, and it never reaches the JSON envelope.
	BaselineStatus string `json:"-"`
	// DeclarationPosition is the line the ordinal was derived from. Two findings
	// sharing an identity but not a position are a collision the baseline reports.
	DeclarationPosition int `json:"-"`
}

// WithFingerprint returns a copy of the finding with identity fields populated.
func (f Finding) WithFingerprint() Finding {
	f.Fingerprint = f.ComputeFingerprint()
	f.StableIdentity = f.ComputeStableIdentity()
	if f.Tier == "" {
		f.Tier = DefaultTier
	}
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

// ComputeStableIdentity hashes line-insensitive finding fields for external diff tooling.
func (f Finding) ComputeStableIdentity() string {
	symbolOrMessage := f.Symbol
	if symbolOrMessage == "" {
		symbolOrMessage = f.Message
	}
	hasher := sha256.New()
	hasher.Write([]byte(f.RuleID))
	hasher.Write([]byte{0})
	hasher.Write([]byte(f.File))
	hasher.Write([]byte{0})
	hasher.Write([]byte(symbolOrMessage))
	return hex.EncodeToString(hasher.Sum(nil))[:16]
}

// MarshalJSON emits the canonical v3 finding shape. Unknown optional spans are
// omitted, while file-level findings use line 1 as their stable file anchor.
func (f Finding) MarshalJSON() ([]byte, error) {
	payload := struct {
		RuleID           string         `json:"ruleId"`
		Message          string         `json:"message"`
		File             string         `json:"file"`
		Line             int            `json:"line"`
		EndLine          *int           `json:"endLine,omitempty"`
		Column           *int           `json:"column,omitempty"`
		Symbol           *string        `json:"symbol,omitempty"`
		Severity         Severity       `json:"severity"`
		Pillar           Pillar         `json:"pillar"`
		SecondaryPillars []Pillar       `json:"secondaryPillars"`
		Tier             string         `json:"tier"`
		Confidence       Confidence     `json:"confidence"`
		Remediation      string         `json:"remediation"`
		Fingerprint      string         `json:"fingerprint"`
		StableIdentity   string         `json:"stableIdentity"`
		Metadata         map[string]any `json:"metadata"`
	}{
		RuleID:           f.RuleID,
		Message:          f.Message,
		File:             f.File,
		Line:             canonicalLine(f.Location),
		EndLine:          locationInt(f.Location, func(location Location) int { return location.EndLine }),
		Column:           locationInt(f.Location, func(location Location) int { return location.Column }),
		Symbol:           nonEmptyString(f.Symbol),
		Severity:         f.Severity,
		Pillar:           f.Pillar,
		SecondaryPillars: nonNilPillars(f.SecondaryPillars),
		Tier:             f.resolvedTier(),
		Confidence:       f.Confidence,
		Remediation:      f.Remediation,
		Fingerprint:      f.Fingerprint,
		StableIdentity:   f.resolvedStableIdentity(),
		Metadata:         canonicalMetadata(f.Metadata, f.Location),
	}
	return json.Marshal(payload)
}

// canonicalLine returns the scanner line when known and the first line for a
// file-level finding, whose subject is the file rather than a source span.
func canonicalLine(location *Location) int {
	if location == nil || location.Line <= 0 {
		return 1
	}
	return location.Line
}

// resolvedTier returns the finding tier, defaulting old in-memory findings to v0.1.
func (f Finding) resolvedTier() string {
	if f.Tier != "" {
		return f.Tier
	}
	return DefaultTier
}

// resolvedStableIdentity returns the finding's stable identity, computing it for old fixtures.
func (f Finding) resolvedStableIdentity() string {
	if f.StableIdentity != "" {
		return f.StableIdentity
	}
	return f.ComputeStableIdentity()
}

// locationInt extracts a positive location field or nil for unknown values.
func locationInt(location *Location, value func(Location) int) *int {
	if location == nil {
		return nil
	}
	out := value(*location)
	if out <= 0 {
		return nil
	}
	return &out
}

// nonEmptyString returns nil for absent optional finding strings.
func nonEmptyString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// nonNilPillars serializes absent secondary pillars as an empty canonical list.
func nonNilPillars(values []Pillar) []Pillar {
	if values == nil {
		return []Pillar{}
	}
	return values
}

// nonNilMetadata serializes absent metadata as an empty canonical object.
func canonicalMetadata(values map[string]any, location *Location) map[string]any {
	out := make(map[string]any, len(values)+1)
	for key, value := range values {
		out[key] = value
	}
	out["locationPrecision"] = "line-only"
	if location != nil && location.Column > 0 {
		out["locationPrecision"] = "scanner-pinpointed"
	}
	return out
}
