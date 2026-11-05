// Package finding defines the Finding payload and fingerprint helpers.
//
// Findings carry rule output, location, severity, and identity hash data.
// A Finding that the report keeps becomes a line in the analyse text report or, through MarshalJSON, a JSON object.
// Fingerprint is line-sensitive, while StableIdentity leaves the line out so external diff tooling can follow a finding that moved.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// DefaultTier is the current rule maturity tier emitted for findings.
// WithFingerprint and MarshalJSON fall back to it when Tier is empty, so the JSON tier field always carries a value.
const DefaultTier = "v0.1"

// Finding is a single rule result emitted by the analyser pipeline.
//
// The analyse text report prints each Finding it shows as one line: severity, file, line when known, rule ID and message.
// MarshalJSON turns it into the v3 JSON object, leaving out SymbolOrdinal, BaselineStatus and DeclarationPosition.
type Finding struct {
	// RuleID is the identifier of the rule that produced the finding.
	RuleID string `json:"ruleId"`
	// Message is the human-readable description of what the rule detected.
	Message string `json:"message"`
	// File is the repo-relative path of the source file the finding targets.
	File string `json:"file"`
	// Location pins the finding to a span within File, even for some whole-file results; nil means no span, and JSON then reports line 1.
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
	// Fingerprint is the line-sensitive identity hash from ComputeFingerprint, written into every finding's JSON object.
	Fingerprint string `json:"fingerprint"`
	// StableIdentity is the line-insensitive identity used by external diff tooling.
	StableIdentity string `json:"stableIdentity,omitempty"`
	// SymbolOrdinal is the 1-based rank of this finding's declaration among same-named symbols in File, assigned after analysis.
	//
	// It separates two functions of one name for the baseline identity, which carries the ordinal.
	// MarshalJSON leaves it out of the frozen v3 finding shape.
	SymbolOrdinal int `json:"-"`
	// BaselineStatus is what an applied baseline made of this finding: "new", "collision" or "notEligible".
	// It is empty when no baseline ran, and it never reaches the JSON envelope.
	BaselineStatus string `json:"-"`
	// DeclarationPosition is the line the ordinal was derived from. Two findings
	// sharing an identity but not a position are a collision the baseline reports.
	DeclarationPosition int `json:"-"`
}

// WithFingerprint returns a copy of the finding with identity fields populated, leaving the receiver unchanged.
// Fingerprint and StableIdentity are recomputed from the current fields, replacing any old values, and an empty Tier becomes DefaultTier.
func (f Finding) WithFingerprint() Finding {
	f.Fingerprint = f.ComputeFingerprint()
	f.StableIdentity = f.ComputeStableIdentity()
	if f.Tier == "" {
		f.Tier = DefaultTier
	}
	return f
}

// ComputeFingerprint hashes the finding identity fields into a stable short ID.
//
// It returns the first 16 hex characters of a SHA-256 over the JSON of RuleID, File, the Location line, column and end line, Symbol and Message.
// A nil Location hashes as line, column and end line 0; the result is never empty, and moving a finding to another line changes it.
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
	// json.Marshal cannot fail on this struct of strings and ints, so no finding data can reach this panic.
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])[:16]
}

// ComputeStableIdentity hashes line-insensitive finding fields for external diff tooling.
//
// It returns the first 16 hex characters of a SHA-256 over RuleID, File and Symbol, or Message when Symbol is empty, separated by zero bytes.
// Location is not hashed, so the result survives a line move and is never empty.
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

// MarshalJSON emits the canonical v3 finding shape.
//
// Unknown optional spans are omitted; a nil Location or a start line of 0 or less uses line 1 as the JSON anchor.
// It returns the encoded object; secondaryPillars and metadata are always present, and an unset tier or stableIdentity is filled in.
// It fails with the json.Marshal error and nil bytes when any field cannot be encoded, such as a channel or NaN float in Metadata.
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

// canonicalLine returns the scanner line when known and line 1 for a file-level finding, whose subject is the whole file rather than a span.
// location is the finding's span; a nil location or a line of 0 or less gives 1.
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
//
// location is the finding's span and value picks one field from it, such as EndLine or Column.
// It returns a pointer to a copy of that field, or nil when location is nil or the field is 0 or less.
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
// value is the optional field text; a non-empty value gives a pointer to its own copy.
func nonEmptyString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// nonNilPillars serializes absent secondary pillars as an empty canonical list.
//
// values is the finding's SecondaryPillars list.
// It returns values unchanged, or an empty non-nil slice when values is nil, so the JSON shows an empty list rather than null.
func nonNilPillars(values []Pillar) []Pillar {
	if values == nil {
		return []Pillar{}
	}
	return values
}

// canonicalMetadata copies the finding metadata and adds locationPrecision, so absent metadata still serializes as an object.
//
// values is the finding's Metadata, copied so the caller's map is untouched; a locationPrecision key in it is replaced in the copy.
// It returns the copy with locationPrecision scanner-pinpointed when location has a positive Column and line-only otherwise, so it is never empty.
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
