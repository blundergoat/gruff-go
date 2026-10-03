// Package config resolves the two severity keys the family contract separates.
//
// Before 0.6.0 gruff-go had one key, minimumSeverity, and it set the exit gate. The family ratified the opposite
// meaning: minimumSeverity is the display floor and a new failOn key carries the gate. A configuration written against
// the old meaning is refused rather than reinterpreted, because silently turning a gate into a display filter would let
// a build that used to fail start passing without anyone changing a line.
package config

import (
	"encoding/json"
	"fmt"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// SeverityFloor is the lowest severity a report displays, read from the scalar minimumSeverity key.
type SeverityFloor struct {
	// Value is the configured severity, empty when the key is absent and every severity is shown.
	Value string
}

// UnmarshalJSON reads the scalar display floor and refuses the map form that used to mean the exit gate.
//
// The map form is the whole reason this type exists: it is valid YAML that used to gate a build, and reading it as a
// display floor would change what the file does without changing what it says.
func (floor *SeverityFloor) UnmarshalJSON(data []byte) error {
	var scalar string

	// A scalar is the family form: one floor for the whole report.
	if err := json.Unmarshal(data, &scalar); err == nil {
		floor.Value = scalar
		return nil
	}

	return fmt.Errorf("minimumSeverity is the display floor in 0.6.0 and takes one severity, not a per-command map; " +
		"move the per-command exit gate to failOn, which is the key that gates the exit code")
}

// MarshalJSON writes the scalar form, so a round-tripped configuration says what the loader will read.
func (floor SeverityFloor) MarshalJSON() ([]byte, error) {
	return json.Marshal(floor.Value)
}

// Severity returns the display floor as a severity, and false when no floor is configured.
func (floor SeverityFloor) Severity() (finding.Severity, bool) {
	// An absent key is not a floor of advisory; it means the report shows everything it found.
	if floor.Value == "" {
		return "", false
	}

	return finding.Severity(floor.Value), true
}

// CommandThresholds is the exit gate keyed by command, accepting a bare severity for every command.
type CommandThresholds map[string]string

// UnmarshalJSON accepts both the per-command map and the bare severity the family contract describes.
func (thresholds *CommandThresholds) UnmarshalJSON(data []byte) error {
	var scalar string

	// A bare severity is the family form; it gates every command that gates at all.
	if err := json.Unmarshal(data, &scalar); err == nil {
		resolved := CommandThresholds{}

		for command := range minimumSeverityCommands {
			resolved[command] = scalar
		}

		*thresholds = resolved
		return nil
	}

	keyed := map[string]string{}
	if err := json.Unmarshal(data, &keyed); err != nil {
		return fmt.Errorf("failOn takes one severity, or a map of command names to severities")
	}

	*thresholds = keyed
	return nil
}

// validateSeverityFloor refuses a display floor outside the ratified severity vocabulary.
func validateSeverityFloor(floor SeverityFloor) error {
	// An absent floor is the default, not an error: a report with no floor shows every finding it made.
	if floor.Value == "" {
		return nil
	}

	if !finding.Severity(floor.Value).Valid() {
		return fmt.Errorf("minimumSeverity %q is not a severity: want advisory, warning, or error", floor.Value)
	}

	return nil
}

// refuseRemovedPreviewKeys rejects a configuration that still carries the removed preview allowlist under either
// of its pre-0.6.0 spellings, allowlists.secretPreviews or sensitiveData.previewAllowlist.
//
// Section 5 makes every category marker unconditional and zero-payload, so the key gates nothing. Leaving it accepted
// would tell a reader their redaction is configured when it is not, which is worse than having no key at all.
func refuseRemovedPreviewKeys(data []byte) error {
	var sections map[string]json.RawMessage
	// Anything that is not an object is left for the strict decoder to describe; there is no key to refuse in it.
	if err := json.Unmarshal(data, &sections); err != nil {
		return nil
	}
	// Presence is the test, not content: an empty list reads as configured redaction just as a populated one does.
	if sectionHasKey(sections["allowlists"], "secretPreviews") || sectionHasKey(sections["sensitiveData"], "previewAllowlist") {
		return fmt.Errorf("allowlists.secretPreviews is removed in 0.6.0: FAMILY-CONTRACT.md section 5 makes category " +
			"markers unconditional, so the key authorises nothing; delete it from the configuration")
	}
	return nil
}

// sectionHasKey reports whether a raw config section is an object carrying the named key, whatever its value.
func sectionHasKey(section json.RawMessage, key string) bool {
	// A missing or non-object section cannot carry the key; the strict decoder reports its shape separately.
	if section == nil {
		return false
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(section, &entries); err != nil {
		return false
	}
	_, present := entries[key]
	return present
}
