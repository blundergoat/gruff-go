// Package config resolves the two severity keys the family contract separates.
//
// Before 0.6.0 gruff-go had one key, minimumSeverity, and it set the exit gate.
// The family ratified the opposite meaning: minimumSeverity is the display floor and a new failOn key carries the gate.
//
// The per-command map form of minimumSeverity is refused rather than reinterpreted as a display floor.
// Silently turning a gate into a display filter would let a build that used to fail start passing without anyone changing a line.
package config

import (
	"encoding/json"
	"fmt"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// SeverityFloor is the lowest severity a report displays, read from the scalar minimumSeverity key.
//
// Reading the key does not check the value; validateSeverityFloor is what refuses a value that is not a severity.
type SeverityFloor struct {
	// Value is the configured severity, empty when the key is absent and every severity is shown.
	Value string
}

// UnmarshalJSON reads the scalar display floor and refuses the map form that used to mean the exit gate.
//
// The map form is the whole reason this type exists: it is valid YAML that used to gate a build.
// Reading it as a display floor would change what the file does without changing what it says.
//
// The data argument is the raw minimumSeverity JSON; a value that decodes as a string is stored in Value without a severity check.
// JSON null decodes as the empty string, so it sets Value to empty, the same as an absent key.
// Any shape other than a string or null, such as a per-command map, returns an error that points the reader to failOn for the exit gate.
func (floor *SeverityFloor) UnmarshalJSON(data []byte) error {
	var scalar string

	// A scalar is the family form: one floor for the whole report.
	if err := json.Unmarshal(data, &scalar); err == nil {
		floor.Value = scalar
		return nil
	}

	// A minimumSeverity map, number or list is refused here with an error telling the user to move the exit gate to failOn.
	return fmt.Errorf("minimumSeverity is the display floor in 0.6.0 and takes one severity, not a per-command map; " +
		"move the per-command exit gate to failOn, which is the key that gates the exit code")
}

// MarshalJSON writes the scalar form, so a round-tripped configuration says what the loader will read.
//
// It returns Value encoded as a JSON string, which is the empty JSON string when no floor is configured.
// The error result is always nil, because json.Marshal does not fail on a string.
func (floor SeverityFloor) MarshalJSON() ([]byte, error) {
	return json.Marshal(floor.Value)
}

// Severity returns the display floor as a severity, and false when no floor is configured.
func (floor SeverityFloor) Severity() (finding.Severity, bool) {
	// An absent key is not a floor of advisory; with no floor, no finding is hidden because of its severity.
	if floor.Value == "" {
		return "", false
	}

	return finding.Severity(floor.Value), true
}

// CommandThresholds is the exit gate read from failOn, keyed by command, accepting a bare severity for every command.
//
// A bare severity is copied to each command in minimumSeverityCommands; no value is checked against the severity vocabulary on read.
type CommandThresholds map[string]string

// UnmarshalJSON accepts both the per-command map and the bare severity the family contract describes.
//
// The data argument is the raw failOn JSON; a bare string replaces the map with that severity for every command in minimumSeverityCommands.
// JSON null counts as a bare empty string, so each of those commands gets an empty threshold.
// An object of command names to strings replaces the map as given, with a null value read as an empty string.
//
// None of these values is checked against the severity vocabulary here, so the empty thresholds from null are accepted at this point.
// Any other shape returns an error saying what failOn accepts and leaves thresholds unchanged; object values may be strings or null.
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

	byCommand := map[string]string{}
	// A failOn number or list, or a map value that is neither a string nor null, is refused here, leaving the configured thresholds unchanged.
	if err := json.Unmarshal(data, &byCommand); err != nil {
		return fmt.Errorf("failOn takes one severity, or a map of command names to severities")
	}

	*thresholds = byCommand
	return nil
}

// validateSeverityFloor refuses a display floor outside the ratified severity vocabulary.
// It returns nil when floor.Value is empty or a valid severity, and otherwise an error that quotes the value and lists the accepted severities.
func validateSeverityFloor(floor SeverityFloor) error {
	// An absent floor is the default, not an error: with no floor, no finding is hidden because of its severity.
	if floor.Value == "" {
		return nil
	}

	// A misspelt severity in minimumSeverity lands here, and the error lists the accepted values.
	if !finding.Severity(floor.Value).Valid() {
		return fmt.Errorf("minimumSeverity %q is not a severity: want advisory, warning, or error", floor.Value)
	}

	return nil
}

// refuseRemovedPreviewKeys rejects a configuration that still carries the removed preview allowlist under either pre-0.6.0 spelling.
//
// The two spellings are allowlists.secretPreviews and sensitiveData.previewAllowlist.
// FAMILY-CONTRACT.md section 5 makes markers unconditional and zero-payload, so accepting either key would falsely imply configurable redaction.
//
// The data argument is the configuration document as JSON; data that is not an object yields nil, leaving its shape to the strict decoder.
// It returns an error when allowlists carries secretPreviews or sensitiveData carries previewAllowlist, whatever its value, and nil otherwise.
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
// It reports false when section is missing or is not an object, and when the object lacks key.
func sectionHasKey(section json.RawMessage, key string) bool {
	// An omitted section cannot carry the removed key, so this check passes it.
	if section == nil {
		return false
	}
	var entries map[string]json.RawMessage
	// A section that is not an object is left for the strict decoder to report.
	if err := json.Unmarshal(section, &entries); err != nil {
		return false
	}
	_, present := entries[key]
	return present
}
