// Package finding tests assert fingerprint stability and identity coverage.
// They guard the JSON payload shape and hash contract used by baselines.
package finding

import (
	"encoding/json"
	"testing"
)

// TestFingerprintIsStableAndIdentityBased asserts identity-only fields drive the hash.
func TestFingerprintIsStableAndIdentityBased(t *testing.T) {
	finding := Finding{
		RuleID:     "size.file-length",
		Message:    "file is too long",
		File:       "internal/foo/foo.go",
		Location:   &Location{Line: 10, Column: 1},
		Symbol:     "Foo",
		Severity:   SeverityWarning,
		Confidence: ConfidenceHigh,
		Pillar:     PillarSize,
	}

	first := finding.ComputeFingerprint()
	second := finding.WithFingerprint().Fingerprint
	if first != second {
		t.Fatalf("fingerprint changed: %q != %q", first, second)
	}

	changed := finding
	changed.Location = &Location{Line: 11, Column: 1}
	if first == changed.ComputeFingerprint() {
		t.Fatal("fingerprint did not change when finding identity changed")
	}
}

// TestStableIdentityIsLineInsensitive asserts the diff identity survives line shifts.
func TestStableIdentityIsLineInsensitive(t *testing.T) {
	base := Finding{
		RuleID:     "docs.missing-public-doc",
		Message:    "exported function should have a doc comment",
		File:       "internal/foo/foo.go",
		Location:   &Location{Line: 10, Column: 1},
		Symbol:     "Run",
		Severity:   SeverityWarning,
		Confidence: ConfidenceHigh,
		Pillar:     PillarDocumentation,
	}.WithFingerprint()
	shifted := base
	shifted.Location = &Location{Line: 42, Column: 1}
	shifted = shifted.WithFingerprint()

	if base.Fingerprint == shifted.Fingerprint {
		t.Fatalf("fingerprint stayed line-insensitive: %q", base.Fingerprint)
	}
	if base.StableIdentity != shifted.StableIdentity {
		t.Fatalf("stable identity changed across line shift: %q != %q", base.StableIdentity, shifted.StableIdentity)
	}
	if len(base.StableIdentity) != 16 {
		t.Fatalf("stable identity len = %d, want 16", len(base.StableIdentity))
	}

	withoutSymbol := base
	withoutSymbol.Symbol = ""
	withoutSymbol.StableIdentity = ""
	changedMessage := withoutSymbol
	changedMessage.Message = "different message"
	if withoutSymbol.ComputeStableIdentity() == changedMessage.ComputeStableIdentity() {
		t.Fatal("stable identity did not distinguish messages when symbol is absent")
	}
}

// TestFindingJSONShape asserts findings emit the canonical flat shape plus legacy location.
func TestFindingJSONShape(t *testing.T) {
	item := Finding{
		RuleID:     "complexity.cyclomatic",
		Message:    "function cyclomatic complexity is 23, above threshold 20",
		File:       "internal/foo/bar.go",
		Location:   &Location{Line: 42, Column: 3, EndLine: 78},
		Symbol:     "DoTheThing",
		Severity:   SeverityWarning,
		Confidence: ConfidenceHigh,
		Pillar:     PillarComplexity,
	}.WithFingerprint()

	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode finding: %v\n%s", err, data)
	}

	if payload["file"] != item.File || payload["line"] != float64(42) || payload["endLine"] != float64(78) || payload["column"] != float64(3) {
		t.Fatalf("flat location fields = %#v", payload)
	}
	location, ok := payload["location"].(map[string]any)
	if !ok || location["line"] != float64(42) || location["endLine"] != float64(78) || location["column"] != float64(3) {
		t.Fatalf("legacy location = %#v", payload["location"])
	}
	if payload["tier"] != DefaultTier || payload["stableIdentity"] != item.StableIdentity || payload["fingerprint"] != item.Fingerprint {
		t.Fatalf("identity fields = %#v", payload)
	}
	secondary, ok := payload["secondaryPillars"].([]any)
	if !ok || len(secondary) != 0 {
		t.Fatalf("secondaryPillars = %#v, want []", payload["secondaryPillars"])
	}
	metadata, ok := payload["metadata"].(map[string]any)
	if !ok || len(metadata) != 0 {
		t.Fatalf("metadata = %#v, want {}", payload["metadata"])
	}
}
