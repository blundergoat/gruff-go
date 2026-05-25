// Package finding tests assert fingerprint stability and identity coverage.
// They guard the JSON payload shape and hash contract used by baselines.
package finding

import "testing"

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
