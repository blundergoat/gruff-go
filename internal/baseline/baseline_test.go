// Package baseline tests exercise loading, applying, and rejecting baselines.
// They cover fingerprint matching, stale-entry reporting, and parse failures.
package baseline

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestApplySuppressesExactFingerprintMatches verifies exact fingerprint suppression.
func TestApplySuppressesExactFingerprintMatches(t *testing.T) {
	item := finding.Finding{
		RuleID:   "size.file-length",
		Message:  "test finding",
		File:     "main.go",
		Location: &finding.Location{Line: 10},
	}.WithFingerprint()
	other := finding.Finding{
		RuleID:   "size.file-length",
		Message:  "other finding",
		File:     "main.go",
		Location: &finding.Location{Line: 11},
	}.WithFingerprint()
	file := FromFindings([]finding.Finding{item})

	result := Apply([]finding.Finding{item, other}, file)
	if result.SuppressedFindings != 1 || result.StaleEntries != 0 || len(result.Findings) != 1 {
		t.Fatalf("result = %#v, want one suppressed and one kept", result)
	}
	if result.Findings[0].Fingerprint != other.Fingerprint {
		t.Fatalf("kept finding = %#v, want other", result.Findings[0])
	}
}

// TestApplyReportsStaleEntries verifies stale entries are counted when no finding matches.
func TestApplyReportsStaleEntries(t *testing.T) {
	file := File{
		SchemaVersion: SchemaVersion,
		Findings: []Entry{{
			RuleID:      "size.file-length",
			File:        "missing.go",
			Fingerprint: "abc123",
		}},
	}
	result := Apply(nil, file)
	if result.StaleEntries != 1 || result.Entries != 1 {
		t.Fatalf("result = %#v, want stale entry", result)
	}
}

// TestBaselineSuppressesSensitiveFindingAcrossPreviewChanges confirms fingerprints ignore preview metadata.
func TestBaselineSuppressesSensitiveFindingAcrossPreviewChanges(t *testing.T) {
	rawSecret := "abcdefghijklmnopqrstuvwxyz123456"
	redactedPreview := "auth_t...3456"
	rawPreview := "auth_token = " + rawSecret
	original := finding.Finding{
		RuleID:   "sensitive-data.secret-pattern",
		Message:  "secret-like assignment detected",
		File:     "secrets.env",
		Location: &finding.Location{Line: 1},
		Metadata: map[string]any{"preview": rawPreview},
	}.WithFingerprint()
	rerun := original
	rerun.Metadata = map[string]any{"preview": redactedPreview}
	rerun = rerun.WithFingerprint()
	if original.Fingerprint != rerun.Fingerprint {
		t.Fatalf("fingerprint changed with preview metadata: %q != %q", original.Fingerprint, rerun.Fingerprint)
	}

	file := FromFindings([]finding.Finding{original})
	data, err := Marshal(file)
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	if strings.Contains(string(data), rawSecret) || strings.Contains(string(data), rawPreview) {
		t.Fatalf("baseline persisted raw secret data:\n%s", data)
	}
	result := Apply([]finding.Finding{rerun}, file)
	if result.SuppressedFindings != 1 || len(result.Findings) != 0 || result.StaleEntries != 0 {
		t.Fatalf("apply = %#v, want one suppressed rerun finding", result)
	}
}

// TestParseRejectsMalformedBaseline checks parser errors for invalid baseline inputs.
func TestParseRejectsMalformedBaseline(t *testing.T) {
	if _, err := Parse([]byte(`{"schemaVersion":`)); err == nil {
		t.Fatal("expected malformed json error")
	}
	if _, err := Parse([]byte(`{"schemaVersion":"wrong","findings":[]}`)); err == nil {
		t.Fatal("expected schema error")
	}
	if _, err := Parse([]byte(`{"schemaVersion":"gruff-go.baseline.v0.1","findings":[{"ruleId":"x"}]}`)); err == nil {
		t.Fatal("expected incomplete entry error")
	}
}
