package baseline

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

func TestApplySuppressesExactFingerprintMatches(t *testing.T) {
	item := finding.Finding{
		RuleID:   "size-file-length",
		Message:  "test finding",
		File:     "main.go",
		Location: &finding.Location{Line: 10},
	}.WithFingerprint()
	other := finding.Finding{
		RuleID:   "size-file-length",
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

func TestApplyReportsStaleEntries(t *testing.T) {
	file := File{
		SchemaVersion: SchemaVersion,
		Findings: []Entry{{
			RuleID:      "size-file-length",
			File:        "missing.go",
			Fingerprint: "abc123",
		}},
	}
	result := Apply(nil, file)
	if result.StaleEntries != 1 || result.Entries != 1 {
		t.Fatalf("result = %#v, want stale entry", result)
	}
}

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
