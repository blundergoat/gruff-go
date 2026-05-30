// Package baseline tests exercise loading, applying, and rejecting baselines.
// They cover fingerprint matching, stale-entry reporting, and parse failures.
package baseline

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestApplySuppressesExactFingerprintMatches asserts that Apply hides a finding whose fingerprint already lives in the baseline while keeping a sibling whose location differs by one line.
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

// TestApplyThreeStateClassification is M24's mid-implementation proof: it
// exercises new / unchanged / resolved across empty, fully-matched, and mixed
// baselines, asserting both the collected slices and the legacy counts agree.
func TestApplyThreeStateClassification(t *testing.T) {
	mkFinding := func(rule, file string, line int) finding.Finding {
		return finding.Finding{
			RuleID:   rule,
			Message:  "test finding",
			File:     file,
			Location: &finding.Location{Line: line},
		}.WithFingerprint()
	}
	kept := mkFinding("size.file-length", "new.go", 1)
	matched := mkFinding("complexity.cognitive", "kept.go", 2)
	gone := mkFinding("naming.identifier-quality", "fixed.go", 3)

	tests := []struct {
		name                          string
		baseline                      []finding.Finding
		current                       []finding.Finding
		wantNew, wantUnch, wantResolv int
	}{
		{"empty baseline -> all new", nil, []finding.Finding{kept, matched}, 2, 0, 0},
		{"fully matched -> all unchanged", []finding.Finding{matched}, []finding.Finding{matched}, 0, 1, 0},
		{"new plus unchanged", []finding.Finding{matched}, []finding.Finding{kept, matched}, 1, 1, 0},
		{"unchanged plus resolved", []finding.Finding{matched, gone}, []finding.Finding{matched}, 0, 1, 1},
		{"all three states", []finding.Finding{matched, gone}, []finding.Finding{kept, matched}, 1, 1, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file := FromFindings(tc.baseline)
			result := Apply(tc.current, file)
			if result.NewCount() != tc.wantNew || result.UnchangedCount() != tc.wantUnch || result.ResolvedCount() != tc.wantResolv {
				t.Fatalf("counts new/unchanged/resolved = %d/%d/%d, want %d/%d/%d",
					result.NewCount(), result.UnchangedCount(), result.ResolvedCount(), tc.wantNew, tc.wantUnch, tc.wantResolv)
			}
			// Legacy counts must stay in lockstep with the new slices.
			if result.SuppressedFindings != result.UnchangedCount() || result.StaleEntries != result.ResolvedCount() {
				t.Fatalf("legacy counts drifted: suppressed=%d stale=%d vs unchanged=%d resolved=%d",
					result.SuppressedFindings, result.StaleEntries, result.UnchangedCount(), result.ResolvedCount())
			}
			if len(result.Findings) != tc.wantNew {
				t.Fatalf("Findings (new set) len = %d, want %d", len(result.Findings), tc.wantNew)
			}
		})
	}
}

// TestApplyResolvedEntriesAreSorted confirms Resolved is ordered by (file, ruleId,
// fingerprint) so reports are deterministic.
func TestApplyResolvedEntriesAreSorted(t *testing.T) {
	file := File{
		SchemaVersion: SchemaVersion,
		Findings: []Entry{
			{RuleID: "z.rule", File: "z.go", Fingerprint: "f3"},
			{RuleID: "a.rule", File: "a.go", Fingerprint: "f1"},
			{RuleID: "a.rule", File: "a.go", Fingerprint: "f0"},
		},
	}
	result := Apply(nil, file)
	if len(result.Resolved) != 3 {
		t.Fatalf("resolved len = %d, want 3", len(result.Resolved))
	}
	if result.Resolved[0].File != "a.go" || result.Resolved[0].Fingerprint != "f0" || result.Resolved[2].File != "z.go" {
		t.Fatalf("resolved not sorted: %#v", result.Resolved)
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
