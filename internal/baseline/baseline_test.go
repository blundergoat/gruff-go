// Package baseline tests exercise loading, applying, and rejecting baselines.
// They model the reviewed-debt journeys users see after duplicates, line shifts,
// sensitive previews, stale entries, and malformed baseline files.
package baseline

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestApplySuppressesExactFingerprintMatches keeps an exact reviewed occurrence
// hidden while a different nearby issue remains visible to the user.
func TestApplySuppressesExactFingerprintMatches(t *testing.T) {
	reviewedFinding := finding.Finding{
		RuleID:   "size.file-length",
		Message:  "test finding",
		File:     "main.go",
		Location: &finding.Location{Line: 10},
	}.WithFingerprint()
	newSiblingFinding := finding.Finding{
		RuleID:   "size.file-length",
		Message:  "other finding",
		File:     "main.go",
		Location: &finding.Location{Line: 11},
	}.WithFingerprint()
	baselineFile := FromFindings([]finding.Finding{reviewedFinding})

	matchResult := Apply([]finding.Finding{reviewedFinding, newSiblingFinding}, baselineFile)
	// The scan should hide exactly the reviewed occurrence and keep its sibling.
	if matchResult.SuppressedFindings != 1 || matchResult.StaleEntries != 0 || len(matchResult.Findings) != 1 {
		t.Fatalf("result = %#v, want one suppressed and one kept", matchResult)
	}
	// The visible result should be the issue the user has not reviewed.
	if matchResult.Findings[0].Fingerprint != newSiblingFinding.Fingerprint {
		t.Fatalf("kept finding = %#v, want other", matchResult.Findings[0])
	}
}

// TestFromFindingsPersistsContractStableIdentity verifies generated baselines
// carry the hook identity needed for value-independent new-only matching.
func TestFromFindingsPersistsContractStableIdentity(t *testing.T) {
	metricFinding := finding.Finding{
		RuleID:   "size.file-length",
		Message:  "file has 510 lines, above threshold 500",
		File:     "main.go",
		Location: &finding.Location{Line: 501},
		Metadata: map[string]any{"lines": 510, "threshold": 500},
	}.WithFingerprint()

	baselineFile := FromFindings([]finding.Finding{metricFinding})
	// A generated entry needs a stable identity to survive user line/value changes.
	if len(baselineFile.Findings) != 1 || baselineFile.Findings[0].StableIdentity == "" {
		t.Fatalf("baseline entries = %#v, want stableIdentity", baselineFile.Findings)
	}

	updatedMetricFinding := metricFinding
	updatedMetricFinding.Message = "file has 820 lines, above threshold 500"
	updatedMetricFinding.Metadata = map[string]any{"lines": 820, "threshold": 500}
	// Changing a measured value must not make reviewed debt look new.
	if baselineFile.Findings[0].StableIdentity != updatedMetricFinding.ComputeContractStableIdentity() {
		t.Fatalf("stable identity changed across measured value: %q != %q",
			baselineFile.Findings[0].StableIdentity, updatedMetricFinding.ComputeContractStableIdentity())
	}
}

// TestApplyReportsStaleEntries verifies stale entries are counted when no finding matches.
func TestApplyReportsStaleEntries(t *testing.T) {
	baselineFile := File{
		SchemaVersion: SchemaVersion,
		Findings: []Entry{{
			RuleID:      "size.file-length",
			File:        "missing.go",
			Fingerprint: "abc123",
		}},
	}
	matchResult := Apply(nil, baselineFile)
	// An absent current issue should appear once as resolved baseline debt.
	if matchResult.StaleEntries != 1 || matchResult.Entries != 1 {
		t.Fatalf("result = %#v, want stale entry", matchResult)
	}
}

// TestBaselineSuppressesSensitiveFindingAcrossPreviewChanges confirms preview
// masking changes neither reviewed identity nor persisted secret safety.
func TestBaselineSuppressesSensitiveFindingAcrossPreviewChanges(t *testing.T) {
	rawSecret := "abcdefghijklmnopqrstuvwxyz123456"
	redactedPreview := "auth_t...3456"
	rawPreview := "auth_token = " + rawSecret
	originalFinding := finding.Finding{
		RuleID:   "sensitive-data.secret-pattern",
		Message:  "secret-like assignment detected",
		File:     "secrets.env",
		Location: &finding.Location{Line: 1},
		Metadata: map[string]any{"preview": rawPreview},
	}.WithFingerprint()
	rerunFinding := originalFinding
	rerunFinding.Metadata = map[string]any{"preview": redactedPreview}
	rerunFinding = rerunFinding.WithFingerprint()
	// Redacting the UI preview must not create a new finding identity.
	if originalFinding.Fingerprint != rerunFinding.Fingerprint {
		t.Fatalf("fingerprint changed with preview metadata: %q != %q", originalFinding.Fingerprint, rerunFinding.Fingerprint)
	}

	baselineFile := FromFindings([]finding.Finding{originalFinding})
	baselineJSON, err := Marshal(baselineFile)
	// Serialization errors would prevent the user from saving reviewed findings.
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	// The saved baseline must never expose the secret or its original preview.
	if strings.Contains(string(baselineJSON), rawSecret) || strings.Contains(string(baselineJSON), rawPreview) {
		t.Fatalf("baseline persisted raw secret data:\n%s", baselineJSON)
	}
	matchResult := Apply([]finding.Finding{rerunFinding}, baselineFile)
	// The masked rerun should remain one unchanged issue in the user's report.
	if matchResult.SuppressedFindings != 1 || len(matchResult.Findings) != 0 || matchResult.StaleEntries != 0 {
		t.Fatalf("apply = %#v, want one suppressed rerun finding", matchResult)
	}
}

// TestApplyKeepsRelocatedSensitiveFindingNew prevents a reviewed secret at one
// location from hiding a different sensitive occurrence elsewhere in the file.
// Non-sensitive contract findings still retain their line-shift behavior.
func TestApplyKeepsRelocatedSensitiveFindingNew(t *testing.T) {
	reviewedSecret := finding.Finding{
		RuleID:   "sensitive-data.secret-pattern",
		Message:  "secret-like assignment detected",
		File:     "secrets.env",
		Location: &finding.Location{Line: 1},
	}.WithFingerprint()
	relocatedSecret := reviewedSecret
	relocatedSecret.Location = &finding.Location{Line: 7}
	relocatedSecret = relocatedSecret.WithFingerprint()

	secretResult := Apply([]finding.Finding{relocatedSecret}, FromFindings([]finding.Finding{reviewedSecret}))
	if secretResult.NewCount() != 1 || secretResult.UnchangedCount() != 0 || secretResult.ResolvedCount() != 1 {
		t.Fatalf("relocated sensitive result = %#v, want new/unchanged/resolved 1/0/1", secretResult)
	}

	reviewedContract := duplicateBaselineTestFinding("Run", "duplicate finding", 10)
	shiftedContract := duplicateBaselineTestFinding("Run", "duplicate finding", 20)
	contractResult := Apply([]finding.Finding{shiftedContract}, FromFindings([]finding.Finding{reviewedContract}))
	if contractResult.NewCount() != 0 || contractResult.UnchangedCount() != 1 || contractResult.ResolvedCount() != 0 {
		t.Fatalf("shifted contract result = %#v, want new/unchanged/resolved 0/1/0", contractResult)
	}
}

// TestApplyKeepsRelocatedSecurityFindingNew prevents one reviewed security
// occurrence from hiding a replacement occurrence elsewhere in the same file.
func TestApplyKeepsRelocatedSecurityFindingNew(t *testing.T) {
	reviewedFinding := finding.Finding{
		RuleID:   "security.request-controlled-url",
		Message:  "request-controlled value used as HTTP request URL without allowlist or validation (possible SSRF)",
		File:     "handler.go",
		Location: &finding.Location{Line: 10},
	}.WithFingerprint()
	replacementFinding := reviewedFinding
	replacementFinding.Location = &finding.Location{Line: 40}
	replacementFinding = replacementFinding.WithFingerprint()

	matchResult := Apply([]finding.Finding{replacementFinding}, FromFindings([]finding.Finding{reviewedFinding}))
	if matchResult.NewCount() != 1 || matchResult.UnchangedCount() != 0 || matchResult.ResolvedCount() != 1 {
		t.Fatalf("relocated security result = %#v, want new/unchanged/resolved 1/0/1", matchResult)
	}
}

// TestApplyKeepsSymbolAnchoredSecurityFindingUnchanged preserves line-insensitive
// matching when a security finding names the same concrete symbol after a shift.
func TestApplyKeepsSymbolAnchoredSecurityFindingUnchanged(t *testing.T) {
	reviewedFinding := finding.Finding{
		RuleID:   "security.request-controlled-url",
		Message:  "request-controlled value used as HTTP request URL without allowlist or validation (possible SSRF)",
		File:     "handler.go",
		Symbol:   "FetchAvatar",
		Location: &finding.Location{Line: 10},
	}.WithFingerprint()
	shiftedFinding := reviewedFinding
	shiftedFinding.Location = &finding.Location{Line: 40}
	shiftedFinding = shiftedFinding.WithFingerprint()

	matchResult := Apply([]finding.Finding{shiftedFinding}, FromFindings([]finding.Finding{reviewedFinding}))
	if matchResult.NewCount() != 0 || matchResult.UnchangedCount() != 1 || matchResult.ResolvedCount() != 0 {
		t.Fatalf("symbol-anchored security result = %#v, want new/unchanged/resolved 0/1/0", matchResult)
	}
}

// TestApplyKeepsRelocatedLocationOnlyFindingNew prevents a reviewed occurrence
// from hiding a different symbol-less issue introduced elsewhere in the file.
func TestApplyKeepsRelocatedLocationOnlyFindingNew(t *testing.T) {
	reviewedFinding := finding.Finding{
		RuleID:   "docs.suppression-without-rationale",
		Message:  "suppression directive requires a rationale",
		File:     "handler.go",
		Location: &finding.Location{Line: 10},
	}.WithFingerprint()
	replacementFinding := reviewedFinding
	replacementFinding.Location = &finding.Location{Line: 40}
	replacementFinding = replacementFinding.WithFingerprint()

	matchResult := Apply([]finding.Finding{replacementFinding}, FromFindings([]finding.Finding{reviewedFinding}))
	if matchResult.NewCount() != 1 || matchResult.UnchangedCount() != 0 || matchResult.ResolvedCount() != 1 {
		t.Fatalf("relocated location-only result = %#v, want new/unchanged/resolved 1/0/1", matchResult)
	}
}

// TestApplyThreeStateClassification is M24's mid-implementation proof: it
// exercises new / unchanged / resolved across empty, fully-matched, and mixed
// baselines, asserting both the collected slices and the legacy counts agree.
func TestApplyThreeStateClassification(t *testing.T) {
	newTestFinding := func(ruleID, filePath string, lineNumber int) finding.Finding {
		return finding.Finding{
			RuleID:   ruleID,
			Message:  "test finding",
			File:     filePath,
			Location: &finding.Location{Line: lineNumber},
		}.WithFingerprint()
	}
	newFinding := newTestFinding("size.file-length", "new.go", 1)
	unchangedFinding := newTestFinding("complexity.cognitive", "kept.go", 2)
	resolvedFinding := newTestFinding("naming.identifier-quality", "fixed.go", 3)

	testCases := []struct {
		journeyName       string
		baselineFindings  []finding.Finding
		currentFindings   []finding.Finding
		expectedNew       int
		expectedUnchanged int
		expectedResolved  int
	}{
		{"empty baseline -> all new", nil, []finding.Finding{newFinding, unchangedFinding}, 2, 0, 0},
		{"fully matched -> all unchanged", []finding.Finding{unchangedFinding}, []finding.Finding{unchangedFinding}, 0, 1, 0},
		{"new plus unchanged", []finding.Finding{unchangedFinding}, []finding.Finding{newFinding, unchangedFinding}, 1, 1, 0},
		{"unchanged plus resolved", []finding.Finding{unchangedFinding, resolvedFinding}, []finding.Finding{unchangedFinding}, 0, 1, 1},
		{"all three states", []finding.Finding{unchangedFinding, resolvedFinding}, []finding.Finding{newFinding, unchangedFinding}, 1, 1, 1},
	}
	// Exercise the status combinations rendered in baseline summaries.
	for _, testCase := range testCases {
		t.Run(testCase.journeyName, func(t *testing.T) {
			baselineFile := FromFindings(testCase.baselineFindings)
			matchResult := Apply(testCase.currentFindings, baselineFile)
			// Each row should expose the expected user-facing three-state counts.
			if matchResult.NewCount() != testCase.expectedNew || matchResult.UnchangedCount() != testCase.expectedUnchanged || matchResult.ResolvedCount() != testCase.expectedResolved {
				t.Fatalf("counts new/unchanged/resolved = %d/%d/%d, want %d/%d/%d",
					matchResult.NewCount(), matchResult.UnchangedCount(), matchResult.ResolvedCount(), testCase.expectedNew, testCase.expectedUnchanged, testCase.expectedResolved)
			}
			// Legacy counts must stay in lockstep with the new slices.
			if matchResult.SuppressedFindings != matchResult.UnchangedCount() || matchResult.StaleEntries != matchResult.ResolvedCount() {
				t.Fatalf("legacy counts drifted: suppressed=%d stale=%d vs unchanged=%d resolved=%d",
					matchResult.SuppressedFindings, matchResult.StaleEntries, matchResult.UnchangedCount(), matchResult.ResolvedCount())
			}
			// The Findings slice remains the exact new set used by the finding gate.
			if len(matchResult.Findings) != testCase.expectedNew {
				t.Fatalf("Findings (new set) len = %d, want %d", len(matchResult.Findings), testCase.expectedNew)
			}
		})
	}
}

// TestApplyConsumesIdentityPairsOneToOne models the baseline journeys users see
// after duplicate findings move, collide, or come from a legacy baseline.
func TestApplyConsumesIdentityPairsOneToOne(t *testing.T) {
	exactFinding := duplicateBaselineTestFinding("Run", "duplicate finding", 10)
	shiftedFinding := duplicateBaselineTestFinding("Run", "duplicate finding", 20)
	secondShiftedFinding := duplicateBaselineTestFinding("Run", "duplicate finding", 30)
	thirdShiftedFinding := duplicateBaselineTestFinding("Run", "duplicate finding", 40)
	exactEntry := FromFindings([]finding.Finding{exactFinding}).Findings[0]
	shiftedEntry := FromFindings([]finding.Finding{shiftedFinding}).Findings[0]
	legacyExactEntry := exactEntry
	legacyExactEntry.StableIdentity = ""
	metricBaselineFinding := finding.Finding{
		RuleID:   "size.file-length",
		File:     "metric.go",
		Message:  "file has 510 lines, above threshold 500",
		Location: &finding.Location{Line: 510},
		Metadata: map[string]any{"lines": 510, "threshold": 500},
	}.WithFingerprint()
	metricCurrentFinding := finding.Finding{
		RuleID:   "size.file-length",
		File:     "metric.go",
		Message:  "file has 820 lines, above threshold 500",
		Location: &finding.Location{Line: 820},
		Metadata: map[string]any{"lines": 820, "threshold": 500},
	}.WithFingerprint()
	wrongContractFinding := duplicateBaselineTestFinding("Different", "different subject", 50)
	wrongContractFinding.StableIdentity = exactEntry.StableIdentity

	testCases := []struct {
		journeyName                 string
		baselineFile                File
		currentFindings             []finding.Finding
		expectedNew                 int
		expectedUnchanged           int
		expectedResolved            int
		expectedResolvedFingerprint string
	}{
		{
			journeyName:       "one prior occurrence cannot hide two current duplicates",
			baselineFile:      FromFindings([]finding.Finding{exactFinding}),
			currentFindings:   []finding.Finding{exactFinding, exactFinding},
			expectedNew:       1,
			expectedUnchanged: 1,
			expectedResolved:  0,
		},
		{
			journeyName:       "two prior duplicates cannot both consume one current occurrence",
			baselineFile:      FromFindings([]finding.Finding{exactFinding, exactFinding}),
			currentFindings:   []finding.Finding{exactFinding},
			expectedNew:       0,
			expectedUnchanged: 1,
			expectedResolved:  1,
		},
		{
			journeyName:       "two exact prior duplicates pair with two current duplicates",
			baselineFile:      FromFindings([]finding.Finding{exactFinding, exactFinding}),
			currentFindings:   []finding.Finding{exactFinding, exactFinding},
			expectedNew:       0,
			expectedUnchanged: 2,
			expectedResolved:  0,
		},
		{
			journeyName:       "two stable collisions leave a third shifted occurrence new",
			baselineFile:      File{SchemaVersion: SchemaVersion, Findings: []Entry{exactEntry, shiftedEntry}},
			currentFindings:   []finding.Finding{secondShiftedFinding, thirdShiftedFinding, exactFinding},
			expectedNew:       1,
			expectedUnchanged: 2,
			expectedResolved:  0,
		},
		{
			journeyName:                 "exact fingerprint wins before a stable collision",
			baselineFile:                File{SchemaVersion: SchemaVersion, Findings: []Entry{exactEntry, shiftedEntry}},
			currentFindings:             []finding.Finding{shiftedFinding},
			expectedNew:                 0,
			expectedUnchanged:           1,
			expectedResolved:            1,
			expectedResolvedFingerprint: exactEntry.Fingerprint,
		},
		{
			journeyName:       "metric changes use contract stable identity instead of finding stable identity",
			baselineFile:      FromFindings([]finding.Finding{metricBaselineFinding}),
			currentFindings:   []finding.Finding{metricCurrentFinding},
			expectedNew:       0,
			expectedUnchanged: 1,
			expectedResolved:  0,
		},
		{
			journeyName:       "finding stable identity cannot override a different contract subject",
			baselineFile:      File{SchemaVersion: SchemaVersion, Findings: []Entry{exactEntry}},
			currentFindings:   []finding.Finding{wrongContractFinding},
			expectedNew:       1,
			expectedUnchanged: 0,
			expectedResolved:  1,
		},
		{
			journeyName:       "legacy exact fingerprint still pairs",
			baselineFile:      File{SchemaVersion: SchemaVersion, Findings: []Entry{legacyExactEntry}},
			currentFindings:   []finding.Finding{exactFinding},
			expectedNew:       0,
			expectedUnchanged: 1,
			expectedResolved:  0,
		},
		{
			journeyName:       "legacy entry without stable identity cannot follow a line shift",
			baselineFile:      File{SchemaVersion: SchemaVersion, Findings: []Entry{legacyExactEntry}},
			currentFindings:   []finding.Finding{shiftedFinding},
			expectedNew:       1,
			expectedUnchanged: 0,
			expectedResolved:  1,
		},
	}

	// Run every user-visible cardinality journey through the same matcher.
	for _, testCase := range testCases {
		t.Run(testCase.journeyName, func(t *testing.T) {
			matchResult := Apply(testCase.currentFindings, testCase.baselineFile)
			// Every current finding must be classified exactly once as new or unchanged.
			if matchResult.NewCount()+matchResult.UnchangedCount() != len(testCase.currentFindings) {
				t.Fatalf("new %d + unchanged %d != current %d", matchResult.NewCount(), matchResult.UnchangedCount(), len(testCase.currentFindings))
			}
			// Every baseline entry must be classified exactly once as unchanged or resolved.
			if matchResult.UnchangedCount()+matchResult.ResolvedCount() != len(testCase.baselineFile.Findings) {
				t.Fatalf("unchanged %d + resolved %d != baseline %d", matchResult.UnchangedCount(), matchResult.ResolvedCount(), len(testCase.baselineFile.Findings))
			}
			// Legacy suppression counts must mirror the user's three-state result.
			if matchResult.SuppressedFindings != matchResult.UnchangedCount() || matchResult.StaleEntries != matchResult.ResolvedCount() {
				t.Fatalf("legacy counts = %d/%d, three-state counts = %d/%d", matchResult.SuppressedFindings, matchResult.StaleEntries, matchResult.UnchangedCount(), matchResult.ResolvedCount())
			}
			// Entries must retain duplicate baseline rows instead of reporting unique keys.
			if matchResult.Entries != len(testCase.baselineFile.Findings) {
				t.Fatalf("entries = %d, want %d", matchResult.Entries, len(testCase.baselineFile.Findings))
			}
			// The row-specific counts describe exactly what the user should see.
			if matchResult.NewCount() != testCase.expectedNew || matchResult.UnchangedCount() != testCase.expectedUnchanged || matchResult.ResolvedCount() != testCase.expectedResolved {
				t.Fatalf("new/unchanged/resolved = %d/%d/%d, want %d/%d/%d", matchResult.NewCount(), matchResult.UnchangedCount(), matchResult.ResolvedCount(), testCase.expectedNew, testCase.expectedUnchanged, testCase.expectedResolved)
			}
			// Exact-first rows identify which older entry remains resolved after pairing.
			if testCase.expectedResolvedFingerprint != "" && (len(matchResult.Resolved) != 1 || matchResult.Resolved[0].Fingerprint != testCase.expectedResolvedFingerprint) {
				t.Fatalf("resolved = %#v, want fingerprint %q", matchResult.Resolved, testCase.expectedResolvedFingerprint)
			}
		})
	}
}

// duplicateBaselineTestFinding builds one occurrence in the fixed duplicate fixture.
// Symbol, message, and line let tests vary the user's semantic or exact identity.
func duplicateBaselineTestFinding(symbolName, message string, lineNumber int) finding.Finding {
	return finding.Finding{
		RuleID:   "test.duplicate",
		File:     "duplicate.go",
		Symbol:   symbolName,
		Message:  message,
		Location: &finding.Location{Line: lineNumber},
	}.WithFingerprint()
}

// TestApplyResolvedEntriesAreSorted confirms Resolved is ordered by (file, ruleId,
// fingerprint) so reports are deterministic.
func TestApplyResolvedEntriesAreSorted(t *testing.T) {
	baselineFile := File{
		SchemaVersion: SchemaVersion,
		Findings: []Entry{
			{RuleID: "z.rule", File: "z.go", Fingerprint: "f3"},
			{RuleID: "a.rule", File: "a.go", Fingerprint: "f1"},
			{RuleID: "a.rule", File: "a.go", Fingerprint: "f0"},
		},
	}
	matchResult := Apply(nil, baselineFile)
	// All unmatched rows should remain available for baseline cleanup.
	if len(matchResult.Resolved) != 3 {
		t.Fatalf("resolved len = %d, want 3", len(matchResult.Resolved))
	}
	// File, rule, then fingerprint ordering keeps the user's output deterministic.
	if matchResult.Resolved[0].File != "a.go" || matchResult.Resolved[0].Fingerprint != "f0" || matchResult.Resolved[2].File != "z.go" {
		t.Fatalf("resolved not sorted: %#v", matchResult.Resolved)
	}
}

// TestParseRejectsMalformedBaseline checks parser errors for invalid baseline inputs.
func TestParseRejectsMalformedBaseline(t *testing.T) {
	// A truncated manual edit should produce a clear baseline diagnostic.
	if _, err := Parse([]byte(`{"schemaVersion":`)); err == nil {
		t.Fatal("expected malformed json error")
	}
	// An unsupported version should ask the user to regenerate the baseline.
	if _, err := Parse([]byte(`{"schemaVersion":"wrong","findings":[]}`)); err == nil {
		t.Fatal("expected schema error")
	}
	// A row without its required identity must never suppress a current finding.
	if _, err := Parse([]byte(`{"schemaVersion":"gruff-go.baseline.v0.1","findings":[{"ruleId":"x"}]}`)); err == nil {
		t.Fatal("expected incomplete entry error")
	}
}
