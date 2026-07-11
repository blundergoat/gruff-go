// Package cli tests one-to-one baseline filtering in the agent hook.
// Its journeys mirror duplicate and shifted findings a user can create while
// editing code, keeping hook JSON aligned with ordinary baseline analysis.
package cli

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/baseline"
	"github.com/blundergoat/gruff-go/internal/diff"
	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestHookBaselineConsumesIdentityPairsOneToOne checks that one prior hook
// finding hides only one current occurrence, even after a line shift.
func TestHookBaselineConsumesIdentityPairsOneToOne(t *testing.T) {
	exactFinding := hookBaselineTestFinding("duplicate finding", 10)
	shiftedFinding := hookBaselineTestFinding("duplicate finding", 20)
	secondShiftedFinding := hookBaselineTestFinding("duplicate finding", 30)
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
	legacyEntry := baseline.FromFindings([]finding.Finding{exactFinding}).Findings[0]
	legacyEntry.StableIdentity = ""

	testCases := []struct {
		journeyName            string
		priorFindings          []finding.Finding
		legacyEntries          []baseline.Entry
		currentFindings        []finding.Finding
		expectedVisibleFinding int
	}{
		{
			journeyName:            "one prior occurrence leaves one of two exact duplicates visible",
			priorFindings:          []finding.Finding{exactFinding},
			currentFindings:        []finding.Finding{exactFinding, exactFinding},
			expectedVisibleFinding: 1,
		},
		{
			journeyName:            "two prior stable collisions leave a third shifted occurrence visible",
			priorFindings:          []finding.Finding{exactFinding, shiftedFinding},
			currentFindings:        []finding.Finding{shiftedFinding, secondShiftedFinding, exactFinding},
			expectedVisibleFinding: 1,
		},
		{
			journeyName:            "metric change remains hidden through contract stable identity",
			priorFindings:          []finding.Finding{metricBaselineFinding},
			currentFindings:        []finding.Finding{metricCurrentFinding},
			expectedVisibleFinding: 0,
		},
		{
			journeyName:            "legacy fingerprint hides only one exact duplicate",
			legacyEntries:          []baseline.Entry{legacyEntry},
			currentFindings:        []finding.Finding{exactFinding, exactFinding},
			expectedVisibleFinding: 1,
		},
		{
			journeyName:            "legacy fingerprint cannot follow a line shift",
			legacyEntries:          []baseline.Entry{legacyEntry},
			currentFindings:        []finding.Finding{shiftedFinding},
			expectedVisibleFinding: 1,
		},
	}

	// Exercise every duplicate journey before changed-region filtering is applied.
	for _, testCase := range testCases {
		t.Run(testCase.journeyName, func(t *testing.T) {
			hookBaseline := hookTestFindingBaseline(testCase.priorFindings, testCase.legacyEntries)
			visibleFindings, _ := hookFindings(testCase.currentFindings, nil, diff.ChangedLines{}, false, hookBaseline)
			// The hook UI should expose only occurrences with no consumed prior pair.
			if len(visibleFindings) != testCase.expectedVisibleFinding {
				t.Fatalf("visible findings = %d, want %d: %#v", len(visibleFindings), testCase.expectedVisibleFinding, visibleFindings)
			}
		})
	}
}

// hookTestFindingBaseline converts generated or legacy prior rows into the
// exact shared baseline shape used by hook new-only filtering.
func hookTestFindingBaseline(priorFindings []finding.Finding, legacyEntries []baseline.Entry) hookFindingBaseline {
	// Generated baseline rows carry contract-stable identities.
	if len(priorFindings) > 0 {
		return hookFindingBaselineFromFindings(priorFindings)
	}
	return hookFindingBaseline{
		enabled: true,
		file:    baseline.File{SchemaVersion: baseline.SchemaVersion, Findings: legacyEntries},
	}
}

// hookBaselineTestFinding creates one same-subject finding at a chosen line.
// Different lines model harmless edits while retaining the user's semantic issue.
func hookBaselineTestFinding(message string, lineNumber int) finding.Finding {
	return finding.Finding{
		RuleID:   "test.duplicate",
		File:     "duplicate.go",
		Symbol:   "Run",
		Message:  message,
		Location: &finding.Location{Line: lineNumber},
	}.WithFingerprint()
}
