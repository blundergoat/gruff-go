// Package cli tests count-aware baseline filtering in the agent hook.
// Its journeys mirror duplicate and shifted findings a user can create while
// editing code, keeping hook JSON aligned with ordinary baseline analysis.
package cli

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/diff"
	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestHookBaselineConsumesIdentityPairsOneToOne checks that one prior hook
// finding hides only one current occurrence, and that a count is spent rather
// than matched by membership.
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
	rewordedSymbolFinding := exactFinding
	rewordedSymbolFinding.Message = "the same duplicate finding, reworded"

	testCases := []struct {
		journeyName            string
		priorFindings          []finding.Finding
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
			// Three declarations of one symbol rank first, second, third; two were reviewed.
			journeyName:            "two prior declarations leave a third declaration visible",
			priorFindings:          []finding.Finding{exactFinding, shiftedFinding},
			currentFindings:        []finding.Finding{shiftedFinding, secondShiftedFinding, exactFinding},
			expectedVisibleFinding: 1,
		},
		{
			// A symbol-bearing finding is named by its symbol, so a reworded message changes nothing.
			journeyName:            "message rewording on a symbol-bearing finding stays hidden",
			priorFindings:          []finding.Finding{exactFinding},
			currentFindings:        []finding.Finding{rewordedSymbolFinding},
			expectedVisibleFinding: 0,
		},
		{
			// A file-level finding is named by its message with the measurement
			// stripped, so the file growing from 510 to 820 lines stays hidden.
			journeyName:            "a file-level metric change stays hidden",
			priorFindings:          []finding.Finding{metricBaselineFinding},
			currentFindings:        []finding.Finding{metricCurrentFinding},
			expectedVisibleFinding: 0,
		},
		{
			journeyName:            "an empty prior base hides nothing",
			priorFindings:          []finding.Finding{},
			currentFindings:        []finding.Finding{exactFinding},
			expectedVisibleFinding: 1,
		},
	}

	// Exercise every duplicate journey before changed-region filtering is applied.
	for _, testCase := range testCases {
		t.Run(testCase.journeyName, func(t *testing.T) {
			hookBaseline, err := hookFindingBaselineFromFindings(testCase.priorFindings)
			if err != nil {
				t.Fatalf("prior base: %v", err)
			}
			visibleFindings, _ := hookFindings(testCase.currentFindings, nil, diff.ChangedLines{}, false, hookBaseline)
			// The hook UI should expose only occurrences beyond the reviewed count.
			if len(visibleFindings) != testCase.expectedVisibleFinding {
				t.Fatalf("visible findings = %d, want %d: %#v", len(visibleFindings), testCase.expectedVisibleFinding, visibleFindings)
			}
		})
	}
}

// TestHookNeverHidesASensitiveFinding keeps a reviewed secret from covering the
// same secret on the next run: a sensitive finding has no baseline identity.
func TestHookNeverHidesASensitiveFinding(t *testing.T) {
	secret := finding.Finding{
		RuleID:   "sensitive-data.secret-pattern",
		File:     "secrets.env",
		Pillar:   finding.PillarSensitiveData,
		Message:  "secret-like assignment detected",
		Location: &finding.Location{Line: 1},
	}.WithFingerprint()
	hookBaseline, err := hookFindingBaselineFromFindings([]finding.Finding{secret})
	if err != nil {
		t.Fatal(err)
	}
	visibleFindings, _ := hookFindings([]finding.Finding{secret}, nil, diff.ChangedLines{}, false, hookBaseline)
	if len(visibleFindings) != 1 {
		t.Fatalf("visible findings = %d, want the sensitive finding to stay visible", len(visibleFindings))
	}
}

// hookBaselineTestFinding creates one same-subject finding at a chosen line.
// Different lines model separate declarations of one symbol name.
func hookBaselineTestFinding(message string, lineNumber int) finding.Finding {
	return finding.Finding{
		RuleID:   "test.duplicate",
		File:     "duplicate.go",
		Symbol:   "Run",
		Message:  message,
		Location: &finding.Location{Line: lineNumber},
	}.WithFingerprint()
}
