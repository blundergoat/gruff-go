// Package analysis tests baseline classification inside the scan runner.
// These journeys verify the counts and detail arrays a user receives after
// duplicate or line-shifted findings are compared with a saved baseline.
package analysis

import (
	"path/filepath"
	"testing"

	"github.com/blundergoat/gruff-go/internal/baseline"
	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestApplyBaselineReportsOneToOneCardinality checks that runner summaries
// preserve every current finding and every duplicate baseline entry exactly once.
func TestApplyBaselineReportsOneToOneCardinality(t *testing.T) {
	exactFinding := runnerBaselineTestFinding(10)
	shiftedFinding := runnerBaselineTestFinding(20)
	testCases := []struct {
		journeyName       string
		baselineFindings  []finding.Finding
		currentFindings   []finding.Finding
		expectedNew       int
		expectedUnchanged int
		expectedResolved  int
	}{
		{
			journeyName:       "one prior duplicate leaves one of two current occurrences new",
			baselineFindings:  []finding.Finding{exactFinding},
			currentFindings:   []finding.Finding{exactFinding, exactFinding},
			expectedNew:       1,
			expectedUnchanged: 1,
			expectedResolved:  0,
		},
		{
			journeyName:       "two prior duplicates leave one resolved when one remains current",
			baselineFindings:  []finding.Finding{exactFinding, exactFinding},
			currentFindings:   []finding.Finding{exactFinding},
			expectedNew:       0,
			expectedUnchanged: 1,
			expectedResolved:  1,
		},
		{
			journeyName:       "a line shift remains unchanged through contract identity",
			baselineFindings:  []finding.Finding{exactFinding},
			currentFindings:   []finding.Finding{shiftedFinding},
			expectedNew:       0,
			expectedUnchanged: 1,
			expectedResolved:  0,
		},
	}

	// Run each user journey through the same loader and summary path as analyse.
	for _, testCase := range testCases {
		t.Run(testCase.journeyName, func(t *testing.T) {
			projectRoot := t.TempDir()
			baselinePath := filepath.Join(projectRoot, "baseline.json")
			baselineFile, err := baseline.FromFindings(testCase.baselineFindings)
			if err != nil {
				t.Fatal(err)
			}
			// A write failure means the runner never received a usable user baseline.
			if err := baseline.Write(baselinePath, baselineFile); err != nil {
				t.Fatal(err)
			}
			// A v3 entry carries a count, so the reviewed total is the sum of counts, not the row count.
			reviewedOccurrences := 0
			for _, occurrence := range baselineFile.Occurrences {
				reviewedOccurrences += occurrence.Count
			}
			newFindings, summary, diagnostics := applyBaseline(projectRoot, testCase.currentFindings, nil, "baseline.json", true)
			// A valid baseline should not create a user-facing diagnostic.
			if len(diagnostics) != 0 {
				t.Fatalf("diagnostics = %#v, want none", diagnostics)
			}
			// Current findings must be split exactly between visible new and unchanged.
			if len(newFindings)+summary.UnchangedFindings != len(testCase.currentFindings) {
				t.Fatalf("new %d + unchanged %d != current %d", len(newFindings), summary.UnchangedFindings, len(testCase.currentFindings))
			}
			// Prior entries must be split exactly between unchanged and resolved.
			if summary.UnchangedFindings+summary.ResolvedFindings != reviewedOccurrences {
				t.Fatalf("unchanged %d + resolved %d != reviewed %d", summary.UnchangedFindings, summary.ResolvedFindings, reviewedOccurrences)
			}
			// Summary compatibility fields must remain aligned for existing UI consumers.
			if summary.SuppressedFindings != summary.UnchangedFindings || summary.StaleEntries != summary.ResolvedFindings || summary.Entries != len(baselineFile.Occurrences) {
				t.Fatalf("summary compatibility counts drifted: %#v", summary)
			}
			// The row-specific result is what the user should see in baseline status.
			if len(newFindings) != testCase.expectedNew || summary.UnchangedFindings != testCase.expectedUnchanged || summary.ResolvedFindings != testCase.expectedResolved {
				t.Fatalf("new/unchanged/resolved = %d/%d/%d, want %d/%d/%d", len(newFindings), summary.UnchangedFindings, summary.ResolvedFindings, testCase.expectedNew, testCase.expectedUnchanged, testCase.expectedResolved)
			}
			// --baseline-show details should match the counts rendered beside them.
			if len(summary.Unchanged) != summary.UnchangedFindings || len(summary.Resolved) != summary.ResolvedFindings {
				t.Fatalf("detail lengths = %d/%d, want %d/%d", len(summary.Unchanged), len(summary.Resolved), summary.UnchangedFindings, summary.ResolvedFindings)
			}
		})
	}
}

// runnerBaselineTestFinding creates one same-subject finding at a selected line.
// Moving the line changes its fingerprint but not the user's semantic issue.
func runnerBaselineTestFinding(lineNumber int) finding.Finding {
	return finding.Finding{
		RuleID:   "test.duplicate",
		File:     "duplicate.go",
		Symbol:   "Run",
		Message:  "duplicate finding",
		Location: &finding.Location{Line: lineNumber},
	}.WithFingerprint()
}
