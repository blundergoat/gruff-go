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

// TestApplyBaselineReportsOneToOneCardinality checks that summaries count every current finding and duplicate baseline entry exactly once.
//
// A failure points at wrong new, unchanged or resolved totals, mismatched compatibility counts or detail lists, or a fixture setup error.
func TestApplyBaselineReportsOneToOneCardinality(t *testing.T) {
	// Both findings share one subject and differ only by line, as when a user adds code above an existing issue.
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
			// A FromFindings error means the baseline package rejected the fixture findings before the runner was reached.
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
			// Compatibility counts must equal the new ones; a mismatch means existing summary consumers would see different numbers.
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
//
// Moving the line changes its fingerprint but not the user's semantic issue.
// Returns a nonzero finding at lineNumber with its fingerprint computed by WithFingerprint; rule ID, file, symbol and message stay fixed.
func runnerBaselineTestFinding(lineNumber int) finding.Finding {
	return finding.Finding{
		RuleID:   "test.duplicate",
		File:     "duplicate.go",
		Symbol:   "Run",
		Message:  "duplicate finding",
		Location: &finding.Location{Line: lineNumber},
	}.WithFingerprint()
}
