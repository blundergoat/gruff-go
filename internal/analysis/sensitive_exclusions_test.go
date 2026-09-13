// Package analysis tests cover the ratified sensitive-exclusion matcher.
// The cases mirror gruff-spec/fixtures/sensitive-exclusions/cases.v1.json,
// including its sibling rule: an exclusion may remove only the findings whose
// rule and path match a declared entry, and nothing else.
package analysis

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// corpusFindings returns the synthetic finding set the acceptance cases run
// against: one rule repeated in one file, the same rule in a sibling file, a
// second sensitive rule in its own file, and an unrelated non-sensitive finding.
func corpusFindings() []finding.Finding {
	return []finding.Finding{
		{RuleID: "sensitive-data.aws-access-key", File: "secrets/aws.env", Message: "[redacted:aws-access-key]", Pillar: finding.PillarSensitiveData},
		{RuleID: "sensitive-data.aws-access-key", File: "secrets/aws.env", Message: "[redacted:aws-access-key]", Pillar: finding.PillarSensitiveData},
		{RuleID: "sensitive-data.aws-access-key", File: "secrets/aws-sibling.env", Message: "[redacted:aws-access-key]", Pillar: finding.PillarSensitiveData},
		{RuleID: "sensitive-data.jwt-token", File: "secrets/jwt.env", Message: "[redacted:jwt]", Pillar: finding.PillarSensitiveData},
		{RuleID: "sensitive-data.github-token", File: "secrets/aws.env", Message: "[redacted:github-token]", Pillar: finding.PillarSensitiveData},
		{RuleID: "size.file-length", File: "secrets/aws.env", Message: "file is too long", Pillar: finding.PillarSize},
	}
}

// findingKeys renders findings as rule+path pairs for set comparison.
func findingKeys(findings []finding.Finding) []string {
	keys := make([]string, 0, len(findings))
	for _, item := range findings {
		keys = append(keys, item.RuleID+" "+item.File)
	}
	return keys
}

// assertRemovedExactly fails unless the exclusions removed the expected rule+path
// pairs and nothing else. This is the spec's sibling rule: an unintended
// suppression is a failure even when the intended one also happened.
func assertRemovedExactly(t *testing.T, kept []finding.Finding, wantRemoved []string) {
	t.Helper()
	remaining := map[string]int{}
	for _, key := range findingKeys(kept) {
		remaining[key]++
	}
	original := map[string]int{}
	for _, key := range findingKeys(corpusFindings()) {
		original[key]++
	}
	removed := []string{}
	for key, count := range original {
		for index := 0; index < count-remaining[key]; index++ {
			removed = append(removed, key)
		}
	}
	if len(removed) != len(wantRemoved) {
		t.Fatalf("removed %v, want %v", removed, wantRemoved)
	}
	wanted := map[string]int{}
	for _, key := range wantRemoved {
		wanted[key]++
	}
	for _, key := range removed {
		wanted[key]--
		if wanted[key] < 0 {
			t.Fatalf("unintended sibling suppression of %q; removed %v, want %v", key, removed, wantRemoved)
		}
	}
}

// TestExactRuleAndPathSuppressesEveryOccurrence covers the exact-rule-and-path
// case: both occurrences of one rule in one file go, its sibling file keeps
// reporting, and another rule in the same file keeps reporting.
func TestExactRuleAndPathSuppressesEveryOccurrence(t *testing.T) {
	exclusions := []SensitiveExclusion{{
		Rule:   "sensitive-data.aws-access-key",
		Path:   "secrets/aws.env",
		Reason: "Synthetic AWS key used by the redaction corpus; not a live credential.",
	}}

	kept, summaries := ApplySensitiveExclusions(corpusFindings(), exclusions)

	assertRemovedExactly(t, kept, []string{
		"sensitive-data.aws-access-key secrets/aws.env",
		"sensitive-data.aws-access-key secrets/aws.env",
	})
	if summaries[0].Suppressed != 2 {
		t.Fatalf("suppressed = %d, want 2", summaries[0].Suppressed)
	}
}

// TestScopeMatchingNothingReportsZero covers the scope-matching-nothing case:
// an entry whose file carries no such finding is not an error, so fixing the
// underlying problem never breaks a build.
func TestScopeMatchingNothingReportsZero(t *testing.T) {
	exclusions := []SensitiveExclusion{{
		Rule:   "sensitive-data.aws-access-key",
		Path:   "secrets/clean.env",
		Reason: "Retained while the fixture is being removed.",
	}}

	kept, summaries := ApplySensitiveExclusions(corpusFindings(), exclusions)

	assertRemovedExactly(t, kept, nil)
	if summaries[0].Suppressed != 0 {
		t.Fatalf("suppressed = %d, want 0", summaries[0].Suppressed)
	}
}

// TestSymbolNarrowsScope covers the symbol-narrows-scope case: no sensitive-data
// rule stamps a symbol, so an entry carrying one correctly claims nothing and
// the finding survives.
func TestSymbolNarrowsScope(t *testing.T) {
	exclusions := []SensitiveExclusion{{
		Rule:   "sensitive-data.aws-access-key",
		Path:   "secrets/aws.env",
		Symbol: "SyntheticFixtureSymbol",
		Reason: "Narrowed to one symbol while the fixture is refactored.",
	}}

	kept, summaries := ApplySensitiveExclusions(corpusFindings(), exclusions)

	assertRemovedExactly(t, kept, nil)
	if summaries[0].Suppressed != 0 {
		t.Fatalf("suppressed = %d, want 0", summaries[0].Suppressed)
	}
}

// TestSymbolMatchesWhenTheFindingStampsOne verifies the symbol narrowing is real
// rather than inert by construction: a finding carrying the configured symbol is
// suppressed and its symbol-free sibling is not.
func TestSymbolMatchesWhenTheFindingStampsOne(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "sensitive-data.aws-access-key", File: "secrets/aws.env", Symbol: "SyntheticFixtureSymbol"},
		{RuleID: "sensitive-data.aws-access-key", File: "secrets/aws.env"},
	}
	exclusions := []SensitiveExclusion{{
		Rule:   "sensitive-data.aws-access-key",
		Path:   "secrets/aws.env",
		Symbol: "SyntheticFixtureSymbol",
		Reason: "Narrowed to one symbol while the fixture is refactored.",
	}}

	kept, summaries := ApplySensitiveExclusions(findings, exclusions)

	if len(kept) != 1 || kept[0].Symbol != "" {
		t.Fatalf("kept = %+v, want only the symbol-free finding", kept)
	}
	if summaries[0].Suppressed != 1 {
		t.Fatalf("suppressed = %d, want 1", summaries[0].Suppressed)
	}
}

// TestTwoDistinctEntriesCountIndependently covers the two-distinct-entries case:
// each entry reports its own count and neither absorbs the other's findings.
func TestTwoDistinctEntriesCountIndependently(t *testing.T) {
	exclusions := []SensitiveExclusion{
		{Rule: "sensitive-data.aws-access-key", Path: "secrets/aws.env", Reason: "Synthetic AWS key in the redaction corpus."},
		{Rule: "sensitive-data.jwt-token", Path: "secrets/jwt.env", Reason: "Synthetic JWT in the redaction corpus."},
	}

	kept, summaries := ApplySensitiveExclusions(corpusFindings(), exclusions)

	assertRemovedExactly(t, kept, []string{
		"sensitive-data.aws-access-key secrets/aws.env",
		"sensitive-data.aws-access-key secrets/aws.env",
		"sensitive-data.jwt-token secrets/jwt.env",
	})
	if summaries[0].Suppressed != 2 || summaries[1].Suppressed != 1 {
		t.Fatalf("counts = %d and %d, want 2 and 1", summaries[0].Suppressed, summaries[1].Suppressed)
	}
}

// TestSameRuleInAnotherFileSurvives covers the same-rule-other-file-survives
// case: excluding the sibling file leaves the primary file reporting.
func TestSameRuleInAnotherFileSurvives(t *testing.T) {
	exclusions := []SensitiveExclusion{{
		Rule:   "sensitive-data.aws-access-key",
		Path:   "secrets/aws-sibling.env",
		Reason: "Only the sibling fixture is accepted.",
	}}

	kept, summaries := ApplySensitiveExclusions(corpusFindings(), exclusions)

	assertRemovedExactly(t, kept, []string{"sensitive-data.aws-access-key secrets/aws-sibling.env"})
	if summaries[0].Suppressed != 1 {
		t.Fatalf("suppressed = %d, want 1", summaries[0].Suppressed)
	}
}

// TestSuppressedFindingsLeaveScoringAndExitCodes verifies a suppressed finding is
// gone from the report the way the existing suppression channel removes one: out
// of the finding list, out of the counts, and out of the resolved exit code.
func TestSuppressedFindingsLeaveScoringAndExitCodes(t *testing.T) {
	findings := []finding.Finding{{
		RuleID:   "sensitive-data.aws-access-key",
		File:     "secrets/aws.env",
		Severity: finding.SeverityError,
		Pillar:   finding.PillarSensitiveData,
	}}
	exclusions := []SensitiveExclusion{{
		Rule:   "sensitive-data.aws-access-key",
		Path:   "secrets/aws.env",
		Reason: "Synthetic AWS key used by the redaction corpus; not a live credential.",
	}}

	kept, summaries := ApplySensitiveExclusions(findings, exclusions)
	report := NewReport(ReportInput{
		Root:         "/repo",
		Inputs:       []string{"."},
		Format:       "json",
		FailOn:       finding.FailThresholdError,
		Scanned:      []string{"secrets/aws.env"},
		Findings:     kept,
		Suppressions: summaries,
	})

	if report.Summary.FindingsCount != 0 {
		t.Fatalf("findingsCount = %d, want 0", report.Summary.FindingsCount)
	}
	if report.Summary.ExitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", report.Summary.ExitCode)
	}
	if report.Suppressions[0].Suppressed != 1 {
		t.Fatalf("audit suppressed = %d, want 1", report.Suppressions[0].Suppressed)
	}
}

// TestSuppressionAuditSerialisesTheFamilyShape locks the audit row down to the
// keys the family contract publishes, and proves the row carries configuration
// text only - never a message excerpt, preview, or matched value.
func TestSuppressionAuditSerialisesTheFamilyShape(t *testing.T) {
	exclusions := []SensitiveExclusion{{
		Rule:   "sensitive-data.aws-access-key",
		Path:   "secrets/aws.env",
		Reason: "Synthetic AWS key used by the redaction corpus; not a live credential.",
	}}
	_, summaries := ApplySensitiveExclusions(corpusFindings(), exclusions)

	encoded, err := json.Marshal(summaries[0])
	if err != nil {
		t.Fatalf("marshal audit row: %v", err)
	}
	want := `{"index":0,"rule":"sensitive-data.aws-access-key","paths":["secrets/aws.env"],"symbol":null,"reason":"Synthetic AWS key used by the redaction corpus; not a live credential.","suppressed":2}`
	if string(encoded) != want {
		t.Fatalf("audit row =\n%s\nwant\n%s", encoded, want)
	}
	if strings.Contains(string(encoded), "redacted") {
		t.Fatal("audit row carries finding message material")
	}
}

// TestReportAlwaysCarriesASuppressionsArray verifies the machine report publishes
// an empty array rather than null when a project configured no exclusions, so
// consumers can read the key unconditionally.
func TestReportAlwaysCarriesASuppressionsArray(t *testing.T) {
	report := NewReport(ReportInput{
		Root:    "/repo",
		Inputs:  []string{"."},
		Format:  "json",
		FailOn:  finding.FailThresholdWarning,
		Scanned: []string{"main.go"},
	})
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if !strings.Contains(string(encoded), `"suppressions":[]`) {
		t.Fatal("report without exclusions did not publish an empty suppressions array")
	}
}
