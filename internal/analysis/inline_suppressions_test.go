package analysis

import (
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// inlineFinding builds a finding at one line of main.go, so each case names only the rule, pillar and line.
func inlineFinding(ruleID string, pillar finding.Pillar, line int) finding.Finding {
	return finding.Finding{RuleID: ruleID, File: "main.go", Pillar: pillar, Location: &finding.Location{Line: line}}
}

// TestInlineCommentsSuppressOnlyTheChecksSection13cNames walks each comment form section 13c decides for gruff-go,
// beside the controls that must keep reporting: an unrelated gosec check, gosec G101 on a security rule, a sibling line, a
// comment above that shares its line with code, and gruff-go's own rationale rule on the comment it reports.
func TestInlineCommentsSuppressOnlyTheChecksSection13cNames(t *testing.T) {
	cases := []struct {
		name     string
		source   string
		finding  finding.Finding
		suppress bool
	}{
		{"gosec check above the call", "// #nosec G204 -- fixed git arguments\nrun()", inlineFinding("security.shell-command", finding.PillarSecurity, 2), true},
		{"gosec check on the line", "run() // #nosec G204", inlineFinding("security.shell-command", finding.PillarSecurity, 1), true},
		{"unrelated gosec check", "// #nosec G304 -- explicit path\nrun()", inlineFinding("security.shell-command", finding.PillarSecurity, 2), false},
		{"gosec G101 covers sensitive data", `url := "postgres://app:secret@db/orders" // #nosec G101 -- fixture`, inlineFinding("sensitive-data.connection-string", finding.PillarSensitiveData, 1), true},
		{"gosec G101 leaves security rules", "// #nosec G101\nrun()", inlineFinding("security.shell-command", finding.PillarSecurity, 2), false},
		{"bare nosec covers sensitive data", `url := "postgres://app:secret@db/orders" // #nosec -- fixture`, inlineFinding("sensitive-data.connection-string", finding.PillarSensitiveData, 1), true},
		{"bare nosec leaves function length", "// #nosec\nfunc long() {", inlineFinding("size.function-length", finding.PillarSize, 2), false},
		{"nolint gosec in a list", `url := "postgres://app:secret@db/orders" //nolint:gosec,goconst`, inlineFinding("sensitive-data.connection-string", finding.PillarSensitiveData, 1), true},
		{"nolint funlen above the function", "//nolint:funlen // setup stays linear\nfunc long() {", inlineFinding("size.function-length", finding.PillarSize, 2), true},
		{"nolint all above the function", "//nolint:all\nfunc long() {", inlineFinding("size.function-length", finding.PillarSize, 2), true},
		{"bare nolint above the function", "//nolint\nfunc long() {", inlineFinding("size.function-length", finding.PillarSize, 2), true},
		{"nolint funlen leaves security", "//nolint:funlen\nrun()", inlineFinding("security.shell-command", finding.PillarSecurity, 2), false},
		{"comment above shares its line with code", "x := 1 // #nosec G204\nrun()", inlineFinding("security.shell-command", finding.PillarSecurity, 2), false},
		{"sibling line keeps reporting", "// #nosec G204\nrun()\nrun()", inlineFinding("security.shell-command", finding.PillarSecurity, 3), false},
		{"zizmor audit on the uses line", "    - uses: actions/checkout@v4 # zizmor: ignore[unpinned-uses]", inlineFinding("security.github-actions-unpinned-action", finding.PillarSecurity, 1), true},
		{"rationale rule on the bare comment", "// #nosec\nrun()", inlineFinding("docs.suppression-without-rationale", finding.PillarDocumentation, 1), false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			kept, summaries, suppressed := ApplyInlineSuppressions([]finding.Finding{testCase.finding}, nil, map[string]string{"main.go": testCase.source})
			if got := len(suppressed) == 1; got != testCase.suppress {
				t.Fatalf("suppressed = %v, want %v (kept %#v, rows %#v)", got, testCase.suppress, kept, summaries)
			}
			if len(kept)+len(suppressed) != 1 {
				t.Fatalf("kept %d and suppressed %d, want one finding accounted for", len(kept), len(suppressed))
			}
		})
	}
}

// TestInlineRowsFollowTheBuiltInRows proves the audit rows: one per file and rule with the contract's source and
// reason, numbered after the built-in rows, and SARIF's copy of each suppressed finding carrying the same reason.
func TestInlineRowsFollowTheBuiltInRows(t *testing.T) {
	builtIn := []SuppressionSummary{
		{Index: 0, Rule: "sensitive-data.high-entropy-string", Paths: []string{"go.sum"}, Reason: "lockfile", Suppressed: 3, Source: SuppressionSourceBuiltIn},
		{Index: 1, Rule: "security.shell-command", Paths: []string{"main_test.go"}, Reason: BuiltInSecurityTestPathReason, Suppressed: 1, Source: SuppressionSourceBuiltIn},
	}
	findings := []finding.Finding{
		inlineFinding("security.shell-command", finding.PillarSecurity, 2),
		inlineFinding("security.shell-command", finding.PillarSecurity, 3),
		inlineFinding("security.shell-command", finding.PillarSecurity, 4),
	}
	source := "// #nosec G204\nrun() // #nosec G204\nrun() // #nosec G204\nrun()"
	kept, summaries, suppressed := ApplyInlineSuppressions(findings, builtIn, map[string]string{"main.go": source})
	if len(kept) != 1 || kept[0].Location.Line != 4 {
		t.Fatalf("kept = %#v, want only the uncommented line 4", kept)
	}
	if len(summaries) != 3 {
		t.Fatalf("rows = %#v, want the two built-in rows and one inline row", summaries)
	}
	row := summaries[2]
	if row.Index != 2 || row.Source != SuppressionSourceInline || row.Rule != "security.shell-command" || row.Paths[0] != "main.go" || row.Suppressed != 2 {
		t.Fatalf("inline row = %#v, want index 2, source inline, main.go, 2 suppressed", row)
	}
	if row.Reason != "Another tool's suppression comment names this check, so the finding is suppressed where it was written." {
		t.Fatalf("reason = %q, want the section 13c wording", row.Reason)
	}
	if len(suppressed) != 2 || suppressed[0].Justification != row.Reason {
		t.Fatalf("suppressed = %#v, want two findings justified by the row's reason", suppressed)
	}
}

// TestAnalyzeCountsAnInlineSuppressionAndKeepsTheRationaleFinding runs the whole pipeline: a `//nolint:funlen` above
// one long function suppresses it and is counted, its unsuppressed sibling still reports, and the rationale-free comment still
// draws gruff-go's own docs.suppression-without-rationale finding where it was written.
func TestAnalyzeCountsAnInlineSuppressionAndKeepsTheRationaleFinding(t *testing.T) {
	root := t.TempDir()
	body := strings.Repeat("\t_ = 1\n", 90)
	writeFile(t, root, "main.go", "// Package main is a fixture.\npackage main\n\n//nolint:funlen\nfunc suppressed() {\n"+body+
		"}\n\n// reported is the unsuppressed sibling.\nfunc reported() {\n"+body+"}\n")
	t.Chdir(root)

	report, err := Analyze(Options{Paths: []string{"."}, Registry: rule.Defaults(), FailOn: finding.FailThresholdNone})
	if err != nil {
		t.Fatal(err)
	}
	lengthSymbols := []string{}
	rationaleLines := []int{}
	for _, item := range report.Findings {
		switch item.RuleID {
		case "size.function-length":
			lengthSymbols = append(lengthSymbols, item.Symbol)
		case "docs.suppression-without-rationale":
			rationaleLines = append(rationaleLines, item.Location.Line)
		}
	}
	if len(lengthSymbols) != 1 || lengthSymbols[0] != "reported" {
		t.Fatalf("function-length findings on %v, want only the unsuppressed sibling", lengthSymbols)
	}
	if len(rationaleLines) != 1 || rationaleLines[0] != 4 {
		t.Fatalf("rationale findings on lines %v, want the bare comment on line 4", rationaleLines)
	}
	var inline []SuppressionSummary
	for _, row := range report.Suppressions {
		if row.Source == SuppressionSourceInline {
			inline = append(inline, row)
		}
	}
	if len(inline) != 1 || inline[0].Rule != "size.function-length" || inline[0].Suppressed != 1 {
		t.Fatalf("inline rows = %#v, want one size.function-length row counting 1", inline)
	}
	if len(report.Suppressed) != 1 || report.Suppressed[0].Finding.Symbol != "suppressed" {
		t.Fatalf("suppressed findings = %#v, want the commented function kept for SARIF", report.Suppressed)
	}
}
