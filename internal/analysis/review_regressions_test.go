// Package analysis tests cover core pipeline regression scenarios verified during the 0.6.0 review.
//
// They protect Windows machinePath handling, strict inline-suppression parsing, gitignored sibling context isolation,
// and non-function declaration ordinal ranking in baseline matching.
package analysis

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/blundergoat/gruff-go/internal/baseline"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestMachinePathWrapsOutsideRootAndUsesLowercaseError ensures Windows drive paths fail with errOutsideProjectRoot and lowercase ST1005 text.
func TestMachinePathWrapsOutsideRootAndUsesLowercaseError(t *testing.T) {
	_, err := machinePath("/work/repo", `C:\other\baseline.json`)
	if err == nil {
		t.Fatal("expected error for Windows drive path outside POSIX root")
	}
	if !errors.Is(err, errOutsideProjectRoot) {
		t.Fatalf("err = %v, want errors.Is(err, errOutsideProjectRoot)", err)
	}
	if msg := err.Error(); msg != "" && unicode.IsUpper(rune(msg[0])) {
		t.Fatalf("error message %q starts uppercase; want lowercase ST1005 phrasing", msg)
	}
}

// TestInlineSuppressionsRejectProseWildcardsAndLeadingBlockComments blocks prose mentions, malformed #nosec lists, and leading block comments.
func TestInlineSuppressionsRejectProseWildcardsAndLeadingBlockComments(t *testing.T) {
	cases := []struct {
		name     string
		file     string
		source   string
		finding  finding.Finding
		suppress bool
	}{
		{
			name:     "colon unmapped gosec code does not wildcard",
			file:     "main.go",
			source:   "// #nosec: G304 -- explicit path\nrun()",
			finding:  inlineFinding("security.shell-command", finding.PillarSecurity, 2),
			suppress: false,
		},
		{
			name:     "lowercase gosec code does not wildcard",
			file:     "main.go",
			source:   "// #nosec g304\nrun()",
			finding:  inlineFinding("security.shell-command", finding.PillarSecurity, 2),
			suppress: false,
		},
		{
			name:     "mixed valid and malformed #nosec list fails closed",
			file:     "main.go",
			source:   "// #nosec G402, typo -- bad directive\nrun()",
			finding:  inlineFinding("security.tls-insecure-config", finding.PillarSecurity, 2),
			suppress: false,
		},
		{
			name:     "prose mentioning nosec does not suppress",
			file:     "main.go",
			source:   "// Removed #nosec after review; validate input first.\nrun()",
			finding:  inlineFinding("security.shell-command", finding.PillarSecurity, 2),
			suppress: false,
		},
		{
			name:     "prose mentioning nolint does not suppress",
			file:     "main.go",
			source:   "// Never add //nolint here.\nrun()",
			finding:  inlineFinding("security.shell-command", finding.PillarSecurity, 2),
			suppress: false,
		},
		{
			name:     "yaml prose mentioning nosec does not suppress",
			file:     ".github/workflows/ci.yml",
			source:   "# Do not use #nosec in workflow files.\n- uses: actions/checkout@v4",
			finding:  finding.Finding{RuleID: "security.github-actions-unpinned-action", File: ".github/workflows/ci.yml", Pillar: finding.PillarSecurity, Location: &finding.Location{Line: 2}},
			suppress: false,
		},
		{
			name:     "leading inline block comment covers only its own line",
			file:     "main.go",
			source:   "/* #nosec G204 -- safe fixed args */ safeRun()\nunsafeRun()",
			finding:  inlineFinding("security.shell-command", finding.PillarSecurity, 2),
			suppress: false,
		},
		{
			name:     "leading inline block comment still covers its own line",
			file:     "main.go",
			source:   "/* #nosec G204 -- safe fixed args */ safeRun()",
			finding:  inlineFinding("security.shell-command", finding.PillarSecurity, 1),
			suppress: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kept, _, suppressed := ApplyInlineSuppressions([]finding.Finding{tc.finding}, nil, map[string]string{tc.file: tc.source})
			if got := len(suppressed) == 1; got != tc.suppress {
				t.Fatalf("suppressed = %v, want %v (kept=%#v, suppressed=%#v)", got, tc.suppress, kept, suppressed)
			}
		})
	}
}

// TestExplicitFileScanSkipsGitignoredBrokenSibling ensures single-file scans respect .gitignore for package context siblings.
func TestExplicitFileScanSkipsGitignoredBrokenSibling(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gitignore", "scratch.go\n")
	writeFile(t, root, "pkg/main.go", "// Package pkg holds clean code.\npackage pkg\n\n// Run executes work.\nfunc Run() {}\n")
	writeFile(t, root, "pkg/scratch.go", "package pkg\nfunc broken( {\n")

	report, err := Analyze(Options{
		Root:     root,
		Paths:    []string{"pkg/main.go"},
		Registry: rule.Defaults(),
		FailOn:   finding.FailThresholdNone,
	})
	if err != nil {
		t.Fatalf("Analyze error = %v", err)
	}
	if len(report.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v, want 0 because scratch.go is gitignored", report.Diagnostics)
	}
	if report.Summary.ExitCode != 0 {
		t.Fatalf("exit = %d, want 0", report.Summary.ExitCode)
	}
}

// TestNonFunctionSymbolOrdinalsPreserveBaselinedSibling ensures clean earlier variable declarations reserve ordinal slots under baseline matching.
func TestNonFunctionSymbolOrdinalsPreserveBaselinedSibling(t *testing.T) {
	root := t.TempDir()
	shortBody := "\t\t_ = item\n"
	longBody := strings.Repeat("\t\t_ = item\n", 18)
	v1 := "// Package p tests non-function ordinals.\npackage p\n\n" +
		"// A runs a short loop over xs.\nfunc A(xs []int) {\n\tfor _, item := range xs {\n" + shortBody + "\t}\n}\n\n" +
		"// B runs a long loop over xs.\nfunc B(xs []int) {\n\tfor _, item := range xs {\n" + longBody + "\t}\n}\n"
	writeFile(t, root, "p.go", v1)

	cfg := rule.Config{Enabled: map[string]bool{"naming.contextual-generic": true}}
	reg, err := rule.DefaultsConfigured(cfg)
	if err != nil {
		t.Fatal(err)
	}
	firstReport, err := Analyze(Options{Root: root, Paths: []string{"."}, Registry: reg, FailOn: finding.FailThresholdNone})
	if err != nil {
		t.Fatal(err)
	}
	baseFile, err := baseline.FromFindings(firstReport.Findings)
	if err != nil {
		t.Fatal(err)
	}
	basePath := filepath.Join(root, "gruff-baseline.json")
	if err := baseline.Write(basePath, baseFile); err != nil {
		t.Fatal(err)
	}

	// Grow A's loop so A's item now fires too; B's baselined item must remain suppressed as #2 while A's item reports as new #1.
	v2 := "// Package p tests non-function ordinals.\npackage p\n\n" +
		"// A runs a long loop over xs.\nfunc A(xs []int) {\n\tfor _, item := range xs {\n" + longBody + "\t}\n}\n\n" +
		"// B runs a long loop over xs.\nfunc B(xs []int) {\n\tfor _, item := range xs {\n" + longBody + "\t}\n}\n"
	if err := os.WriteFile(filepath.Join(root, "p.go"), []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}

	secondReport, err := Analyze(Options{Root: root, Paths: []string{"."}, Registry: reg, BaselinePath: basePath, FailOn: finding.FailThresholdNone})
	if err != nil {
		t.Fatal(err)
	}
	if len(secondReport.Findings) != 1 || secondReport.Baseline.UnchangedFindings != 1 {
		t.Fatalf("findings=%d unchanged=%d, want 1 new (A) and 1 unchanged (B)", len(secondReport.Findings), secondReport.Baseline.UnchangedFindings)
	}
	if secondReport.Findings[0].Location == nil || secondReport.Findings[0].Location.Line > 10 {
		t.Fatalf("surviving finding at line %#v, want new finding in A near top of file", secondReport.Findings[0].Location)
	}
}

// TestSymbolScopeDiffKeepsCallableDocFindingsOnDocCommentEdit ensures doc-only edits remain inside the function's symbol scope.
func TestSymbolScopeDiffKeepsCallableDocFindingsOnDocCommentEdit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "p.go", "// Package p checks doc-only symbol scope.\npackage p\n\n// Compute scales input.\nfunc Compute(amount int, rate int) int {\n\treturn amount * rate\n}\n")

	report, err := Analyze(Options{
		Root:          root,
		Paths:         []string{"."},
		Registry:      rule.Defaults(),
		FailOn:        finding.FailThresholdNone,
		ChangedRanges: "4-4",
		ChangedScope:  "symbol",
	})
	if err != nil {
		t.Fatalf("Analyze error = %v", err)
	}
	foundParamDoc := false
	for _, item := range report.Findings {
		if item.RuleID == "docs.missing-param-doc" && item.Symbol == "Compute" {
			foundParamDoc = true
		}
	}
	if !foundParamDoc {
		t.Fatalf("findings = %#v, want docs.missing-param-doc on Compute when editing its doc comment line 4", report.Findings)
	}
}
