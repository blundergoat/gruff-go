// Package analysis tests exercise the Analyze pipeline end-to-end.
// They cover diagnostics, deterministic output, and exit-code thresholds.
package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestAnalyzeReportsMissingPathAsDiagnostic asserts missing inputs surface as discovery diagnostics.
func TestAnalyzeReportsMissingPathAsDiagnostic(t *testing.T) {
	t.Chdir(t.TempDir())
	report, err := Analyze(Options{
		Paths:    []string{"missing.go"},
		FailOn:   finding.FailThresholdWarning,
		Registry: rule.Defaults(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.ExitCode != 2 {
		t.Fatalf("exit code = %d, want 2", report.Summary.ExitCode)
	}
	if len(report.Diagnostics) != 1 || report.Diagnostics[0].Stage != "discovery" {
		t.Fatalf("diagnostics = %#v, want discovery diagnostic", report.Diagnostics)
	}
}

// TestAnalyzeIsDeterministicExceptStartedAt confirms repeated runs match aside from timestamps.
func TestAnalyzeIsDeterministicExceptStartedAt(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Chdir(root)

	first, err := Analyze(Options{Registry: rule.Defaults(), FailOn: finding.FailThresholdWarning})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Analyze(Options{Registry: rule.Defaults(), FailOn: finding.FailThresholdWarning})
	if err != nil {
		t.Fatal(err)
	}
	if first.Summary.ExitCode != second.Summary.ExitCode || first.Paths.Scanned[0] != second.Paths.Scanned[0] {
		t.Fatalf("reports differ: %#v %#v", first, second)
	}
}

// TestAnalyzeExitsOneWhenFindingMeetsThreshold checks the threshold-driven exit code.
func TestAnalyzeExitsOneWhenFindingMeetsThreshold(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n")
	t.Chdir(root)
	registry, err := rule.NewRegistry([]rule.UnitRule{findingRule{}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	report, err := Analyze(Options{
		Registry: registry,
		FailOn:   finding.FailThresholdWarning,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.ExitCode != 1 {
		t.Fatalf("exit code = %d, want 1", report.Summary.ExitCode)
	}
	if len(report.Findings) != 1 || report.Findings[0].Fingerprint == "" {
		t.Fatalf("findings = %#v, want one fingerprinted finding", report.Findings)
	}
}

// TestPruneOrphanedCompositesDropsCompositesWithoutSurvivingEvidence confirms
// that composite findings (carrying an underlyingFingerprints metadata slice)
// are dropped when none of their underlying fingerprints survive the diff
// filter. Without this prune, composites would stay in --diff-base reports
// even when the size/complexity evidence they composed has been filtered out.
func TestPruneOrphanedCompositesDropsCompositesWithoutSurvivingEvidence(t *testing.T) {
	survivingEvidence := finding.Finding{
		RuleID:      "size.function-length",
		File:        "hot.go",
		Symbol:      "Hot",
		Fingerprint: "ev-1",
		Location:    &finding.Location{Line: 10},
	}
	survivingComposite := finding.Finding{
		RuleID: "design.hotspot-file",
		File:   "hot.go",
		Symbol: "Hot",
		Metadata: map[string]any{
			"underlyingFingerprints": []string{"ev-1"},
		},
	}
	orphanComposite := finding.Finding{
		RuleID: "design.hotspot-file",
		File:   "cold.go",
		Symbol: "Cold",
		Metadata: map[string]any{
			"underlyingFingerprints": []string{"ev-cold-not-present"},
		},
	}

	kept, pruned := pruneOrphanedComposites([]finding.Finding{
		survivingEvidence,
		survivingComposite,
		orphanComposite,
	})

	if pruned != 1 {
		t.Fatalf("pruned = %d, want 1 orphan composite removed", pruned)
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %#v, want survivingEvidence and survivingComposite only", kept)
	}
	for _, item := range kept {
		if item.File == "cold.go" {
			t.Fatalf("orphan composite for cold.go should have been pruned; got %#v", item)
		}
	}
}

// TestAnalyzeChangedRangesUseEnclosingFunction checks that symbol-scope filtering
// keeps a finding when its enclosing function was changed, suppresses findings in
// untouched functions, and reports the suppressed total.
func TestAnalyzeChangedRangesUseEnclosingFunction(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", `package main

func stable() {
	println("old")
}

func changed() {
	println("new")
}
`)
	t.Chdir(root)
	registry, err := rule.NewRegistry([]rule.UnitRule{functionDeclarationRule{}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	report, err := Analyze(Options{
		Paths:         []string{"main.go"},
		Registry:      registry,
		FailOn:        finding.FailThresholdNone,
		ChangedRanges: "8-8",
		ChangedScope:  "symbol",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Symbol != "changed" {
		t.Fatalf("findings = %#v, want only changed function", report.Findings)
	}
	if report.SuppressedCount == nil || *report.SuppressedCount != 1 {
		t.Fatalf("suppressedCount = %#v, want 1", report.SuppressedCount)
	}
}

// TestAnalyzeChangedScopeHunkExcludesSignatureFindings checks that hunk scope is
// line-exact: a finding on the function signature is dropped when only an inner
// line is in the changed range, unlike the function-wide symbol scope.
func TestAnalyzeChangedScopeHunkExcludesSignatureFindings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", `package main

func changed() {
	println("new")
}
`)
	t.Chdir(root)
	registry, err := rule.NewRegistry([]rule.UnitRule{functionDeclarationRule{}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	report, err := Analyze(Options{
		Paths:         []string{"main.go"},
		Registry:      registry,
		FailOn:        finding.FailThresholdNone,
		ChangedRanges: "4-4",
		ChangedScope:  "hunk",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %#v, want hunk-only signature finding filtered", report.Findings)
	}
}

// TestAnalyzeExplicitIgnoredArgProducesNoFindings proves config paths.ignore is
// authoritative when the file is passed as an explicit argument (the coding-agent
// hook shape): the file yields zero findings and is reported in Skipped with
// source=config and the matching glob, even though findingRule would otherwise
// fire on it. Without the ignore, the same file produces a finding.
func TestAnalyzeExplicitIgnoredArgProducesNoFindings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "ignored/bad.go", "package ignored\n")
	t.Chdir(root)
	registry, err := rule.NewRegistry([]rule.UnitRule{findingRule{}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Control: with no ignore, the explicit file is scanned and flagged.
	control, err := Analyze(Options{Paths: []string{"ignored/bad.go"}, Registry: registry, FailOn: finding.FailThresholdNone})
	if err != nil {
		t.Fatal(err)
	}
	if len(control.Findings) == 0 {
		t.Fatalf("control run produced no findings; fixture cannot prove the ignore suppresses anything")
	}

	report, err := Analyze(Options{
		Paths:       []string{"ignored/bad.go"},
		Registry:    registry,
		FailOn:      finding.FailThresholdNone,
		IgnorePaths: []string{"ignored/**"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("explicit ignored-file arg produced findings = %#v, want none", report.Findings)
	}
	if !hasConfigSkip(report.Paths.Skipped, "ignored/bad.go", "ignored/**") {
		t.Fatalf("skipped = %#v, want ignored/bad.go with source=config pattern=ignored/**", report.Paths.Skipped)
	}
	if !hasString(report.Paths.IgnoredPaths, "ignored/bad.go") {
		t.Fatalf("ignoredPaths = %#v, want ignored/bad.go", report.Paths.IgnoredPaths)
	}
}

// TestAnalyzeDirectoryWalkReportsIgnoredPaths proves the cross-port
// paths.ignoredPaths list is populated from config paths.ignore during ordinary
// directory discovery, alongside the detailed paths.skipped object.
func TestAnalyzeDirectoryWalkReportsIgnoredPaths(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n")
	writeFile(t, root, "secret.go", "package secret\n")
	t.Chdir(root)
	registry, err := rule.NewRegistry([]rule.UnitRule{findingRule{}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	report, err := Analyze(Options{
		Paths:       []string{"."},
		Registry:    registry,
		FailOn:      finding.FailThresholdNone,
		IgnorePaths: []string{"secret.go"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasConfigSkip(report.Paths.Skipped, "secret.go", "secret.go") {
		t.Fatalf("skipped = %#v, want secret.go with source=config pattern=secret.go", report.Paths.Skipped)
	}
	if !hasString(report.Paths.IgnoredPaths, "secret.go") {
		t.Fatalf("ignoredPaths = %#v, want secret.go", report.Paths.IgnoredPaths)
	}
}

// TestAnalyzeDiffModeHonorsConfigIgnore proves config paths.ignore is
// authoritative in diff mode: a changed-ranges scan over an ignored file still
// produces zero findings and records the config skip, so a hook scoping to the
// agent's diff never surfaces an excluded file.
func TestAnalyzeDiffModeHonorsConfigIgnore(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "ignored/bad.go", "package ignored\n")
	t.Chdir(root)
	registry, err := rule.NewRegistry([]rule.UnitRule{findingRule{}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	report, err := Analyze(Options{
		Paths:         []string{"ignored/bad.go"},
		Registry:      registry,
		FailOn:        finding.FailThresholdNone,
		IgnorePaths:   []string{"ignored/**"},
		ChangedRanges: "1-10",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("diff-mode scan of an ignored file produced findings = %#v, want none", report.Findings)
	}
	if !hasConfigSkip(report.Paths.Skipped, "ignored/bad.go", "ignored/**") {
		t.Fatalf("skipped = %#v, want ignored/bad.go with source=config pattern=ignored/**", report.Paths.Skipped)
	}
	if !hasString(report.Paths.IgnoredPaths, "ignored/bad.go") {
		t.Fatalf("ignoredPaths = %#v, want ignored/bad.go", report.Paths.IgnoredPaths)
	}
}

// TestAnalyzeIncludeIgnoredKeepsConfigIgnore proves --include-ignored opts into
// git/default ignores only and never overrides config paths.ignore: the ignored
// file stays unscanned and config-skipped.
func TestAnalyzeIncludeIgnoredKeepsConfigIgnore(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "ignored/bad.go", "package ignored\n")
	t.Chdir(root)
	registry, err := rule.NewRegistry([]rule.UnitRule{findingRule{}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	report, err := Analyze(Options{
		Paths:          []string{"ignored/bad.go"},
		Registry:       registry,
		FailOn:         finding.FailThresholdNone,
		IgnorePaths:    []string{"ignored/**"},
		IncludeIgnored: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("--include-ignored overrode config paths.ignore: findings = %#v, want none", report.Findings)
	}
	if !hasConfigSkip(report.Paths.Skipped, "ignored/bad.go", "ignored/**") {
		t.Fatalf("skipped = %#v, want config skip preserved under --include-ignored", report.Paths.Skipped)
	}
	if !hasString(report.Paths.IgnoredPaths, "ignored/bad.go") {
		t.Fatalf("ignoredPaths = %#v, want ignored/bad.go", report.Paths.IgnoredPaths)
	}
}

// TestAnalyzeDiffModeKeepsFullProjectContext proves a changed-region scan parses the
// whole project, not just the changed files, so a project-level rule
// (dead-code.unused-private-function) does not falsely flag a private function in a
// changed file that an unchanged sibling still calls. The patch touches the helper's
// own line, so a false finding would survive the symbol-scope filter; the scan stays
// clean only because the unchanged caller is still parsed for cross-file resolution.
func TestAnalyzeDiffModeKeepsFullProjectContext(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "used.go", "package svc\n\nfunc helper() string {\n\treturn \"ok\"\n}\n")
	writeFile(t, root, "caller.go", "package svc\n\n// Run keeps helper reachable from an unchanged sibling file.\nfunc Run() string {\n\treturn helper()\n}\n")
	t.Chdir(root)

	patch := "diff --git a/used.go b/used.go\n--- a/used.go\n+++ b/used.go\n@@ -3 +3 @@\n-func helper() string {\n+func helper() string { // touched\n"
	report, err := Analyze(Options{
		Registry:  rule.Defaults(),
		FailOn:    finding.FailThresholdWarning,
		DiffMode:  "-",
		DiffPatch: []byte(patch),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Diff.Enabled {
		t.Fatal("expected diff mode to be enabled for the stdin patch")
	}
	if len(report.Paths.Scanned) != 2 {
		t.Fatalf("diff scan parsed %d files, want 2 (full project context): %#v", len(report.Paths.Scanned), report.Paths.Scanned)
	}
	for _, item := range report.Findings {
		if item.RuleID == "dead-code.unused-private-function" {
			t.Fatalf("diff scan falsely flagged a cross-file-used private function: %#v", report.Findings)
		}
	}
}

// hasConfigSkip reports whether skipped contains path with source=config and the
// expected matched glob.
func hasConfigSkip(skipped []SkippedPath, path, pattern string) bool {
	for _, item := range skipped {
		if item.Path == path && item.Source == "config" && item.Pattern == pattern {
			return true
		}
	}
	return false
}

// hasString reports whether values contains want.
func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// findingRule is a test rule that always emits one finding per unit.
type findingRule struct{}

// Definition returns the rule metadata used by the registry.
func (findingRule) Definition() rule.Definition {
	return rule.Definition{
		ID:             "size.file-length",
		Title:          "File length",
		Pillar:         finding.PillarSize,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
	}
}

// AnalyzeUnit emits a single fixed finding for the given unit.
func (findingRule) AnalyzeUnit(unit parser.Unit, _ rule.Context) []finding.Finding {
	return []finding.Finding{{
		Message:  "test finding",
		File:     unit.File.Path,
		Location: &finding.Location{Line: 1},
	}}
}

// functionDeclarationRule is a test rule that emits one finding per function
// declaration, used to exercise symbol-scope changed-region filtering.
type functionDeclarationRule struct{}

// Definition returns this test rule's metadata used by the registry.
func (functionDeclarationRule) Definition() rule.Definition {
	return rule.Definition{
		ID:             "test.function-declaration",
		Title:          "Function declaration",
		Pillar:         finding.PillarMaintain,
		Severity:       finding.SeverityWarning,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
	}
}

// AnalyzeUnit emits one fingerprinted finding per function in the unit, located at
// the function's line and carrying its name as Symbol, so changed-scope filtering
// can resolve the enclosing function.
func (functionDeclarationRule) AnalyzeUnit(unit parser.Unit, _ rule.Context) []finding.Finding {
	findings := []finding.Finding{}
	for _, fn := range unit.Functions {
		findings = append(findings, finding.Finding{
			RuleID:   "test.function-declaration",
			Message:  "test finding",
			File:     unit.File.Path,
			Location: &finding.Location{Line: fn.Line},
			Symbol:   fn.Name,
			Severity: finding.SeverityWarning,
		}.WithFingerprint())
	}
	return findings
}

// writeFile writes contents to root/rel, creating parent directories as needed.
func writeFile(t *testing.T, root, rel, contents string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
