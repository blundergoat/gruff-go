// Package analysis tests run the Analyze pipeline end to end against small temporary projects.
//
// They cover baseline load diagnostics, repeat-run stability, exit-code thresholds, bounded deep scans and composite pruning.
// They also pin how changed-range filtering, diff mode and config paths.ignore decide which findings reach the report.
package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestAnalyzeMissingBaselineDoesNotMarkApplied checks that a baseline file which fails to load leaves Baseline.Applied false.
//
// SARIF marks a result baselineState:"new" only when a baseline was applied and that finding's BaselineStatus is "new".
// The load failure must still surface as a baseline-stage diagnostic, so the user learns the baseline was not applied.
func TestAnalyzeMissingBaselineDoesNotMarkApplied(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Chdir(root)
	report, err := Analyze(Options{
		Registry:     rule.Defaults(),
		FailOn:       finding.FailThresholdWarning,
		BaselinePath: "no-such-baseline.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Baseline.Applied {
		t.Fatal("Baseline.Applied = true after a failed load, want false")
	}
	hasBaselineDiagnostic := false
	for _, diagnostic := range report.Diagnostics {
		if diagnostic.Stage == "baseline" {
			hasBaselineDiagnostic = true
		}
	}
	if !hasBaselineDiagnostic {
		t.Fatalf("diagnostics = %#v, want a baseline-stage diagnostic", report.Diagnostics)
	}
}

// TestAnalyzeIsDeterministicExceptStartedAt checks that repeated scans have the same exit code and first scanned path.
// Only those two fields are compared; a failure means two scans of one unchanged project disagreed on one of them.
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
// One finding from a warning-severity rule under a warning fail threshold must make the scan exit 1, and that finding must carry a fingerprint.
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

// TestAnalyzeBoundedDeepScanRetainsTextRules checks that a file over the deep-scan budget loses AST-derived function evidence but stays scanned.
//
// With a one-line budget the text-level rule still fires and the function-declaration rule stays silent.
// The run must exit 0 with one bounded-deep-scan diagnostic that does not invalidate it, so the degradation is visible but not fatal.
func TestAnalyzeBoundedDeepScanRetainsTextRules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Chdir(root)
	registry, err := rule.NewRegistry([]rule.UnitRule{findingRule{}, functionDeclarationRule{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Analyze(Options{
		Registry:       registry,
		FailOn:         finding.FailThresholdNone,
		DeepScanBudget: DeepScanBudget{Enabled: true, MaxLines: 1, MaxBytes: 10_000, Override: "cli"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.ExitCode != 0 || report.Summary.FilesScanned != 1 {
		t.Fatalf("summary = %#v, want one analysed file and clean non-fatal exit", report.Summary)
	}
	if !containsRuleID(report.Findings, "size.file-length") || containsRuleID(report.Findings, "test.function-declaration") {
		t.Fatalf("findings = %#v, want text-level rule only", report.Findings)
	}
	if len(report.Diagnostics) != 1 || report.Diagnostics[0].DiagnosticType != "bounded-deep-scan" || report.Diagnostics[0].InvalidatesRun == nil || *report.Diagnostics[0].InvalidatesRun {
		t.Fatalf("diagnostics = %#v, want one visible non-fatal degradation", report.Diagnostics)
	}
}

// TestPruneOrphanedCompositesDropsCompositesWithoutSurvivingEvidence checks that pruneOrphanedComposites removes orphaned composites.
//
// A composite carries underlyingFingerprints metadata and is dropped and counted when none of those fingerprints survive the diff filter.
// Without this prune, --diff-base reports would keep composites even when the size or complexity evidence they composed was filtered out.
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

// TestAnalyzeChangedRangesUseEnclosingFunction checks symbol-scope filtering against a change on line 8, inside changed().
//
// The finding for changed() must stay, the finding for the untouched stable() must be suppressed, and the suppressed total must be 1.
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

// TestAnalyzeChangedScopeHunkExcludesSignatureFindings checks that hunk scope is line-exact.
// A finding on the function signature is dropped when only an inner line is in the changed range, unlike the function-wide symbol scope.
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

// TestAnalyzeExplicitIgnoredArgProducesNoFindings checks that config paths.ignore is authoritative for a file passed as an explicit argument.
//
// That is the coding-agent hook shape: the file must yield zero findings and appear in Skipped with source=config and the matching glob.
// A control run without the ignore proves findingRule fires on the same file, and the file must also be listed in IgnoredPaths.
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

// TestAnalyzeDirectoryWalkReportsIgnoredPaths checks that ordinary directory discovery fills the cross-port paths.ignoredPaths list.
// The config-ignored secret.go must appear in IgnoredPaths and have a source=config record in report.Paths.Skipped.
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

// TestAnalyzeDiffModeHonorsConfigIgnore checks that config paths.ignore stays authoritative in diff mode.
//
// A changed-ranges scan over an ignored file must produce zero findings and record the config skip.
// Otherwise a hook scoping to the agent's diff could surface a file the user excluded.
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

// TestAnalyzeIncludeIgnoredKeepsConfigIgnore checks that --include-ignored preserves config paths.ignore.
// It never overrides config paths.ignore: the ignored file must stay unscanned, config-skipped and listed in IgnoredPaths.
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

// TestAnalyzeDiffModeKeepsFullProjectContext checks that a changed-region scan parses the whole project, not just the changed files.
//
// Otherwise dead-code.unused-private-function would falsely flag a private helper in a changed file that an unchanged sibling still calls.
// The patch touches the helper's own line, so the symbol-scope filter would keep a false finding; parsing the unchanged caller prevents it.
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

// hasConfigSkip reports whether skipped holds an entry for path with source=config and the expected matched glob in pattern.
// It reports false when skipped is empty or no entry matches path, config and pattern.
func hasConfigSkip(skipped []SkippedPath, path, pattern string) bool {
	for _, item := range skipped {
		if item.Path == path && item.Source == "config" && item.Pattern == pattern {
			return true
		}
	}
	return false
}

// hasString reports whether values contains want; it reports false when values is empty.
func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// containsRuleID reports whether findings include a finding for id; it reports false when findings is empty.
func containsRuleID(findings []finding.Finding, id string) bool {
	for _, item := range findings {
		if item.RuleID == id {
			return true
		}
	}
	return false
}

// findingRule is a test rule that always emits one finding per unit.
// It borrows the size.file-length rule ID at warning severity, so its findings count toward a warning fail threshold.
type findingRule struct{}

// Definition returns the rule metadata used by the registry.
// The result is a fixed, default-enabled size.file-length definition with warning severity and high confidence.
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
// It returns a one-element slice whose finding carries unit.File.Path, line 1 and a fixed test message, so the result is never empty.
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
// The result is a fixed, default-enabled test.function-declaration definition with warning severity and high confidence.
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

// AnalyzeUnit emits one fingerprinted finding per function in unit, so changed-scope filtering can resolve the enclosing function.
//
// Each finding sits at the function's line and carries its name as Symbol.
// It returns one finding per entry of unit.Functions, in that order, and an empty non-nil slice when the unit has no functions.
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

// writeFile writes contents to the file rel under root, creating parent directories as needed.
// A failed directory or file write stops the test at once through t.Fatal.
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
