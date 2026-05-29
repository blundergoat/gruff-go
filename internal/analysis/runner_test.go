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
		RuleID: "design.god-function",
		File:   "hot.go",
		Symbol: "Hot",
		Metadata: map[string]any{
			"underlyingFingerprints": []string{"ev-1"},
		},
	}
	orphanComposite := finding.Finding{
		RuleID: "design.god-function",
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

type functionDeclarationRule struct{}

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
