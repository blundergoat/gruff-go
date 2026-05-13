package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/rule"
)

func TestRunReportsMissingPathAsDiagnostic(t *testing.T) {
	t.Chdir(t.TempDir())
	report, err := Run(Options{
		Paths:    []string{"missing.go"},
		FailOn:   finding.SeverityMedium,
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

func TestRunIsDeterministicExceptStartedAt(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Chdir(root)

	first, err := Run(Options{Registry: rule.Defaults(), FailOn: finding.SeverityMedium})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(Options{Registry: rule.Defaults(), FailOn: finding.SeverityMedium})
	if err != nil {
		t.Fatal(err)
	}
	if first.Summary.ExitCode != second.Summary.ExitCode || first.Paths.Scanned[0] != second.Paths.Scanned[0] {
		t.Fatalf("reports differ: %#v %#v", first, second)
	}
}

func TestRunExitsOneWhenFindingMeetsThreshold(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n")
	t.Chdir(root)
	registry, err := rule.NewRegistry([]rule.UnitRule{findingRule{}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	report, err := Run(Options{
		Registry: registry,
		FailOn:   finding.SeverityMedium,
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

type findingRule struct{}

func (findingRule) Definition() rule.Definition {
	return rule.Definition{
		ID:             "size.file-length",
		Title:          "File length",
		Pillar:         finding.PillarSize,
		Severity:       finding.SeverityMedium,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
	}
}

func (findingRule) AnalyzeUnit(unit parser.Unit, _ rule.Context) []finding.Finding {
	return []finding.Finding{{
		Message:  "test finding",
		File:     unit.File.Path,
		Location: &finding.Location{Line: 1},
	}}
}

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
