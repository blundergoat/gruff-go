package analysis

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestAnalyzeExplicitFileUsesSiblingPackageContextForDeadCode proves an
// explicit-file scan still gives project rules enough same-package context to
// avoid false positives for declarations used from sibling files.
func TestAnalyzeExplicitFileUsesSiblingPackageContextForDeadCode(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "decl.go", "package svc\n\nfunc helper() string {\n\treturn \"ok\"\n}\n")
	writeFile(t, root, "caller.go", "package svc\n\nfunc Run() string {\n\treturn helper()\n}\n")
	t.Chdir(root)

	report, err := Analyze(Options{
		Paths:    []string{"decl.go"},
		Registry: rule.Defaults(),
		FailOn:   finding.FailThresholdNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if containsRuleID(report.Findings, "dead-code.unused-private-function") {
		t.Fatalf("explicit file scan falsely flagged sibling-used helper: %#v", report.Findings)
	}
}

// TestAnalyzeExplicitFileUsesSiblingPackageCommentContext proves package-level
// doc rules can see comments carried by a sibling package file.
func TestAnalyzeExplicitFileUsesSiblingPackageCommentContext(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "doc.go", "// Package svc explains the package.\npackage svc\n")
	writeFile(t, root, "impl.go", "package svc\n\nfunc Run() {}\n")
	t.Chdir(root)

	report, err := Analyze(Options{
		Paths:    []string{"impl.go"},
		Registry: rule.Defaults(),
		FailOn:   finding.FailThresholdNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if containsRuleID(report.Findings, "docs.package-comment") {
		t.Fatalf("explicit file scan missed sibling package doc: %#v", report.Findings)
	}
}

// TestAnalyzeExplicitFileHidesContextOnlyFindings proves sibling package files
// are context for project rules, not additional report targets.
func TestAnalyzeExplicitFileHidesContextOnlyFindings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "impl.go", "// Package svc explains the package.\npackage svc\n\nfunc Run() {}\n")
	writeFile(t, root, "sibling.go", "package svc\n\nimport \"os/exec\"\n\nfunc Dangerous() {\n\t_ = exec.Command(\"sh\", \"-c\", \"echo hi\")\n}\n")
	t.Chdir(root)

	report, err := Analyze(Options{
		Paths:    []string{"impl.go"},
		Registry: rule.Defaults(),
		FailOn:   finding.FailThresholdNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range report.Findings {
		if item.File == "sibling.go" {
			t.Fatalf("context-only sibling produced finding: %#v", report.Findings)
		}
	}
}
