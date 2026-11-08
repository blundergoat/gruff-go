// Package analysis tests what users see when they select one Go file for scanning.
//
// Sibling package files may explain a selected file without adding their findings.
// These tests keep both the extra context and the selected-file boundary visible.
package analysis

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestAnalyzeExplicitFileUsesSiblingPackageContextForDeadCode proves an explicit-file scan gives project rules context from sibling files.
// A failure means gruff-go analyse decl.go falsely flags helper as dead code because its only caller lives in caller.go.
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

// TestAnalyzeExplicitFileUsesSiblingPackageCommentContext proves package-level doc rules can see comments carried by a sibling package file.
// A failure means scanning impl.go alone reports docs.package-comment even though doc.go already documents the package.
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

// TestAnalyzeExplicitFileSurfacesSiblingParseFailure proves a sibling pulled in only for package context still reports its parse failure.
// Otherwise a project rule can lose context and false-positive on the scanned file with no diagnostic explaining why.
func TestAnalyzeExplicitFileSurfacesSiblingParseFailure(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "caller.go", "package svc\n\nfunc Run() string {\n\treturn helper()\n}\n")
	writeFile(t, root, "broken.go", "package svc\n\nfunc helper() string {\n\treturn\n") // unterminated: fails to parse
	t.Chdir(root)

	report, err := Analyze(Options{
		Paths:    []string{"caller.go"},
		Registry: rule.Defaults(),
		FailOn:   finding.FailThresholdNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, diag := range report.Diagnostics {
		if diag.File == "broken.go" && diag.Stage == "parse" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a parse diagnostic for context-only sibling broken.go, got %#v", report.Diagnostics)
	}
}

// TestAnalyzeExplicitFileHidesContextOnlyFindings checks that scanning impl.go reports no findings from the unrequested sibling.go.
// A failure means gruff-go analyse impl.go reports findings, such as the exec.Command call, from sibling.go, a file the user never named.
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

// TestAnalyzeExplicitFileStillReportsMissingPackageComment proves a missing package comment is still reported, anchored to the requested file.
// This holds even when the alphabetically first package file, aaa.go here, is a context-only sibling, so the context feature does not hide it.
func TestAnalyzeExplicitFileStillReportsMissingPackageComment(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "aaa.go", "package svc\n\nfunc Helper() {}\n")
	writeFile(t, root, "zzz.go", "package svc\n\nfunc Run() {}\n")
	t.Chdir(root)

	report, err := Analyze(Options{
		Paths:    []string{"zzz.go"},
		Registry: rule.Defaults(),
		FailOn:   finding.FailThresholdNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range report.Findings {
		if item.RuleID != "docs.package-comment" {
			continue
		}
		found = true
		// Anchoring to aaa.go would put the finding on a file the user did not name, where it would be hidden as context-only.
		if item.File != "zzz.go" {
			t.Fatalf("package-comment finding should anchor to the requested file zzz.go, got %q", item.File)
		}
	}
	if !found {
		t.Fatalf("explicit scan of zzz.go should still report the package's missing comment, got %#v", report.Findings)
	}
}
