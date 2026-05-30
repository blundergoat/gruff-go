// Package diff tests cover patch parsing, changed-line filtering, and git invocation.
// They exercise both the in-process Parse path and the FromGit subprocess path.
package diff

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestParseAndFilterChangedLines verifies hunk parsing and filtering against changed lines.
func TestParseAndFilterChangedLines(t *testing.T) {
	changed := Parse("main", []byte(`diff --git a/a.go b/a.go
--- a/a.go
+++ b/a.go
@@ -1,0 +2,2 @@
+if a {}
+if b {}
diff --git a/b.go b/b.go
--- a/b.go
+++ b/b.go
@@ -9 +10 @@
+changed
`))
	if len(changed.ChangedFiles) != 2 || changed.ChangedFiles[0] != "a.go" || changed.ChangedFiles[1] != "b.go" {
		t.Fatalf("changed files = %#v, want sorted a.go/b.go", changed.ChangedFiles)
	}
	items := []finding.Finding{
		{RuleID: "r", File: "a.go", Location: &finding.Location{Line: 2}},
		{RuleID: "r", File: "a.go", Location: &finding.Location{Line: 4}},
		{RuleID: "r", File: "c.go", Location: &finding.Location{Line: 1}},
	}
	result := Filter(items, changed)
	if len(result.Findings) != 1 || result.FilteredFindings != 2 {
		t.Fatalf("result = %#v, want one kept and two filtered", result)
	}
}

// TestParseIgnoresDeletedOnlyFiles verifies fully deleted files yield no changed entries.
func TestParseIgnoresDeletedOnlyFiles(t *testing.T) {
	changed := Parse("main", []byte(`diff --git a/deleted.go b/deleted.go
--- a/deleted.go
+++ /dev/null
@@ -1 +0,0 @@
-package deleted
`))
	if len(changed.ChangedFiles) != 0 {
		t.Fatalf("changed files = %#v, want none for deleted-only diff", changed.ChangedFiles)
	}
}

func TestParseMarksNewFilesWholeFileChanged(t *testing.T) {
	changed := Parse("main", []byte(`diff --git a/new.go b/new.go
new file mode 100644
--- /dev/null
+++ b/new.go
@@ -0,0 +1,3 @@
+package main
+func main() {}
`))
	item := finding.Finding{RuleID: "r", File: "new.go", Location: &finding.Location{Line: 99}}
	result := Filter([]finding.Finding{item}, changed)
	if len(result.Findings) != 1 || result.FilteredFindings != 0 {
		t.Fatalf("result = %#v, want whole new file retained", result)
	}
}

func TestExplicitRangesApplyToFiles(t *testing.T) {
	changed, err := ExplicitRanges("explicit", "3-3,8-10", []string{"a.go"})
	if err != nil {
		t.Fatal(err)
	}
	if !RangeChanged(changed, "a.go", 9, 9) || RangeChanged(changed, "a.go", 4, 4) {
		t.Fatalf("changed ranges = %#v", changed.LinesByFile["a.go"])
	}
}

// TestFromGitReportsWorkingTreeBaseRef shells out to git and confirms changed line detection.
func TestFromGitReportsWorkingTreeBaseRef(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "test@example.test")
	runGit(t, root, "config", "user.name", "test")
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	runGit(t, root, "add", "main.go")
	runGit(t, root, "commit", "-q", "-m", "initial")
	writeFile(t, root, "main.go", "package main\n\nfunc main() {\n\tprintln(\"changed\")\n}\n")

	changed, err := FromGit(root, "HEAD", []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	if len(changed.ChangedFiles) != 1 || changed.ChangedFiles[0] != "main.go" {
		t.Fatalf("changed files = %#v, want main.go", changed.ChangedFiles)
	}
	if _, ok := changed.LinesByFile["main.go"][4]; !ok {
		t.Fatalf("changed lines = %#v, want line 4", changed.LinesByFile["main.go"])
	}
}

func TestFromModeWorkingTreeIncludesUntrackedWholeFiles(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "test@example.test")
	runGit(t, root, "config", "user.name", "test")
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	runGit(t, root, "add", "main.go")
	runGit(t, root, "commit", "-q", "-m", "initial")
	writeFile(t, root, "new.go", "package main\n\nfunc added() {}\n")

	changed, err := FromMode(root, "working-tree", []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := changed.WholeFiles["new.go"]; !ok {
		t.Fatalf("whole files = %#v, want new.go", changed.WholeFiles)
	}
}

// TestFromGitReportsNonGitDiagnostics ensures non-repo invocations return an error.
func TestFromGitReportsNonGitDiagnostics(t *testing.T) {
	_, err := FromGit(t.TempDir(), "HEAD", []string{"."})
	if err == nil {
		t.Fatal("expected non-git error")
	}
}

// runGit executes a git command inside root and fails the test on errors.
func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
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
