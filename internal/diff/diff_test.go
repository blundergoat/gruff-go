// Package diff tests cover patch parsing, changed-line filtering, and git invocation.
//
// They exercise both the in-process Parse path and the FromGit and FromMode paths, which call git in a temporary directory.
// A failure here means a run scoped to changed lines may keep findings outside the user's edit or drop findings inside it.
package diff

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestParseAndFilterChangedLines verifies hunk parsing and filtering against changed lines.
// A failure means a changed-lines run would list the wrong files or keep findings outside the edit.
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
	// The +2,2 hunk covers a.go lines 2 and 3, so only the line 2 finding stays; line 4 and c.go, a file outside the diff, are filtered.
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
// A failure means a file the diff removes, shown as +++ /dev/null, would still be listed as changed with nothing left to scan.
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

// TestParseMarksNewFilesWholeFileChanged checks that a new-file diff marks the
// entire file changed, so a finding on any line of it is retained.
func TestParseMarksNewFilesWholeFileChanged(t *testing.T) {
	changed := Parse("main", []byte(`diff --git a/new.go b/new.go
new file mode 100644
--- /dev/null
+++ b/new.go
@@ -0,0 +1,3 @@
+package main
+func main() {}
`))
	// Line 99 lies far past the hunk's added lines, so only whole-file marking can keep this finding.
	item := finding.Finding{RuleID: "r", File: "new.go", Location: &finding.Location{Line: 99}}
	result := Filter([]finding.Finding{item}, changed)
	if len(result.Findings) != 1 || result.FilteredFindings != 0 {
		t.Fatalf("result = %#v, want whole new file retained", result)
	}
}

// TestParseAnchorsDeletionOnlyHunk verifies a pure-deletion hunk in a still-present file records its anchor line.
//
// The hunk adds zero lines, so without the anchor the file's line map would hold no changed lines.
// That would silently suppress findings in the edited function; the anchor keeps its enclosing region in scope.
func TestParseAnchorsDeletionOnlyHunk(t *testing.T) {
	changed := Parse("main", []byte(`diff --git a/a.go b/a.go
--- a/a.go
+++ b/a.go
@@ -4,2 +3,0 @@
-removed one
-removed two
`))
	// The +3,0 header names new line 3, the line just before the two removed lines, as the anchor.
	if _, ok := changed.LinesByFile["a.go"][3]; !ok {
		t.Fatalf("changed lines = %#v, want deletion anchored at line 3", changed.LinesByFile["a.go"])
	}
	item := finding.Finding{RuleID: "r", File: "a.go", Location: &finding.Location{Line: 3}}
	result := Filter([]finding.Finding{item}, changed)
	if len(result.Findings) != 1 || result.FilteredFindings != 0 {
		t.Fatalf("result = %#v, want finding on the deletion anchor retained", result)
	}
}

// TestExplicitRangesApplyToFiles checks that explicit ranges are applied per file:
// a line inside a range counts as changed and one outside does not.
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
// It commits main.go, edits it without committing, and expects FromGit against HEAD to report the uncommitted line 4.
func TestFromGitReportsWorkingTreeBaseRef(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "test@example.test")
	runGit(t, root, "config", "user.name", "test")
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	runGit(t, root, "add", "main.go")
	runGit(t, root, "commit", "-q", "-m", "initial")
	writeFile(t, root, "main.go", "package main\n\nfunc main() {\n\tprintln(\"changed\")\n}\n")

	changed, err := FromGit(context.Background(), root, "HEAD", []string{"."})
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

// TestFromModeWorkingTreeIncludesUntrackedWholeFiles checks that working-tree mode counts an untracked file as wholly changed.
// Edits to tracked files are not enough; a failure means a file the user has not yet added to git would escape a working-tree run.
func TestFromModeWorkingTreeIncludesUntrackedWholeFiles(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "test@example.test")
	runGit(t, root, "config", "user.name", "test")
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	runGit(t, root, "add", "main.go")
	runGit(t, root, "commit", "-q", "-m", "initial")
	writeFile(t, root, "new.go", "package main\n\nfunc added() {}\n")

	changed, err := FromMode(context.Background(), root, "working-tree", []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := changed.WholeFiles["new.go"]; !ok {
		t.Fatalf("whole files = %#v, want new.go", changed.WholeFiles)
	}
}

// TestFromGitReportsNonGitDiagnostics ensures non-repo invocations return an error.
// A failure means FromGit on a directory that is not a git repository returns no error, leaving the user with no diagnostic.
func TestFromGitReportsNonGitDiagnostics(t *testing.T) {
	_, err := FromGit(context.Background(), t.TempDir(), "HEAD", []string{"."})
	if err == nil {
		t.Fatal("expected non-git error")
	}
}

// runGit executes a git command inside root and fails the test on errors.
// The args are passed to git unchanged as its arguments, and the failure message shows them with the error and the combined output.
func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	// A machine without git on PATH lands here, so the repository-building tests fail instead of skipping.
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
