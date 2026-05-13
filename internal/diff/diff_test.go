package diff

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

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

func TestFromGitReportsNonGitDiagnostics(t *testing.T) {
	_, err := FromGit(t.TempDir(), "HEAD", []string{"."})
	if err == nil {
		t.Fatal("expected non-git error")
	}
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
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
