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
	"slices"
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// TestParseStdinDistinguishesEmptyChangesFromInvalidInput protects the result developers see after piping a patch into Gruff.
// An empty Git diff can pass. Unrelated text and unusable hunk headers must stop the changed-code scan.
func TestParseStdinDistinguishesEmptyChangesFromInvalidInput(t *testing.T) {
	const headers = "--- a/main.go\n+++ b/main.go\n"
	cases := []struct {
		name      string
		patch     string
		wantPaths []string
		wantError bool
	}{
		{name: "empty pipe"},
		{name: "file change", patch: headers + "@@ -1 +1 @@\n-old\n+new\n", wantPaths: []string{"main.go"}},
		{name: "rename", patch: "diff --git a/a.go b/b.go\nsimilarity index 100%\nrename from a.go\nrename to b.go\n"},
		{name: "deleted file", patch: "--- a/gone.go\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n"},
		{name: "unrelated text", patch: "git: could not read input\n", wantError: true},
		{name: "truncated headers", patch: headers, wantError: true},
		{name: "bad hunk header", patch: headers + "@@ missing range @@\n", wantError: true},
		{name: "range longer than patch", patch: headers + "@@ -1 +1,100 @@\n-old\n+new\n", wantError: true},
	}
	// Run valid and failing comparisons through the same entry point to protect the empty-input contract.
	for _, comparison := range cases {
		t.Run(comparison.name, func(t *testing.T) {
			changed, err := ParseStdin([]byte(comparison.patch))
			// A false success would let CI interpret an invalid comparison as an empty patch.
			if (err != nil) != comparison.wantError {
				t.Fatalf("ParseStdin error = %v, want error %t", err, comparison.wantError)
			}
			// A valid comparison must retain the source paths the user asked to check.
			if !slices.Equal(changed.ChangedFiles, comparison.wantPaths) {
				t.Fatalf("changed paths = %v, want %v", changed.ChangedFiles, comparison.wantPaths)
			}
		})
	}
}

// TestParseAndFilterChangedLines verifies hunk parsing and filtering against changed lines.
// It expects sorted a.go and b.go paths, one kept finding and two filtered findings.
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

// TestParseMarksNewFilesWholeFileChanged checks that a new-file diff retains a finding on line 99, beyond its added hunk.
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
// Without that anchor, a finding on line 3 would be suppressed; the test checks that it is retained.
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

// TestExplicitRangesApplyToFiles checks that explicit ranges are applied per file: a line inside a range counts as changed and one outside does not.
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

// TestFromGitRejectsLeadingDashBase blocks git option injection such as --output=<file> or --ext-diff.
func TestFromGitRejectsLeadingDashBase(t *testing.T) {
	root := t.TempDir()
	clobber := filepath.Join(root, "clobbered.txt")
	_, err := FromGit(context.Background(), root, "--output="+clobber, []string{"."})
	if err == nil {
		t.Fatal("expected error for leading-dash diff base")
	}
	if _, statErr := os.Stat(clobber); !os.IsNotExist(statErr) {
		t.Fatalf("git option injection created %s", clobber)
	}
}

// TestParseTracksHunkContextBlocksHeaderHijackAndStripsTimestamps pins -U3 context precision, "++ " body protection, diff -u timestamps, and CRLF.
func TestParseTracksHunkContextBlocksHeaderHijackAndStripsTimestamps(t *testing.T) {
	patch := "diff --git a/a.go b/a.go\r\n" +
		"--- a/a.go\t2026-11-25 00:00:00 +0000\r\n" +
		"+++ b/a.go\t2026-11-25 00:00:00 +0000\r\n" +
		"@@ -1,4 +1,5 @@\r\n" +
		" package p\r\n" +
		" func untouched() {}\r\n" +
		"+// ++ ../evil.go\r\n" +
		"+++ ../hijack.go\r\n" +
		" func end() {}\r\n" +
		"diff --git a/new.go b/new.go\r\n" +
		"--- /dev/null\r\n" +
		"+++ b/new.go\r\n" +
		"@@ -0,0 +1,1 @@\r\n" +
		"+package p\r\n"
	changed := Parse("stdin", []byte(patch))
	if _, hijacked := changed.LinesByFile["../hijack.go"]; hijacked {
		t.Fatalf("added +++ content hijacked currentFile: %#v", changed.ChangedFiles)
	}
	lines := changed.LinesByFile["a.go"]
	if _, ok := lines[3]; !ok {
		t.Fatalf("expected added line 3 in a.go, got %#v", lines)
	}
	if _, ok := lines[4]; !ok {
		t.Fatalf("expected added +++ line 4 in a.go, got %#v", lines)
	}
	if _, ctxMarked := lines[2]; ctxMarked {
		t.Fatalf("unchanged context line 2 must not be marked changed: %#v", lines)
	}
	if _, whole := changed.WholeFiles["new.go"]; !whole {
		t.Fatalf("CRLF new file new.go was not marked whole: %#v", changed.WholeFiles)
	}

	// Synthetic header-only hunks with trailing newlines must preserve every line in the declared new range.
	headerOnly := Parse("stdin", []byte("+++ b/only.go\n@@ -1,2 +1,2 @@\n"))
	if len(headerOnly.LinesByFile["only.go"]) != 2 {
		t.Fatalf("header-only hunk lines = %#v, want lines 1 and 2", headerOnly.LinesByFile["only.go"])
	}

	// Plain diff -u patches without "diff --git " must mark /dev/null files whole without leaking newFile into later files.
	plainDiff := "--- /dev/null\t2026-11-25 00:00:00 +0000\n" +
		"+++ b/added.go\t2026-11-25 00:00:00 +0000\n" +
		"@@ -0,0 +1,1 @@\n+package p\n" +
		"--- a/existing.go\t2026-11-25 00:00:00 +0000\n" +
		"+++ b/existing.go\t2026-11-25 00:00:00 +0000\n" +
		"@@ -1,1 +1,1 @@\n-old\n+new\n"
	plainChanged := Parse("stdin", []byte(plainDiff))
	if _, whole := plainChanged.WholeFiles["added.go"]; !whole {
		t.Fatalf("plain diff -u new file added.go was not marked whole: %#v", plainChanged.WholeFiles)
	}
	if _, whole := plainChanged.WholeFiles["existing.go"]; whole {
		t.Fatalf("plain diff -u leaked newFile flag into existing.go: %#v", plainChanged.WholeFiles)
	}
	if _, ok := plainChanged.LinesByFile["existing.go"][1]; !ok {
		t.Fatalf("plain diff -u existing.go lines = %#v, want line 1", plainChanged.LinesByFile["existing.go"])
	}
}

// TestFromModeWorkingTreeKeepsStagedLinesAlignedAfterUnstagedShift verifies working-tree diffs align shifted staged edits with disk lines.
func TestFromModeWorkingTreeKeepsStagedLinesAlignedAfterUnstagedShift(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "test@example.test")
	runGit(t, root, "config", "user.name", "test")
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	runGit(t, root, "add", "main.go")
	runGit(t, root, "commit", "-q", "-m", "initial")

	// Stage a change on line 4, then prepend 3 unstaged lines above it so disk line is now 7.
	writeFile(t, root, "main.go", "package main\n\nfunc main() {\n\tprintln(\"staged\")\n}\n")
	runGit(t, root, "add", "main.go")
	writeFile(t, root, "main.go", "// header 1\n// header 2\n// header 3\npackage main\n\nfunc main() {\n\tprintln(\"staged\")\n}\n")

	changed, err := FromMode(context.Background(), root, "working-tree", []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := changed.LinesByFile["main.go"][7]; !ok {
		t.Fatalf("changed lines = %#v, want shifted staged edit at disk line 7", changed.LinesByFile["main.go"])
	}
}

// TestParseAnchorsShiftedDeletionLinesAndMixedHunks verifies -U0 shifted deletion anchors, -U3 multi-edit deletions, and ./ path cleanup.
func TestParseAnchorsShiftedDeletionLinesAndMixedHunks(t *testing.T) {
	u0Delete := "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -4,1 +3,0 @@\n-// deleted doc\n"
	changed := Parse("HEAD", []byte(u0Delete))
	if _, ok := changed.LinesByFile["a.go"][4]; !ok {
		t.Fatalf("-U0 deletion lines = %#v, want shifted post-deletion line 4", changed.LinesByFile["a.go"])
	}

	u3Mixed := "--- ./main.go\n+++ ./main.go\n@@ -1,5 +1,4 @@\n package p\n-// deleted doc\n func Foo() {}\n func Mid() {}\n-// old\n+func Bar() {}\n"
	mixed := Parse("stdin", []byte(u3Mixed))
	lines := mixed.LinesByFile["main.go"]
	if _, ok := lines[2]; !ok {
		t.Fatalf("-U3 mixed hunk dropped deletion anchor at line 2: %#v", lines)
	}
	if _, ok := lines[4]; !ok {
		t.Fatalf("-U3 mixed hunk missed added line 4: %#v", lines)
	}
}

// TestFromGitHandlesMnemonicPrefixColorAndNonASCIIPaths ensures user git config cannot drop changed-region findings.
func TestFromGitHandlesMnemonicPrefixColorAndNonASCIIPaths(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "test@example.test")
	runGit(t, root, "config", "user.name", "test")
	runGit(t, root, "config", "diff.mnemonicPrefix", "true")
	runGit(t, root, "config", "color.diff", "always")
	writeFile(t, root, "café.go", "package main\n\nfunc main() {}\n")
	runGit(t, root, "add", "café.go")
	runGit(t, root, "commit", "-q", "-m", "initial")
	writeFile(t, root, "café.go", "package main\n\nfunc main() {\n\tprintln(\"hi\")\n}\n")

	changed, err := FromGit(context.Background(), root, "HEAD", []string{"."})
	if err != nil {
		t.Fatalf("FromGit error = %v", err)
	}
	if _, ok := changed.LinesByFile["café.go"][4]; !ok {
		t.Fatalf("changed lines = %#v, want café.go line 4", changed.LinesByFile)
	}
}

// TestParseStdinHandlesMnemonicQuotedPathsAndRejectsTruncatedHunks covers piped git patches with mnemonic/quoted headers and truncated hunks.
func TestParseStdinHandlesMnemonicQuotedPathsAndRejectsTruncatedHunks(t *testing.T) {
	mnemonic := "diff --git i/pkg/a.go w/pkg/a.go\n--- i/pkg/a.go\n+++ w/pkg/a.go\n@@ -1 +1 @@\n-old\n+new\n"
	changed, err := ParseStdin([]byte(mnemonic))
	if err != nil {
		t.Fatalf("ParseStdin(mnemonic) error = %v", err)
	}
	if _, ok := changed.LinesByFile["pkg/a.go"][1]; !ok {
		t.Fatalf("mnemonic changed lines = %#v, want pkg/a.go line 1", changed.LinesByFile)
	}

	// A --no-prefix patch for a real top-level w/ folder keeps its path, because both sides carry the same letter.
	noPrefix := "diff --git w/handler.go w/handler.go\n--- w/handler.go\n+++ w/handler.go\n@@ -1 +1 @@\n-old\n+new\n"
	npChanged, err := ParseStdin([]byte(noPrefix))
	if err != nil {
		t.Fatalf("ParseStdin(noPrefix) error = %v", err)
	}
	if _, ok := npChanged.LinesByFile["w/handler.go"][1]; !ok {
		t.Fatalf("no-prefix changed lines = %#v, want w/handler.go line 1", npChanged.LinesByFile)
	}
	// A new file under diff.mnemonicPrefix has a /dev/null source, so its c/ to w/ header decides the prefix.
	newFile := "diff --git c/pkg/n.go w/pkg/n.go\nnew file mode 100644\n--- /dev/null\n+++ w/pkg/n.go\n@@ -0,0 +1 @@\n+new\n"
	nfChanged, err := ParseStdin([]byte(newFile))
	if err != nil {
		t.Fatalf("ParseStdin(newFile) error = %v", err)
	}
	if _, ok := nfChanged.WholeFiles["pkg/n.go"]; !ok {
		t.Fatalf("mnemonic new-file changed lines = %#v, want pkg/n.go", nfChanged.LinesByFile)
	}

	quoted := "diff --git \"a/caf\\303\\251.go\" \"b/caf\\303\\251.go\"\n--- \"a/caf\\303\\251.go\"\n+++ \"b/caf\\303\\251.go\"\n@@ -1 +1 @@\n-old\n+new\n"
	qChanged, err := ParseStdin([]byte(quoted))
	if err != nil {
		t.Fatalf("ParseStdin(quoted) error = %v", err)
	}
	if _, ok := qChanged.LinesByFile["café.go"][1]; !ok {
		t.Fatalf("quoted changed lines = %#v, want café.go line 1", qChanged.LinesByFile)
	}

	truncated := "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -1 +1,2 @@\n-old\n+only-one\n"
	if _, err := ParseStdin([]byte(truncated)); err == nil {
		t.Fatal("expected ParseStdin to reject truncated hunk body")
	}
}

// TestFromModeStagedFailsClosedWhenStagedFileHasUnstagedEdits ensures --diff staged never checks stale disk bytes when index and disk diverge.
func TestFromModeStagedFailsClosedWhenStagedFileHasUnstagedEdits(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "test@example.test")
	runGit(t, root, "config", "user.name", "test")
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	runGit(t, root, "add", "main.go")
	runGit(t, root, "commit", "-q", "-m", "initial")

	writeFile(t, root, "main.go", "package main\n\nfunc main() {\n\tprintln(\"staged\")\n}\n")
	runGit(t, root, "add", "main.go")
	if _, err := FromMode(context.Background(), root, "staged", []string{"."}); err != nil {
		t.Fatalf("clean staged FromMode error = %v", err)
	}

	writeFile(t, root, "main.go", "package main\n\nfunc main() {\n\tprintln(\"unstaged-fix\")\n}\n")
	if _, err := FromMode(context.Background(), root, "staged", []string{"."}); err == nil {
		t.Fatal("expected FromMode(staged) to fail closed when staged file also has unstaged edits")
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
// It fails the test if directory creation or writing fails.
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
