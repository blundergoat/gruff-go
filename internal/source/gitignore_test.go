// Package source gitignore tests cover pattern semantics for the Matcher.
// They write temp .gitignore trees and assert ignore decisions for varied paths.
package source

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMatcherSimplePattern verifies basic glob matching against gitignore patterns.
func TestMatcherSimplePattern(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "*.log\n",
	})
	m := NewMatcher(root)

	cases := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{"foo.log", false, true},
		{"deep/bar.log", false, true},
		{"foo.go", false, false},
		{"deep/foo.go", false, false},
	}
	for _, tc := range cases {
		got, _ := m.Match(tc.path, tc.isDir)
		if got != tc.want {
			t.Fatalf("Match(%q, %v) = %v, want %v", tc.path, tc.isDir, got, tc.want)
		}
	}
}

// TestMatcherAnchoredPattern verifies that leading-slash patterns anchor to the root.
func TestMatcherAnchoredPattern(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "/build\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("build", true); !got {
		t.Fatalf("root-level build should be matched")
	}
	if got, _ := m.Match("pkg/build", true); got {
		t.Fatalf("nested build should not be matched by anchored /build")
	}
}

// TestMatcherDirectoryOnly verifies that trailing-slash patterns match directories only.
func TestMatcherDirectoryOnly(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "logs/\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("logs", true); !got {
		t.Fatalf("logs/ should match directory logs")
	}
	if got, _ := m.Match("logs", false); got {
		t.Fatalf("logs/ should not match a file named logs")
	}
	if got, _ := m.Match("logs/today.txt", false); !got {
		t.Fatalf("file inside matched dir should be reported as ignored")
	}
}

// TestMatcherNegation verifies bang-prefixed negation rules re-include matched paths.
func TestMatcherNegation(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "bin/*\n!bin/keep\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("bin/scratch", false); !got {
		t.Fatalf("bin/scratch should be ignored")
	}
	if got, _ := m.Match("bin/keep", false); got {
		t.Fatalf("bin/keep should be re-included by negation")
	}
}

// TestMatcherNegationReincludesDirectoryDescendants verifies directory negation cascades to children.
func TestMatcherNegationReincludesDirectoryDescendants(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "bin/*\n!bin/keep/\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("bin/scratch/file.go", false); !got {
		t.Fatalf("bin/scratch/file.go should be ignored through matched ancestor")
	}
	if got, _ := m.Match("bin/keep/file.go", false); got {
		t.Fatalf("bin/keep/file.go should inherit the re-included directory")
	}
}

// TestMatcherNegationCannotReIncludeUnderExcludedDir matches git's negation precedence rules.
func TestMatcherNegationCannotReIncludeUnderExcludedDir(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "secrets/\n!secrets/public.txt\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("secrets/public.txt", false); !got {
		t.Fatalf("negation cannot re-include a file under an excluded directory")
	}
}

// TestMatcherDoubleStar verifies inner double-star patterns match across directory levels.
func TestMatcherDoubleStar(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "a/**/b\n",
	})
	m := NewMatcher(root)

	cases := []struct {
		path string
		want bool
	}{
		{"a/b", true},
		{"a/x/b", true},
		{"a/x/y/b", true},
		{"a/c", false},
		{"b/a/b", false},
	}
	for _, tc := range cases {
		got, _ := m.Match(tc.path, false)
		if got != tc.want {
			t.Fatalf("Match(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestMatcherTrailingDoubleStar verifies trailing double-star matches all descendants.
func TestMatcherTrailingDoubleStar(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "vendor/**\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("vendor/foo.go", false); !got {
		t.Fatalf("vendor/foo.go should be matched by vendor/**")
	}
	if got, _ := m.Match("vendor/sub/dir/x", false); !got {
		t.Fatalf("vendor/sub/dir/x should be matched by vendor/**")
	}
}

// TestMatcherTrailingDoubleStarDoesNotMatchParentDir verifies that "foo/**"
// targets descendants of foo and not foo itself, matching git's semantics. The
// regression: a terminal ** branch used to short-circuit to true, which made
// "!foo/a" negations fail because the ancestor walk re-ignored foo.
func TestMatcherTrailingDoubleStarDoesNotMatchParentDir(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "foo/**\n!foo/a\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("foo", true); got {
		t.Fatalf("foo itself should not be matched by foo/**")
	}
	if got, _ := m.Match("foo/b", false); !got {
		t.Fatalf("foo/b should be matched by foo/**")
	}
	if got, _ := m.Match("foo/a", false); got {
		t.Fatalf("foo/a should be re-included by !foo/a (was being re-ignored via the foo ancestor)")
	}
	if got, _ := m.Match("foo/sub/c", false); !got {
		t.Fatalf("foo/sub/c should be matched by foo/** at depth")
	}
}

// TestMatcherCommentsAndBlankLines verifies comments and blank lines are skipped during parsing.
func TestMatcherCommentsAndBlankLines(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "# leading comment\n\n*.tmp\n   \n#trailing comment\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("scratch.tmp", false); !got {
		t.Fatalf("scratch.tmp should match *.tmp despite surrounding comments and blanks")
	}
	if got, _ := m.Match("scratch.go", false); got {
		t.Fatalf("comment lines must not be treated as patterns")
	}
}

// TestMatcherEscapedTrailingWhitespace confirms backslash-escaped trailing spaces are preserved.
func TestMatcherEscapedTrailingWhitespace(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "name\\ \n*.log\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("name ", false); !got {
		t.Fatalf("escaped trailing space should be part of the pattern")
	}
	if got, _ := m.Match("name", false); got {
		t.Fatalf("escaped trailing space should not match name without the space")
	}
	if got, _ := m.Match("debug.log", false); !got {
		t.Fatalf("later rules should still apply after escaped trailing whitespace")
	}
}

// TestMatcherNestedOverride verifies nested .gitignore files override parent patterns.
func TestMatcherNestedOverride(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore":           "*.log\n",
		"pkg/.gitignore":       "!keep.log\n",
		"pkg/other/.gitignore": "*.tmp\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("a/foo.log", false); !got {
		t.Fatalf("root *.log should ignore a/foo.log")
	}
	if got, _ := m.Match("pkg/foo.log", false); !got {
		t.Fatalf("pkg/foo.log should remain excluded by root *.log; nested !keep.log does not re-include foo.log")
	}
	if got, _ := m.Match("pkg/keep.log", false); got {
		t.Fatalf("nested negation should re-include pkg/keep.log")
	}
	if got, _ := m.Match("pkg/other/scratch.tmp", false); !got {
		t.Fatalf("nested *.tmp should ignore pkg/other/scratch.tmp")
	}
}

// TestMatcherNestedIgnoreWithoutRoot verifies nested .gitignore files still
// apply when the discovery root has no .gitignore of its own.
func TestMatcherNestedIgnoreWithoutRoot(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		"pkg/.gitignore": "*.tmp\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("pkg/scratch.tmp", false); !got {
		t.Fatalf("nested .gitignore should ignore pkg/scratch.tmp")
	}
	if got, _ := m.Match("pkg/scratch.go", false); got {
		t.Fatalf("nested .gitignore should not ignore pkg/scratch.go")
	}
}

// TestMatcherNestedParseErrorWithoutRoot verifies the fast path still loads
// nested .gitignore files so parse diagnostics are not lost.
func TestMatcherNestedParseErrorWithoutRoot(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		"pkg/.gitignore": "[bad\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("pkg/main.go", false); got {
		t.Fatalf("malformed nested .gitignore should not ignore pkg/main.go")
	}
	errs := m.ParseErrors()
	if len(errs) != 1 || errs[0] != "pkg/.gitignore" {
		t.Fatalf("ParseErrors = %#v, want [pkg/.gitignore]", errs)
	}
}

// TestMatcherEmptyFile verifies an empty .gitignore matches nothing.
func TestMatcherEmptyFile(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("anything.go", false); got {
		t.Fatalf("empty .gitignore must not match anything")
	}
}

// TestMatcherMalformedPatternSkipsFile verifies malformed .gitignore files report parse errors.
func TestMatcherMalformedPatternSkipsFile(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "*.log\n[bad\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("foo.log", false); got {
		t.Fatalf("malformed .gitignore should be ignored wholesale; *.log must not apply")
	}
	errs := m.ParseErrors()
	if len(errs) != 1 || errs[0] != ".gitignore" {
		t.Fatalf("ParseErrors = %#v, want [.gitignore]", errs)
	}
}

// TestMatcherNoGitignore verifies a missing .gitignore matches nothing without errors.
func TestMatcherNoGitignore(t *testing.T) {
	root := t.TempDir()
	m := NewMatcher(root)

	if got, _ := m.Match("anything.go", false); got {
		t.Fatalf("matcher with no .gitignore must not match")
	}
	if errs := m.ParseErrors(); len(errs) != 0 {
		t.Fatalf("ParseErrors = %#v, want empty", errs)
	}
}

// TestMatcherCRLFLineEndings verifies CRLF-terminated rules are parsed correctly.
func TestMatcherCRLFLineEndings(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "*.log\r\nbuild/\r\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("foo.log", false); !got {
		t.Fatalf("CRLF-terminated rule should still apply")
	}
	if got, _ := m.Match("build", true); !got {
		t.Fatalf("CRLF-terminated directory rule should still apply")
	}
}

// TestMatcherSource verifies Match reports the originating .gitignore file path.
func TestMatcherSource(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore":     "*.log\n",
		"pkg/.gitignore": "!keep.log\n",
	})
	m := NewMatcher(root)

	_, source := m.Match("a/foo.log", false)
	if source != ".gitignore" {
		t.Fatalf("source for a/foo.log = %q, want .gitignore", source)
	}
	_, source = m.Match("pkg/keep.log", false)
	if source != "pkg/.gitignore" {
		t.Fatalf("source for pkg/keep.log = %q, want pkg/.gitignore", source)
	}
}

// writeIgnoreTree materialises a temporary directory tree with the supplied files.
func writeIgnoreTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, contents := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
