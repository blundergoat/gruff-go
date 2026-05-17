package source

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestMatcherNegationCannotReIncludeUnderExcludedDir(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "secrets/\n!secrets/public.txt\n",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("secrets/public.txt", false); !got {
		t.Fatalf("negation cannot re-include a file under an excluded directory")
	}
}

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

func TestMatcherEmptyFile(t *testing.T) {
	root := writeIgnoreTree(t, map[string]string{
		".gitignore": "",
	})
	m := NewMatcher(root)

	if got, _ := m.Match("anything.go", false); got {
		t.Fatalf("empty .gitignore must not match anything")
	}
}

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
