package source

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile writes contents to the file rel under root, creating parent directories as needed, so a test can lay out a fixture tree.
// A directory or write failure stops the test through t.Fatal, which points at the fixture setup, not the code under test.
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

// paths returns each discovered file's display path, which can be absolute for a file outside the discovery root.
// Each entry is the Path field of the matching element of files, in input order; an empty files slice gives an empty, non-nil slice.
func paths(files []File) []string {
	out := make([]string, 0, len(files))
	for _, file := range files {
		out = append(out, file.Path)
	}
	return out
}

// skippedReasons formats skipped entries as "path:reason" strings for assertions.
//
// It returns one string per element of skipped, in input order, each joining Path and Reason with a colon.
// An empty skipped slice gives an empty, non-nil result.
func skippedReasons(skipped []SkippedPath) []string {
	out := make([]string, 0, len(skipped))
	for _, item := range skipped {
		out = append(out, item.Path+":"+item.Reason)
	}
	return out
}

// equal reports whether two string slices have identical contents in order.
// It reports false when a and b differ in length or in any element at the same index, so two empty or nil slices are equal.
func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// contains reports whether the slice includes the given value.
// It checks each element of values for exact equality with value and reports false when none matches, including when values is nil or empty.
func contains(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}
