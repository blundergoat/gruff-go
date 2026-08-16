package source

import (
	"os"
	"path/filepath"
	"testing"
)

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

// paths returns the relative path of each discovered file.
func paths(files []File) []string {
	out := make([]string, 0, len(files))
	for _, file := range files {
		out = append(out, file.Path)
	}
	return out
}

// skippedReasons formats skipped entries as "path:reason" strings for assertions.
func skippedReasons(skipped []SkippedPath) []string {
	out := make([]string, 0, len(skipped))
	for _, item := range skipped {
		out = append(out, item.Path+":"+item.Reason)
	}
	return out
}

// equal reports whether two string slices have identical contents in order.
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
func contains(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}
