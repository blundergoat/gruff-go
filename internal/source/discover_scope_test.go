// Package source tests the discovery-scope additions for dependency and workflow rules.
package source

import "testing"

// TestDiscoverGoModuleFilesAndGitHubMetadata verifies module files and committed
// GitHub control metadata remain analysable security surfaces.
func TestDiscoverGoModuleFilesAndGitHubMetadata(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.com/app\n\ngo 1.25.0\n")
	writeFile(t, root, "go.sum", "example.com/dep v1.0.0 h1:deadbeef=\n")
	writeFile(t, root, "main.go", "package main\n")
	writeFile(t, root, ".github/workflows/ci.yml", "name: ci\n")
	writeFile(t, root, ".github/dependabot.yml", "version: 2\n")

	result, err := Discover(Options{Root: root, Paths: []string{"."}})
	if err != nil {
		t.Fatal(err)
	}

	got := paths(result.Files)
	want := []string{".github/dependabot.yml", ".github/workflows/ci.yml", "go.mod", "go.sum", "main.go"}
	if !equal(got, want) {
		t.Fatalf("files = %#v, want %#v", got, want)
	}
	// The shared ignore engine keeps the same verdicts through CheckIgnore.
	opts := Options{Root: root}
	if d := CheckIgnore(root, ".github/workflows/ci.yml", false, opts); d.Ignored {
		t.Fatalf("workflow file should be analysable; got %#v", d)
	}
	if d := CheckIgnore(root, ".github/dependabot.yml", false, opts); d.Ignored {
		t.Fatalf("committed GitHub metadata should be analysable; got %#v", d)
	}
	if d := CheckIgnore(root, "go.mod", false, opts); d.Ignored {
		t.Fatalf("go.mod should be analysable; got %#v", d)
	}
}
