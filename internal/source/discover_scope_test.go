// Package source tests the discovery-scope additions for dependency and workflow rules.
package source

import "testing"

// TestDiscoverGoModuleFilesAndWorkflowCarveout verifies the discovery-scope
// additions that back the dependency and CI/workflow security rules: go.mod and
// go.sum classify as analysable text, the .github/workflows subtree is
// discovered, and non-workflow .github paths stay ignored as metadata.
func TestDiscoverGoModuleFilesAndWorkflowCarveout(t *testing.T) {
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
	want := []string{".github/workflows/ci.yml", "go.mod", "go.sum", "main.go"}
	if !equal(got, want) {
		t.Fatalf("files = %#v, want %#v", got, want)
	}
	if !contains(skippedReasons(result.Skipped), ".github/dependabot.yml:non-application-metadata") {
		t.Fatalf("non-workflow .github file should be skipped; got %#v", result.Skipped)
	}

	// The shared ignore engine keeps the same verdicts through CheckIgnore.
	opts := Options{Root: root}
	if d := CheckIgnore(root, ".github/workflows/ci.yml", false, opts); d.Ignored {
		t.Fatalf("workflow file should be analysable; got %#v", d)
	}
	if d := CheckIgnore(root, ".github/dependabot.yml", false, opts); !d.Ignored || d.Source != OriginDefault {
		t.Fatalf("non-workflow .github file should be default-ignored; got %#v", d)
	}
	if d := CheckIgnore(root, "go.mod", false, opts); d.Ignored {
		t.Fatalf("go.mod should be analysable; got %#v", d)
	}
}
