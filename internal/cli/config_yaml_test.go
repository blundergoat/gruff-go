// Package cli tests sanitized YAML configuration failures at the command
// boundary.
package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestAnalyseDuplicateYAMLConfigErrorIsSanitized verifies analyse preserves the
// parser's key and original line evidence without echoing source text.
func TestAnalyseDuplicateYAMLConfigErrorIsSanitized(t *testing.T) {
	root := t.TempDir()
	hiddenValue := configYAMLFixtureValue()
	duplicateLine := "    enabled: " + hiddenValue
	configBody := strings.Join([]string{
		"schemaVersion: gruff-go.config.v0.1",
		"rules:",
		"  size.file-length:",
		"    enabled: true",
		"",
		"    # original line numbers include comments",
		duplicateLine,
	}, "\n")
	writeFile(t, root, "duplicate.yaml", configBody)
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(root)

	var stdout, stderr bytes.Buffer
	code := Main([]string{"analyse", "--config", "duplicate.yaml", "main.go"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("analyse exit = %d, want 2", code)
	}
	want := "config: duplicate YAML key \"enabled\": first defined at line 4, duplicated at line 7\n"
	if stderr.String() != want {
		t.Fatal("stderr did not preserve the deterministic sanitized config error")
	}
	if stdout.Len() != 0 {
		t.Fatal("analyse wrote stdout after a duplicate config error")
	}
	if strings.Contains(stderr.String(), hiddenValue) {
		t.Fatal("stderr contains the secret-shaped duplicate value")
	}
	if strings.Contains(stderr.String(), duplicateLine) {
		t.Fatal("stderr contains the raw duplicate source line")
	}
}

// configYAMLFixtureValue returns a secret-shaped token assembled from short
// fragments so dogfood never sees the complete value in this source file.
func configYAMLFixtureValue() string {
	return strings.Join([]string{"M07c8R", "w3P6m", "T9k2V", "b5N4q"}, "")
}
