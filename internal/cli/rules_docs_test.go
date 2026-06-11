package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestDocsRulesReferenceCoversRegistry catches registry/docs drift when rule IDs
// are added or renamed without a matching per-rule reference section.
func TestDocsRulesReferenceCoversRegistry(t *testing.T) {
	root := repoRootForTest(t)
	data, err := os.ReadFile(filepath.Join(root, "docs", "rules.md"))
	if err != nil {
		t.Fatal(err)
	}
	docs := string(data)
	registry := rule.Defaults()
	missing := []string{}
	for _, definition := range registry.Definitions() {
		if !strings.Contains(docs, "### `"+definition.ID+"`") {
			missing = append(missing, definition.ID)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		t.Fatalf("docs/rules.md missing per-rule sections for: %s", strings.Join(missing, ", "))
	}
}

// repoRootForTest walks upward from the package test directory to locate files
// that live at repository root.
func repoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repository root from test working directory")
		}
		dir = parent
	}
}
