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

// TestDocsRulesPrecisionGuidanceMatchesRegistry keeps docs/rules.md and list-rules catalogue on the same reviewed recognition and mitigation text.
//
// A failure names a rule whose docs/rules.md section lacks one of its registry false-positive shapes or that shape's mitigation.
func TestDocsRulesPrecisionGuidanceMatchesRegistry(t *testing.T) {
	root := repoRootForTest(t)
	data, err := os.ReadFile(filepath.Join(root, "docs", "rules.md"))
	if err != nil {
		t.Fatal(err)
	}
	docs := string(data)
	registry := rule.Defaults()

	for _, definition := range registry.Definitions() {
		if len(definition.FalsePositiveShapes) == 0 {
			continue
		}
		heading := "### `" + definition.ID + "`"
		sectionStart := strings.Index(docs, heading)
		if sectionStart < 0 {
			t.Fatalf("docs/rules.md missing section for %s", definition.ID)
		}
		sectionEnd := strings.Index(docs[sectionStart+len(heading):], "\n### `")
		// The last rule section has no next heading, so it runs to the end of docs/rules.md.
		if sectionEnd < 0 {
			sectionEnd = len(docs)
		} else {
			sectionEnd += sectionStart + len(heading)
		}
		section := docs[sectionStart:sectionEnd]
		for _, knownShape := range definition.FalsePositiveShapes {
			if !strings.Contains(section, knownShape.Shape) || !strings.Contains(section, knownShape.Mitigation) {
				t.Errorf("docs/rules.md precision guidance drifted for %s", definition.ID)
			}
		}
	}
}

// repoRootForTest walks upward from the package test directory to locate files
// that live at repository root.
//
// It returns the first directory holding a go.mod file, starting at the working directory and moving up one parent at a time.
// When the working directory cannot be read or no ancestor holds go.mod, it stops the test through t.Fatal, so no empty path is returned.
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
		// Only the filesystem root is its own parent, so the walk found no go.mod anywhere above the test directory.
		if parent == dir {
			t.Fatal("could not find repository root from test working directory")
		}
		dir = parent
	}
}
