// Package cli tests migrate-config upgrades from 0.5 configurations to the 0.6 schema.
//
// Each test verifies real legacy shapes: renaming minimumSeverity maps to failOn, stripping retired rules and
// preview allowlists, adding missing schemaVersion, preserving untouched settings, and refusing existing outputs.
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/rule"
)

const legacyV05ConfigFixture = `paths:
  ignore:
    - '.goat-flow/**'

minimumSeverity:
  summary: advisory

allowlists:
  acceptedAbbreviations:
    - HTTP
  secretPreviews: []

sensitiveData:
  previewAllowlist:
    - example

rules:
  complexity.cognitive:
    enabled: true
    severity: warning
    threshold: 25
  design.hotspot-file:
    enabled: true
    severity: warning
  security.sql-string-query:
    enabled: true
    severity: warning
  sensitive-data.high-entropy-string:
    enabled: true
    severity: warning
`

// TestMigrateConfigRewritesLegacyKeysAndRetiredRules checks dry-run and write paths on a 0.5-style config.
func TestMigrateConfigRewritesLegacyKeysAndRetiredRules(t *testing.T) {
	root := t.TempDir()
	srcPath := filepath.Join(root, "legacy.yaml")
	outPath := filepath.Join(root, "migrated.yaml")
	if err := os.WriteFile(srcPath, []byte(legacyV05ConfigFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	var dryOut, dryErr bytes.Buffer
	if code := Main([]string{"migrate-config", "--config", srcPath, "--dry-run"}, &dryOut, &dryErr); code != 0 {
		t.Fatalf("dry-run exit = %d, stderr = %s", code, dryErr.String())
	}
	for _, want := range []string{
		"minimumSeverity map renamed to failOn",
		"removed secretPreviews",
		"removed previewAllowlist",
		"removed design.hotspot-file",
		"removed security.sql-string-query",
		"removed sensitive-data.high-entropy-string",
		"schemaVersion added as " + config.SchemaVersion,
		"Dry run: nothing written.",
	} {
		if !strings.Contains(dryOut.String(), want) {
			t.Fatalf("dry-run output missing %q; got:\n%s", want, dryOut.String())
		}
	}

	var writeOut, writeErr bytes.Buffer
	if code := Main([]string{"migrate-config", "--config", srcPath, "--output", outPath}, &writeOut, &writeErr); code != 0 {
		t.Fatalf("write exit = %d, stderr = %s", code, writeErr.String())
	}
	migratedBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read migrated output: %v", err)
	}
	defaults := rule.Defaults()
	parsed, err := config.Parse(migratedBytes, defaults.Definitions())
	if err != nil {
		t.Fatalf("migrated config failed validation: %v\n%s", err, string(migratedBytes))
	}
	if parsed.FailOn["summary"] != "advisory" {
		t.Fatalf("FailOn[summary] = %q, want advisory", parsed.FailOn["summary"])
	}
	if len(parsed.Allowlists.AcceptedAbbreviations) != 1 || parsed.Allowlists.AcceptedAbbreviations[0] != "HTTP" {
		t.Fatalf("AcceptedAbbreviations = %#v, want [HTTP]", parsed.Allowlists.AcceptedAbbreviations)
	}

	// Running again to the same destination must fail rather than overwrite.
	var secondOut, secondErr bytes.Buffer
	if code := Main([]string{"migrate-config", "--config", srcPath, "--output", outPath}, &secondOut, &secondErr); code != 2 {
		t.Fatalf("existing-output exit = %d, want 2; stdout=%s stderr=%s", code, secondOut.String(), secondErr.String())
	}
}

// TestMigrateConfigReportsCurrentConfigWithoutChanges confirms an already-valid 0.6 config passes through unchanged.
func TestMigrateConfigReportsCurrentConfigWithoutChanges(t *testing.T) {
	root := t.TempDir()
	current := "schemaVersion: \"" + config.SchemaVersion + "\"\n\nfailOn:\n  summary: advisory\n"
	srcPath := filepath.Join(root, "current.yaml")
	if err := os.WriteFile(srcPath, []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	if code := Main([]string{"migrate-config", "--config", srcPath, "--dry-run"}, &out, &errBuf); code != 0 {
		t.Fatalf("current dry-run exit = %d, stderr = %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "is already current; no changes.") {
		t.Fatalf("expected already-current message; got:\n%s", out.String())
	}
}
