// Package cli tests cover the family's built-in test-path skip end to end.
// A test, fixture or example file holds sample credentials, so sensitive-data findings there are removed by path,
// but counted on every surface and never dropped in silence. gruff-go retired the entropy rule and with it the
// lockfile skip that existed only for that rule (precision-floor M19, FAMILY-CONTRACT.md section 13a).
package cli

import (
	"strings"
	"testing"
)

// lockfileSkipFixture returns a JSON document holding one digest-shaped token and one key-shaped identifier. Both are
// assembled from fragments, so this test file holds no complete secret-shaped literal for the dogfood scan to report.
func lockfileSkipFixture() string {
	token := strings.Join([]string{"q7Zx", "M2kP", "v9Lt", "B4nR", "w8Hs", "D3jF", "y6Gc", "T5mV", "a1Ue", "N0bK"}, "")
	key := "AKIA" + strings.Join([]string{"Q7R2", "M8N4", "P6T9", "V1X3"}, "")
	return "{\n  \"resolvedDigest\": \"" + token + "\",\n  \"accessKeyId\": \"" + key + "\"\n}\n"
}

// rulesByFile groups the reported rule IDs by the file each finding names.
func rulesByFile(payload map[string]any) map[string][]string {
	grouped := map[string][]string{}
	for _, item := range payload["findings"].([]any) {
		entry := item.(map[string]any)
		file := entry["file"].(string)
		grouped[file] = append(grouped[file], entry["ruleId"].(string))
	}
	return grouped
}

// TestTestPathSensitiveFindingsAreSkippedAndCounted verifies a key in test, fixture or example files is skipped and counted.
//
// Rows are one per rule and file.
// The same bytes in production code, and in `latest.json`, whose name only resembles a test, still report.
func TestTestPathSensitiveFindingsAreSkippedAndCounted(t *testing.T) {
	root := t.TempDir()
	body := lockfileSkipFixture()
	writeFile(t, root, "package-lock.json", body)
	writeFile(t, root, "Tests/Fixtures/keys.json", body)
	writeFile(t, root, "examples/demo.json", body)
	writeFile(t, root, "src/config.json", body)
	writeFile(t, root, "src/latest.json", body)
	// The AWS rule is off by default since precision-floor M19, so the fixture enables it.
	writeFile(t, root, ".gruff-go.yaml", "schemaVersion: gruff-go.config.v0.1\nrules:\n  sensitive-data.aws-access-key:\n    enabled: true\n")
	t.Chdir(root)

	payload := analyseJSONReport(t, "--no-baseline", "--fail-on", "none", ".")
	grouped := rulesByFile(payload)
	for _, file := range []string{"Tests/Fixtures/keys.json", "examples/demo.json"} {
		if rules := grouped[file]; len(rules) != 0 {
			t.Fatalf("%s still reports %v", file, rules)
		}
	}
	for _, file := range []string{"src/config.json", "src/latest.json"} {
		if !strings.Contains(strings.Join(grouped[file], ","), "sensitive-data.aws-access-key") {
			t.Fatalf("%s must still report its key; got %v", file, grouped[file])
		}
	}

	rows := payload["suppressions"].([]any)
	var testPathRows []map[string]any
	for index, item := range rows {
		row := item.(map[string]any)
		if row["source"] != "built-in" || int(row["index"].(float64)) != index {
			t.Fatalf("row %d = %v, want built-in rows numbered in order", index, row)
		}
		if row["reason"] == "Test, fixture and example files hold sample credentials, so sensitive-data rules skip them by path." {
			testPathRows = append(testPathRows, row)
		}
	}
	if len(testPathRows) != 2 {
		t.Fatalf("test-path rows = %d, want one per rule and file (2 files x 1 rule): %v", len(testPathRows), rows)
	}
	if first := testPathRows[0]["paths"].([]any)[0]; first != "Tests/Fixtures/keys.json" {
		t.Fatalf("test-path rows are ordered by path, then rule; first = %v", first)
	}
}
