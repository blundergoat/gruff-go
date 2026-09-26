// Package cli tests cover the family's built-in lockfile skip end to end.
// A package-manager lockfile carries thousands of published integrity digests, so the entropy rule's findings there
// are removed by file name - but counted on every surface, never dropped in silence, and only for that one rule: a
// credential pasted into a lockfile is still reported.
package cli

import (
	"bytes"
	"encoding/json"
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

// TestLockfileEntropyFindingsAreSkippedByNameAndCounted verifies a nested lockfile loses only its entropy findings,
// that its byte-identical twin under another name keeps them, and that the skip is published as a built-in audit row.
func TestLockfileEntropyFindingsAreSkippedByNameAndCounted(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "web/package-lock.json", lockfileSkipFixture())
	writeFile(t, root, "web/other.json", lockfileSkipFixture())
	t.Chdir(root)

	payload := analyseJSONReport(t, "--no-config", "--no-baseline", "--fail-on", "none", ".")
	grouped := rulesByFile(payload)

	if got := strings.Join(grouped["web/other.json"], ","); !strings.Contains(got, "sensitive-data.high-entropy-string") {
		t.Fatalf("the twin must still report the entropy rule, or this test proves nothing; got %q", got)
	}
	lockfileRules := strings.Join(grouped["web/package-lock.json"], ",")
	if strings.Contains(lockfileRules, "sensitive-data.high-entropy-string") {
		t.Fatalf("the lockfile still reports the entropy rule: %q", lockfileRules)
	}
	if !strings.Contains(lockfileRules, "sensitive-data.aws-access-key") {
		t.Fatalf("a credential in a lockfile must still report; got %q", lockfileRules)
	}

	suppressions := payload["suppressions"].([]any)
	if len(suppressions) != 1 {
		t.Fatalf("suppressions = %d rows, want 1 built-in row", len(suppressions))
	}
	row := suppressions[0].(map[string]any)
	if row["source"] != "built-in" || row["rule"] != "sensitive-data.high-entropy-string" {
		t.Fatalf("audit row = %v, want the built-in entropy row", row)
	}
	if paths := row["paths"].([]any); len(paths) != 1 || paths[0] != "web/package-lock.json" {
		t.Fatalf("audit paths = %v, want [web/package-lock.json]", row["paths"])
	}
	if row["suppressed"].(float64) < 1 {
		t.Fatalf("audit suppressed = %v, want at least 1", row["suppressed"])
	}
}

// TestLockfileSkipIsCountedOnTextSummaryAndHook verifies the three other surfaces that filter also say so.
func TestLockfileSkipIsCountedOnTextSummaryAndHook(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package-lock.json", lockfileSkipFixture())
	t.Chdir(root)

	for _, command := range []string{"analyse", "summary"} {
		var stdout, stderr bytes.Buffer
		if code := Main([]string{command, "--no-config", "--format", "text", "."}, &stdout, &stderr); code == 2 {
			t.Fatalf("%s exited 2: %s", command, stderr.String())
		}
		if !strings.Contains(stdout.String(), "builtInLockfile[package-lock.json] sensitive-data.high-entropy-string: ") {
			t.Fatalf("%s text does not count the built-in skip:\n%s", command, stdout.String())
		}
	}

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"hook", "--no-config", "--format", "json", "package-lock.json"}, &stdout, &stderr); code == 2 {
		t.Fatalf("hook exited 2: %s", stderr.String())
	}
	var hook struct {
		Suppressions []map[string]any `json:"suppressions"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &hook); err != nil {
		t.Fatalf("decode hook payload: %v\n%s", err, stdout.String())
	}
	if len(hook.Suppressions) != 1 || hook.Suppressions[0]["source"] != "built-in" || hook.Suppressions[0]["path"] != "package-lock.json" {
		t.Fatalf("hook suppressions = %v, want one built-in row for package-lock.json", hook.Suppressions)
	}
}

// TestTestPathSensitiveFindingsAreSkippedAndCounted verifies a key in test, fixture or example files is skipped and counted.
//
// Rows are one per rule and file, after the lockfile row.
// The same bytes in production code, and in `latest.json`, whose name only resembles a test, still report.
func TestTestPathSensitiveFindingsAreSkippedAndCounted(t *testing.T) {
	root := t.TempDir()
	body := lockfileSkipFixture()
	writeFile(t, root, "package-lock.json", body)
	writeFile(t, root, "Tests/Fixtures/keys.json", body)
	writeFile(t, root, "examples/demo.json", body)
	writeFile(t, root, "src/config.json", body)
	writeFile(t, root, "src/latest.json", body)
	t.Chdir(root)

	payload := analyseJSONReport(t, "--no-config", "--no-baseline", "--fail-on", "none", ".")
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
	if rows[0].(map[string]any)["paths"].([]any)[0] != "package-lock.json" {
		t.Fatalf("the lockfile row must come first; got %v", rows[0])
	}
	if len(testPathRows) != 4 {
		t.Fatalf("test-path rows = %d, want one per rule and file (2 files x 2 rules): %v", len(testPathRows), rows)
	}
	if first := testPathRows[0]["paths"].([]any)[0]; first != "Tests/Fixtures/keys.json" {
		t.Fatalf("test-path rows are ordered by path, then rule; first = %v", first)
	}
}
