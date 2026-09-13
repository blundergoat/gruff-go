// Package cli tests cover the sensitiveExclusions section end to end.
// They prove the config file actually reaches the analyser: an accepted entry
// removes the finding and publishes its audit row, and a rejected entry stops
// the run with exit 2.
package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// sensitiveExclusionFixture returns a Go source file carrying a synthetic AWS
// access key. The literal is assembled from fragments so this test file never
// contains a complete secret-shaped token for the dogfood scan to report.
func sensitiveExclusionFixture() string {
	key := "AKIA" + strings.Repeat("Q", 16)
	return "// Package fixture is a sensitive-data test fixture.\npackage fixture\n\n// AccessKey is a synthetic identifier used by the exclusion tests.\nconst AccessKey = \"" + key + "\"\n"
}

// analyseJSONReport runs analyse in root and decodes the machine report.
func analyseJSONReport(t *testing.T, args ...string) map[string]any {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Main(append([]string{"analyse", "--format", "json"}, args...), &stdout, &stderr)
	if code == 2 {
		t.Fatalf("analyse exited 2: %s", stderr.String())
	}
	payload := map[string]any{}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode report: %v\n%s", err, stdout.String())
	}
	return payload
}

// TestAnalyseHonoursSensitiveExclusionAndPublishesTheAudit verifies an accepted
// entry removes the finding from the report and counts it in the suppressions
// array, so the suppression is never silently invisible.
func TestAnalyseHonoursSensitiveExclusionAndPublishesTheAudit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "fixture.go", sensitiveExclusionFixture())
	writeFile(t, root, ".gruff-go.yaml", strings.Join([]string{
		"schemaVersion: gruff-go.config.v0.1",
		"sensitiveExclusions:",
		"  - rule: sensitive-data.aws-access-key",
		"    path: fixture.go",
		"    reason: Synthetic key used by the exclusion fixture; not a live credential.",
	}, "\n"))
	t.Chdir(root)

	payload := analyseJSONReport(t, "fixture.go")

	for _, item := range payload["findings"].([]any) {
		if item.(map[string]any)["ruleId"] == "sensitive-data.aws-access-key" {
			t.Fatal("the excluded sensitive-data finding is still reported")
		}
	}
	suppressions := payload["suppressions"].([]any)
	if len(suppressions) != 1 {
		t.Fatalf("suppressions = %d rows, want 1", len(suppressions))
	}
	row := suppressions[0].(map[string]any)
	if row["rule"] != "sensitive-data.aws-access-key" {
		t.Fatalf("audit rule = %v, want sensitive-data.aws-access-key", row["rule"])
	}
	if row["suppressed"].(float64) < 1 {
		t.Fatalf("audit suppressed = %v, want at least 1", row["suppressed"])
	}
	if row["symbol"] != nil {
		t.Fatalf("audit symbol = %v, want null", row["symbol"])
	}
}

// TestAnalyseKeepsUnexcludedSensitiveFinding is the control: without the config
// the same fixture reports, so the test above proves suppression rather than a
// rule that never fired.
func TestAnalyseKeepsUnexcludedSensitiveFinding(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "fixture.go", sensitiveExclusionFixture())
	t.Chdir(root)

	payload := analyseJSONReport(t, "--no-config", "fixture.go")

	reported := false
	for _, item := range payload["findings"].([]any) {
		if item.(map[string]any)["ruleId"] == "sensitive-data.aws-access-key" {
			reported = true
		}
	}
	if !reported {
		t.Fatal("the fixture produced no aws-access-key finding to exclude")
	}
}

// TestAnalyseRejectsValueMatchingExclusion verifies a value-matching key is a
// fatal configuration diagnostic: exit 2, no report, and a message naming both
// the entry index and the offending key.
func TestAnalyseRejectsValueMatchingExclusion(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "fixture.go", sensitiveExclusionFixture())
	writeFile(t, root, ".gruff-go.yaml", strings.Join([]string{
		"schemaVersion: gruff-go.config.v0.1",
		"sensitiveExclusions:",
		"  - rule: sensitive-data.aws-access-key",
		"    path: fixture.go",
		"    value: AKIA",
		"    reason: Synthetic fixture.",
	}, "\n"))
	t.Chdir(root)

	var stdout, stderr bytes.Buffer
	code := Main([]string{"analyse", "--format", "json", "fixture.go"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, want 2\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "sensitiveExclusions[0]") || !strings.Contains(stderr.String(), "value") {
		t.Fatalf("stderr does not name the entry and key: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("analyse wrote a report after a fatal config diagnostic: %s", stdout.String())
	}
}

// suppressionAuditLine returns the single `suppressed findings:` line a text
// surface printed, failing the test when the surface published none.
func suppressionAuditLine(t *testing.T, surface, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "suppressed findings:") {
			return line
		}
	}
	t.Fatalf("%s text output published no suppression audit line:\n%s", surface, output)
	return ""
}

// TestSummaryTextReportsTheSameSuppressionAuditAsAnalyse verifies the surface
// that applies a sensitive exclusion also reports it: with one entry
// configured, `summary --format text` prints the suppression count, and the
// line is byte-identical to the one `analyse` prints for the same tree
// (FAMILY-CONTRACT.md section 13a, "Where the audit must appear").
func TestSummaryTextReportsTheSameSuppressionAuditAsAnalyse(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "fixture.go", sensitiveExclusionFixture())
	writeFile(t, root, ".gruff-go.yaml", strings.Join([]string{
		"schemaVersion: gruff-go.config.v0.1",
		"sensitiveExclusions:",
		"  - rule: sensitive-data.aws-access-key",
		"    path: fixture.go",
		"    reason: Synthetic key used by the exclusion fixture; not a live credential.",
	}, "\n"))
	t.Chdir(root)

	var summaryOut, summaryErr bytes.Buffer
	if code := Main([]string{"summary", "fixture.go"}, &summaryOut, &summaryErr); code == 2 {
		t.Fatalf("summary exited 2: %s", summaryErr.String())
	}
	var analyseOut, analyseErr bytes.Buffer
	if code := Main([]string{"analyse", "fixture.go"}, &analyseOut, &analyseErr); code == 2 {
		t.Fatalf("analyse exited 2: %s", analyseErr.String())
	}

	summaryLine := suppressionAuditLine(t, "summary", summaryOut.String())
	analyseLine := suppressionAuditLine(t, "analyse", analyseOut.String())
	if summaryLine != analyseLine {
		t.Fatalf("summary audit line %q differs from analyse %q", summaryLine, analyseLine)
	}
	if !strings.HasPrefix(summaryLine, "suppressed findings: 1 via sensitiveExclusions[0] sensitive-data.aws-access-key: 1 (") {
		t.Fatalf("summary audit line does not report the fixture's one suppression: %q", summaryLine)
	}
	// The canonical Composite/Findings block stays above the extension line.
	if composite := strings.Index(summaryOut.String(), "Composite:"); composite < 0 || composite > strings.Index(summaryOut.String(), summaryLine) {
		t.Fatalf("suppression line is not below the canonical block:\n%s", summaryOut.String())
	}
}
