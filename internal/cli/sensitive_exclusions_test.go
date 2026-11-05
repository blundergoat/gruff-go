// Package cli tests cover the sensitiveExclusions section of .gruff-go.yaml end to end.
//
// They prove the config file reaches the analyser: an accepted entry removes the finding and publishes its suppression audit row.
// A rejected entry stops the run with exit 2 and a config diagnostic in the JSON report.
// The summary text output must print the same audit line as analyse for the same tree.
package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
)

// sensitiveExclusionFixture returns the text of a Go source file whose AccessKey const holds a synthetic AWS access key.
//
// The literal is assembled from fragments so this test file never contains a complete secret-shaped token for the dogfood scan to report.
func sensitiveExclusionFixture() string {
	key := "AKIA" + strings.Repeat("Q", 16)
	return "// Package fixture is a sensitive-data test fixture.\npackage fixture\n\n// AccessKey is a synthetic identifier used by the exclusion tests.\nconst AccessKey = \"" + key + "\"\n"
}

// analyseJSONReport runs analyse --format json through Main in the current directory and decodes the JSON report.
//
// The args follow analyse --format json on the command line, such as the file path to scan; any exit code but 2 is accepted.
// It returns the decoded JSON report as a map keyed by top-level field name, and fails the test instead on exit 2 or stdout that is not JSON.
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

// TestAnalyseHonoursSensitiveExclusionAndPublishesTheAudit verifies an accepted entry removes the finding from the report.
// The suppressions array must count it in one audit row with no symbol, so the suppression is never silently invisible.
func TestAnalyseHonoursSensitiveExclusionAndPublishesTheAudit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "fixture.go", sensitiveExclusionFixture())
	writeFile(t, root, ".gruff-go.yaml", strings.Join([]string{
		"schemaVersion: gruff-go.config.v0.1",
		"rules:",
		"  sensitive-data.aws-access-key:",
		"    enabled: true",
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

// TestAnalyseKeepsUnexcludedSensitiveFinding is the control: the enabled AWS rule reports the fixture when no sensitive exclusion is configured.
// This shows TestAnalyseHonoursSensitiveExclusionAndPublishesTheAudit sees a real suppression, not a rule that never fired.
func TestAnalyseKeepsUnexcludedSensitiveFinding(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "fixture.go", sensitiveExclusionFixture())
	// The AWS rule is off by default since precision-floor M19, so the fixture enables it.
	writeFile(t, root, ".gruff-go.yaml", "schemaVersion: gruff-go.config.v0.1\nrules:\n  sensitive-data.aws-access-key:\n    enabled: true\n")
	t.Chdir(root)

	payload := analyseJSONReport(t, "fixture.go")

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

// TestAnalyseRejectsValueMatchingExclusion verifies a sensitiveExclusions entry that matches by value is a fatal configuration error.
// Analyse must exit 2, publish a JSON report with no findings and one config diagnostic, and name the entry index and offending key on stderr.
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
	// A refusal after argument parsing publishes the v3 envelope, so a JSON caller reads the failure rather than
	// scraping stderr for it (FAMILY-CONTRACT.md section 6).
	payload := map[string]any{}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("analyse published no readable envelope after a fatal config diagnostic: %v\n%s", err, stdout.String())
	}
	if payload["schemaVersion"] != analysis.SchemaVersion {
		t.Fatalf("schemaVersion = %v, want %s", payload["schemaVersion"], analysis.SchemaVersion)
	}
	if findings, ok := payload["findings"].([]any); !ok || len(findings) != 0 {
		t.Fatalf("a run that could not start published findings: %v", payload["findings"])
	}
	diagnostics, ok := payload["diagnostics"].([]any)
	if !ok || len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %v, want exactly one", payload["diagnostics"])
	}
	first, ok := diagnostics[0].(map[string]any)
	if !ok || first["type"] != analysis.ConfigErrorDiagnosticType {
		t.Fatalf("diagnostic = %v, want type %s", diagnostics[0], analysis.ConfigErrorDiagnosticType)
	}
}

// suppressionAuditLine returns the first line starting "suppressed findings:" in a text output, failing the test when there is none.
//
// The output is the captured text searched line by line, and surface names the command, such as summary or analyse, in the failure message.
// Later lines with the same prefix are ignored, so a duplicate audit line goes unnoticed.
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

// TestSummaryTextReportsTheSameSuppressionAuditAsAnalyse verifies the summary text output reports the sensitive exclusion it applied.
//
// With one entry configured, summary prints the suppression count on a line byte-identical to the one analyse prints for the same tree.
// FAMILY-CONTRACT.md section 13a, "Where the audit must appear", requires the line; it must also sit below the Composite block.
func TestSummaryTextReportsTheSameSuppressionAuditAsAnalyse(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "fixture.go", sensitiveExclusionFixture())
	writeFile(t, root, ".gruff-go.yaml", strings.Join([]string{
		"schemaVersion: gruff-go.config.v0.1",
		"rules:",
		"  sensitive-data.aws-access-key:",
		"    enabled: true",
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
