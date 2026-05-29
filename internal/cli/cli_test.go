// Package cli implements the gruff-go command-line interface.
// This file exercises the analyse subcommand and related helpers.
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/analysis"
)

// TestAnalyseTextAndJSON checks that text and JSON formats both produce valid output.
func TestAnalyseTextAndJSON(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(root)

	var textOut, textErr bytes.Buffer
	if code := Main([]string{"analyse", "."}, &textOut, &textErr); code != 0 {
		t.Fatalf("text exit = %d, stderr = %s", code, textErr.String())
	}
	if !strings.Contains(textOut.String(), "gruff-go analysis") {
		t.Fatalf("text output missing header: %s", textOut.String())
	}

	var jsonOut, jsonErr bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "."}, &jsonOut, &jsonErr); code != 0 {
		t.Fatalf("json exit = %d, stderr = %s", code, jsonErr.String())
	}
	var parsed analysis.Report
	if err := json.Unmarshal(jsonOut.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, jsonOut.String())
	}
	if parsed.SchemaVersion != analysis.SchemaVersion {
		t.Fatalf("schema = %q, want %q", parsed.SchemaVersion, analysis.SchemaVersion)
	}
	if parsed.Summary.FilesScanned != 1 {
		t.Fatalf("files scanned = %d, want 1", parsed.Summary.FilesScanned)
	}
	for _, definition := range parsed.Rules {
		if definition.Capability != "parser" {
			t.Fatalf("rule %s capability = %q, want parser", definition.ID, definition.Capability)
		}
	}
}

func TestAnalyseChangedRangesFailOnNoneExitsZero(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	var out, errOut bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "--fail-on", "none", "--changed-ranges", "3-3", "complex.go"}, &out, &errOut); code != 0 {
		t.Fatalf("changed-ranges analyse exit = %d, stderr = %s, stdout = %s", code, errOut.String(), out.String())
	}
	var parsed analysis.Report
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.SuppressedCount == nil {
		t.Fatalf("suppressedCount missing from changed-region JSON: %s", out.String())
	}
}

func TestAnalyseHelpDocumentsChangedRegionFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Main([]string{"help", "analyse"}, &out, &errOut); code != 0 {
		t.Fatalf("help analyse exit = %d, stderr = %s", code, errOut.String())
	}
	for _, flag := range []string{"--changed-ranges", "--since", "--diff mode", "--changed-scope"} {
		if !strings.Contains(out.String(), flag) {
			t.Fatalf("help missing %s: %s", flag, out.String())
		}
	}
}

// TestAnalyseFailOnRejectsLegacySeverity confirms the 5-bucket alias parser is
// gone (ADR-009 + ADR-010): --fail-on critical is rejected by
// ParseFailThreshold, exit 2.
func TestAnalyseFailOnRejectsLegacySeverity(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(root)

	var out, errBuf bytes.Buffer
	if code := Main([]string{"analyse", "--fail-on", "critical", "."}, &out, &errBuf); code != 2 {
		t.Fatalf("analyse --fail-on critical exit = %d, want 2; stderr = %s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), `unknown threshold "critical"`) {
		t.Fatalf(`stderr should contain unknown threshold "critical"; got: %s`, errBuf.String())
	}
}

// TestAnalyseJSONDeterministicShape verifies that repeated scans yield identical JSON.
func TestAnalyseJSONDeterministicShape(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "b.go", "// Package main is a test fixture.\npackage main\n")
	writeFile(t, root, "a.go", "// Package main is a test fixture.\npackage main\n")
	t.Chdir(root)

	var first, second bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "."}, &first, &bytes.Buffer{}); code != 0 {
		t.Fatalf("first exit = %d", code)
	}
	if code := Main([]string{"analyse", "--format", "json", "."}, &second, &bytes.Buffer{}); code != 0 {
		t.Fatalf("second exit = %d", code)
	}
	var firstReport, secondReport analysis.Report
	if err := json.Unmarshal(first.Bytes(), &firstReport); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Bytes(), &secondReport); err != nil {
		t.Fatal(err)
	}
	if firstReport.Paths.Scanned[0] != "a.go" || firstReport.Paths.Scanned[1] != "b.go" {
		t.Fatalf("scanned paths not sorted: %#v", firstReport.Paths.Scanned)
	}
	if first.String() != second.String() {
		t.Fatalf("json output changed between runs:\nfirst:\n%s\nsecond:\n%s", first.String(), second.String())
	}
	if !reflect.DeepEqual(firstReport.Summary, secondReport.Summary) {
		t.Fatalf("summary changed: %#v %#v", firstReport.Summary, secondReport.Summary)
	}
}

// TestListRulesAndDiagnostics covers list-rules output and diagnostic exit codes.
func TestListRulesAndDiagnostics(t *testing.T) {
	t.Chdir(t.TempDir())

	var listOut, listErr bytes.Buffer
	if code := Main([]string{"list-rules", "--format", "json"}, &listOut, &listErr); code != 0 {
		t.Fatalf("list-rules exit = %d, stderr = %s", code, listErr.String())
	}
	if !strings.Contains(listOut.String(), `"id": "size.file-length"`) {
		t.Fatalf("list-rules output = %s", listOut.String())
	}
	if !strings.Contains(listOut.String(), `"capability": "parser"`) {
		t.Fatalf("list-rules output missing capability = %s", listOut.String())
	}

	var missingOut, missingErr bytes.Buffer
	if code := Main([]string{"analyse", "missing.go"}, &missingOut, &missingErr); code != 2 {
		t.Fatalf("missing exit = %d, stderr = %s, stdout = %s", code, missingErr.String(), missingOut.String())
	}

	writeFile(t, ".", "broken.go", "package main\nfunc broken( {\n")
	var parseOut, parseErr bytes.Buffer
	if code := Main([]string{"analyse", "broken.go"}, &parseOut, &parseErr); code != 2 {
		t.Fatalf("parse exit = %d, stderr = %s, stdout = %s", code, parseErr.String(), parseOut.String())
	}
}

// TestAnalyseJSONIncludesFindingsAndScore asserts findings and score appear in JSON output.
func TestAnalyseJSONIncludesFindingsAndScore(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	var out, errOut bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "."}, &out, &errOut); code != 1 {
		t.Fatalf("exit = %d, stderr = %s, stdout = %s", code, errOut.String(), out.String())
	}
	var parsed analysis.Report
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("findings = %#v, want one", parsed.Findings)
	}
	finding := parsed.Findings[0]
	if finding.RuleID != "complexity.cyclomatic" || finding.Fingerprint == "" || finding.Remediation == "" {
		t.Fatalf("finding = %#v, want complete complexity finding", finding)
	}
	if parsed.Score.Composite >= 100 || parsed.Score.Grade == "" || len(parsed.Score.Pillars) != 1 {
		t.Fatalf("score = %#v, want penalized score", parsed.Score)
	}
}

// TestAnalyseHonorsConfigThresholdAndBaseline checks config thresholds and baseline suppression.
func TestAnalyseHonorsConfigThresholdAndBaseline(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	writeFile(t, root, "config.yaml", `
rules:
  complexity.cyclomatic:
    thresholds:
      maxComplexity: 100
`)
	t.Chdir(root)

	var configOut, configErr bytes.Buffer
	if code := Main([]string{"analyse", "--config", "config.yaml", "."}, &configOut, &configErr); code != 0 {
		t.Fatalf("config exit = %d, stderr = %s, stdout = %s", code, configErr.String(), configOut.String())
	}

	var baselineOut, baselineErr bytes.Buffer
	if code := Main([]string{"baseline", "--out", "baseline.json", "complex.go"}, &baselineOut, &baselineErr); code != 0 {
		t.Fatalf("baseline exit = %d, stderr = %s, stdout = %s", code, baselineErr.String(), baselineOut.String())
	}

	var analysisOut, analysisErr bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "--baseline", "baseline.json", "complex.go"}, &analysisOut, &analysisErr); code != 0 {
		t.Fatalf("baseline analyse exit = %d, stderr = %s, stdout = %s", code, analysisErr.String(), analysisOut.String())
	}
	var parsed analysis.Report
	if err := json.Unmarshal(analysisOut.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Baseline.SuppressedFindings != 1 || parsed.Summary.FindingsCount != 0 {
		t.Fatalf("baseline summary = %#v summary = %#v, want one suppressed and no findings", parsed.Baseline, parsed.Summary)
	}
}

// TestAnalyseGenerateBaselineWritesUsableBaseline verifies the analyse-side
// onboarding flag writes the same kind of baseline the steady-state
// --baseline flow can apply on the next run.
func TestAnalyseGenerateBaselineWritesUsableBaseline(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	var generateOut, generateErr bytes.Buffer
	if code := Main([]string{"analyse", "--generate-baseline", "baseline.json", "complex.go"}, &generateOut, &generateErr); code != 0 {
		t.Fatalf("generate-baseline exit = %d, stderr = %s, stdout = %s", code, generateErr.String(), generateOut.String())
	}
	if !strings.Contains(generateOut.String(), "baseline: wrote 1 findings to baseline.json") {
		t.Fatalf("generate-baseline stdout = %s, want write confirmation", generateOut.String())
	}
	if _, err := os.Stat(filepath.Join(root, "baseline.json")); err != nil {
		t.Fatalf("expected baseline.json to be written: %v", err)
	}

	var analysisOut, analysisErr bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "--baseline", "baseline.json", "complex.go"}, &analysisOut, &analysisErr); code != 0 {
		t.Fatalf("baseline analyse exit = %d, stderr = %s, stdout = %s", code, analysisErr.String(), analysisOut.String())
	}
	var parsed analysis.Report
	if err := json.Unmarshal(analysisOut.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Baseline.SuppressedFindings != 1 || parsed.Summary.FindingsCount != 0 {
		t.Fatalf("baseline summary = %#v summary = %#v, want one suppressed and no findings", parsed.Baseline, parsed.Summary)
	}
}

// TestAnalyseGenerateBaselineRejectsPartialScopeFlags protects the baseline
// from being generated after suppression, diff filtering, or display filters.
func TestAnalyseGenerateBaselineRejectsPartialScopeFlags(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	cases := [][]string{
		{"analyse", "--generate-baseline", "baseline.json", "--baseline", "existing.json", "complex.go"},
		{"analyse", "--generate-baseline", "baseline.json", "--diff-base", "HEAD", "complex.go"},
		{"analyse", "--generate-baseline", "baseline.json", "--changed-ranges", "3-3", "complex.go"},
		{"analyse", "--generate-baseline", "baseline.json", "--since", "HEAD", "complex.go"},
		{"analyse", "--generate-baseline", "baseline.json", "--diff", "working-tree", "complex.go"},
		{"analyse", "--generate-baseline", "baseline.json", "--include-rules", "complexity.cyclomatic", "complex.go"},
		{"analyse", "--generate-baseline", "baseline.json", "--exclude-rules", "complexity.cyclomatic", "complex.go"},
		{"analyse", "--generate-baseline", "baseline.json", "--include-pillars", "complexity", "complex.go"},
		{"analyse", "--generate-baseline", "baseline.json", "--exclude-pillars", "complexity", "complex.go"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args[2:4], "_"), func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Main(args, &out, &errOut); code != 2 {
				t.Fatalf("%v exit = %d, want 2; stdout=%s stderr=%s", args, code, out.String(), errOut.String())
			}
			if !strings.Contains(errOut.String(), "--generate-baseline cannot be combined") {
				t.Fatalf("%v stderr = %s, want incompatibility message", args, errOut.String())
			}
		})
	}
}

// TestAnalyseAutoLoadsGruffGoYAMLAndNoConfigSkipsIt confirms config autoload and --no-config behaviour.
func TestAnalyseAutoLoadsGruffGoYAMLAndNoConfigSkipsIt(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	writeFile(t, root, ".gruff-go.yaml", `
rules:
  complexity.cyclomatic:
    threshold: 100
`)
	t.Chdir(root)

	var out, errOut bytes.Buffer
	if code := Main([]string{"analyse", "complex.go"}, &out, &errOut); code != 0 {
		t.Fatalf("auto config exit = %d, stderr = %s, stdout = %s", code, errOut.String(), out.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Main([]string{"analyse", "--no-config", "complex.go"}, &out, &errOut); code != 1 {
		t.Fatalf("no-config exit = %d, stderr = %s, stdout = %s", code, errOut.String(), out.String())
	}
}

// TestAnalyseSummarySARIFAndGitHubFormats verifies non-empty output for alternative report formats.
func TestAnalyseSummarySARIFAndGitHubFormats(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	for _, format := range []string{"summary-json", "sarif", "github"} {
		t.Run(format, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Main([]string{"analyse", "--format", format, "complex.go"}, &out, &errOut); code != 1 {
				t.Fatalf("exit = %d, stderr = %s, stdout = %s", code, errOut.String(), out.String())
			}
			if out.Len() == 0 {
				t.Fatalf("%s output is empty", format)
			}
		})
	}
}

// TestAnalyseDisplayFiltersDoNotChangeExitOrScoreInputs ensures display filters affect rendering only.
func TestAnalyseDisplayFiltersDoNotChangeExitOrScoreInputs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	var out, errOut bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "--exclude-rules", "complexity.cyclomatic", "complex.go"}, &out, &errOut); code != 1 {
		t.Fatalf("exit = %d, stderr = %s, stdout = %s", code, errOut.String(), out.String())
	}
	var parsed analysis.Report
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 0 || parsed.Summary.FindingsCount != 1 || parsed.DisplayFilter.HiddenFindings != 1 {
		t.Fatalf("findings = %#v summary = %#v display = %#v", parsed.Findings, parsed.Summary, parsed.DisplayFilter)
	}
}

// TestReportIncludeIgnoredOverridesGitignore verifies the report subcommand
// accepts --include-ignored and threads it into discovery so gitignored files
// are scanned. Without this, gruff-go report --format json silently dropped
// ignored files regardless of user intent.
func TestReportIncludeIgnoredOverridesGitignore(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gitignore", "ignored.go\n")
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	writeFile(t, root, "ignored.go", "package main\n")
	t.Chdir(root)

	withoutFlag := bytes.Buffer{}
	errOut := bytes.Buffer{}
	if code := Main([]string{"report", "--format", "json"}, &withoutFlag, &errOut); code != 0 {
		t.Fatalf("default report exit = %d, stderr = %s", code, errOut.String())
	}
	if !strings.Contains(withoutFlag.String(), `"main.go"`) {
		t.Fatalf("default report should scan main.go; got %s", withoutFlag.String())
	}
	if !strings.Contains(withoutFlag.String(), `"reason": "gitignored"`) {
		t.Fatalf("default report should record ignored.go under skipped:gitignored; got %s", withoutFlag.String())
	}

	withFlag := bytes.Buffer{}
	errOut.Reset()
	if code := Main([]string{"report", "--format", "json", "--include-ignored"}, &withFlag, &errOut); code != 0 {
		t.Fatalf("include-ignored report exit = %d, stderr = %s", code, errOut.String())
	}
	if !strings.Contains(withFlag.String(), `"ignored.go"`) {
		t.Fatalf("--include-ignored report should scan ignored.go; got %s", withFlag.String())
	}
	if strings.Contains(withFlag.String(), `"reason": "gitignored"`) {
		t.Fatalf("--include-ignored report should not emit gitignored skip reasons; got %s", withFlag.String())
	}
}

// complexFixture returns a Go source string that triggers a complexity finding.
// The switch shape (sum semantics under NPath, product under cyclomatic) keeps
// only complexity.cyclomatic above threshold; npath stays under its 200 cap and
// the exported name keeps dead-code.unused-private-function from firing.
func complexFixture() string {
	return `// Package sample is a test package.
package sample

// Risky is intentionally over the cyclomatic threshold for fixture use.
func Risky(a int) {
	switch a {
	case 1:
		_ = a
	case 2:
		_ = a
	case 3:
		_ = a
	case 4:
		_ = a
	case 5:
		_ = a
	case 6:
		_ = a
	case 7:
		_ = a
	case 8:
		_ = a
	case 9:
		_ = a
	case 10:
		_ = a
	case 11:
		_ = a
	case 12:
		_ = a
	case 13:
		_ = a
	case 14:
		_ = a
	case 15:
		_ = a
	case 16:
		_ = a
	case 17:
		_ = a
	case 18:
		_ = a
	case 19:
		_ = a
	case 20:
		_ = a
	case 21:
		_ = a
	}
}
`
}

// writeFile is a test helper that creates a file beneath root with the given contents.
func writeFile(t *testing.T, root, rel, contents string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
