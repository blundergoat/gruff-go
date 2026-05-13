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

func TestAnalyseTextAndJSON(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
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
}

func TestAnalyseJSONDeterministicShape(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "b.go", "package main\n")
	writeFile(t, root, "a.go", "package main\n")
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

func TestListRulesAndDiagnostics(t *testing.T) {
	t.Chdir(t.TempDir())

	var listOut, listErr bytes.Buffer
	if code := Main([]string{"list-rules", "--format", "json"}, &listOut, &listErr); code != 0 {
		t.Fatalf("list-rules exit = %d, stderr = %s", code, listErr.String())
	}
	if !strings.Contains(listOut.String(), `"id": "size.file-length"`) {
		t.Fatalf("list-rules output = %s", listOut.String())
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

func TestAnalyseJSONIncludesFindingsAndScore(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", `// Package sample is a test package.
package sample

func risky(a bool) {
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
}
`)
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

func TestAnalyseHonorsConfigThresholdAndBaseline(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	writeFile(t, root, "config.json", `{
		"rules": {
			"complexity.cyclomatic": {
				"thresholds": {"maxComplexity": 100}
			}
		}
	}`)
	t.Chdir(root)

	var configOut, configErr bytes.Buffer
	if code := Main([]string{"analyse", "--config", "config.json", "."}, &configOut, &configErr); code != 0 {
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

func TestAnalyseAutoLoadsGruffYAMLAndNoConfigSkipsIt(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	writeFile(t, root, ".gruff.yaml", `
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

func complexFixture() string {
	return `// Package sample is a test package.
package sample

func risky(a bool) {
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
	if a {}
}
`
}

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
