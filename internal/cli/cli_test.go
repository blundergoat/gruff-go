// Package cli implements the gruff-go command-line interface.
//
// This file exercises analyse, baseline, report, rule-catalogue and diagnostic responses through Main with the arguments a user would type.
// The tests protect what terminal users and JSON consumers receive, so a failure means an exit code, flag or report field they rely on changed.
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
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
	"github.com/blundergoat/gruff-go/internal/scoring"
)

// machineAnalysisReport mirrors the v3 JSON report surface these tests decode from analyse --format json.
//
// The runtime analysis.Report remains the richer internal model and is not a wire decoder.
// SuppressedFindings is a pointer so a test can tell an absent or null summary.suppressedFindings from a zero count.
type machineAnalysisReport struct {
	SchemaVersion string `json:"schemaVersion"`
	Summary       struct {
		AnalysedFiles      int  `json:"analysedFiles"`
		ExitCode           int  `json:"exitCode"`
		SuppressedFindings *int `json:"suppressedFindings"`
		Findings           struct {
			Total int `json:"total"`
		} `json:"findings"`
	} `json:"summary"`
	Baseline      analysis.BaselineSummary      `json:"baseline"`
	Diff          analysis.DiffSummary          `json:"diff"`
	DisplayFilter analysis.DisplayFilterSummary `json:"displayFilter"`
	Diagnostics   []struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"diagnostics"`
	Findings []finding.Finding `json:"findings"`
	Score    struct {
		Composite struct {
			Score float64 `json:"score"`
			Grade string  `json:"grade"`
		} `json:"composite"`
		Pillars []scoring.PillarDetail `json:"pillars"`
	} `json:"score"`
	Paths struct {
		IgnoredPaths []string               `json:"ignoredPaths"`
		MissingPaths []string               `json:"missingPaths"`
		Details      []analysis.SkippedPath `json:"details"`
		Extensions   struct {
			Go struct {
				Paths struct {
					Scanned []string `json:"scanned"`
				} `json:"paths"`
			} `json:"go"`
		} `json:"extensions"`
	} `json:"paths"`
	Extensions struct {
		Go struct {
			TopLevel struct {
				Rules []rule.Definition `json:"rules"`
			} `json:"topLevel"`
		} `json:"go"`
	} `json:"extensions"`
}

// TestAnalyseTextAndJSON checks that text and JSON formats both produce valid output for a clean one-file project, exiting 0.
// A failure means the text header, the JSON schemaVersion, the analysed-file count or a rule's parser capability changed.
func TestAnalyseTextAndJSON(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(root)

	var textOut, textErr bytes.Buffer
	if code := Main([]string{"analyse", "."}, &textOut, &textErr); code != 0 {
		t.Fatalf("text exit = %d, stderr = %s", code, textErr.String())
	}
	if !strings.Contains(textOut.String(), "gruff-go "+toolVersion+" analyse") {
		t.Fatalf("text output missing header: %s", textOut.String())
	}

	var jsonOut, jsonErr bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "."}, &jsonOut, &jsonErr); code != 0 {
		t.Fatalf("json exit = %d, stderr = %s", code, jsonErr.String())
	}
	var parsed machineAnalysisReport
	if err := json.Unmarshal(jsonOut.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, jsonOut.String())
	}
	if parsed.SchemaVersion != analysis.SchemaVersion {
		t.Fatalf("schema = %q, want %q", parsed.SchemaVersion, analysis.SchemaVersion)
	}
	if parsed.Summary.AnalysedFiles != 1 {
		t.Fatalf("files scanned = %d, want 1", parsed.Summary.AnalysedFiles)
	}
	for _, definition := range parsed.Extensions.Go.TopLevel.Rules {
		if definition.Capability != "parser" {
			t.Fatalf("rule %s capability = %q, want parser", definition.ID, definition.Capability)
		}
	}
}

// TestDeepScanBudgetCLIOverridesConfig checks that --deep-scan-budget takes precedence over the deepScanBudget block in .gruff-go.yaml.
// The config's tiny budget gives one override=config diagnostic; a paired value such as 100:10000, or off to disable it, gives none.
func TestDeepScanBudgetCLIOverridesConfig(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "// Package main is a budget fixture.\npackage main\n\nfunc main() {}\n")
	writeFile(t, root, ".gruff-go.yaml", "schemaVersion: gruff-go.config.v0.1\ndeepScanBudget:\n  enabled: true\n  maxLines: 1\n  maxBytes: 1\n")
	t.Chdir(root)

	// run passes arguments to Main, fails the test on any nonzero exit, and returns the decoded JSON report, so each call below asserts exit 0.
	run := func(arguments ...string) machineAnalysisReport {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := Main(arguments, &out, &errOut); code != 0 {
			t.Fatalf("%v exit = %d, stderr = %s", arguments, code, errOut.String())
		}
		var reportData machineAnalysisReport
		if err := json.Unmarshal(out.Bytes(), &reportData); err != nil {
			t.Fatal(err)
		}
		return reportData
	}

	configured := run("analyse", "--format", "json", "--fail-on", "none", "main.go")
	if len(configured.Diagnostics) != 1 || !strings.Contains(configured.Diagnostics[0].Message, "override=config") {
		t.Fatalf("configured diagnostics = %#v", configured.Diagnostics)
	}
	for _, override := range []string{"100:10000", "off"} {
		reportData := run("analyse", "--format", "json", "--fail-on", "none", "--deep-scan-budget", override, "main.go")
		if len(reportData.Diagnostics) != 0 {
			t.Fatalf("override %q diagnostics = %#v, want none", override, reportData.Diagnostics)
		}
	}
}

// TestAnalyseChangedRangesFailOnNoneExitsZero checks that a changed-ranges scan with --fail-on none exits 0.
// The JSON must still include summary.suppressedFindings; a missing key fails the test.
func TestAnalyseChangedRangesFailOnNoneExitsZero(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	var out, errOut bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "--fail-on", "none", "--changed-ranges", "3-3", "complex.go"}, &out, &errOut); code != 0 {
		t.Fatalf("changed-ranges analyse exit = %d, stderr = %s, stdout = %s", code, errOut.String(), out.String())
	}
	var parsed machineAnalysisReport
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Summary.SuppressedFindings == nil {
		t.Fatalf("suppressedCount missing from changed-region JSON: %s", out.String())
	}
}

// TestAnalyseHelpDocumentsChangedRegionFlags checks that every analyse help route lists --changed-ranges, --changed-scope and --no-baseline.
// The routes are help analyse, analyse --help and analyse --diff --help; downstream hooks string-match GNU-style long flags to detect support.
func TestAnalyseHelpDocumentsChangedRegionFlags(t *testing.T) {
	for _, args := range [][]string{
		{"help", "analyse"},
		{"analyse", "--help"},
		{"analyse", "--diff", "--help"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Main(args, &out, &errOut); code != 0 {
				t.Fatalf("%v exit = %d, stderr = %s", args, code, errOut.String())
			}
			for _, flag := range []string{"--changed-ranges", "--changed-scope", "--no-baseline"} {
				if !strings.Contains(out.String(), flag) {
					t.Fatalf("%v help missing %s: %s", args, flag, out.String())
				}
			}
		})
	}
}

// TestAnalyseTreatsHelpAfterTerminatorAsPath checks that in analyse main.go -- --help, the --help after -- is a path, not a help request.
// The run must exit 0 without printing the analyse usage text, so a user can still name a file that looks like a flag.
func TestAnalyseTreatsHelpAfterTerminatorAsPath(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	writeFile(t, projectRoot, "--help", "not a go source file\n")
	t.Chdir(projectRoot)

	var out, errOut bytes.Buffer
	if code := Main([]string{"analyse", "--fail-on", "none", "main.go", "--", "--help"}, &out, &errOut); code != 0 {
		t.Fatalf("analyse exit = %d, stderr = %s, stdout = %s", code, errOut.String(), out.String())
	}
	if strings.Contains(out.String(), "gruff-go analyse [") {
		t.Fatalf("-- --help should not render command help: %s", out.String())
	}
}

// TestAnalyseRecognisesHelpAfterPath verifies a trailing help flag does not become another scan path.
func TestAnalyseRecognisesHelpAfterPath(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Main([]string{"analyse", "main.go", "--help"}, &out, &errOut); code != 0 {
		t.Fatalf("analyse help exit = %d, stderr = %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "gruff-go analyse [") {
		t.Fatalf("help output missing command usage: %s", out.String())
	}
}

// TestAnalyseFailOnRejectsLegacySeverity checks that --fail-on critical exits 2 with unknown threshold "critical" on standard error.
// The 5-bucket alias parser is gone (ADR-009 + ADR-010), so ParseFailThreshold rejects the old severity name.
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
// Scanned paths must also come out sorted, a.go before b.go, even though b.go is written first.
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
	var firstReport, secondReport machineAnalysisReport
	if err := json.Unmarshal(first.Bytes(), &firstReport); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Bytes(), &secondReport); err != nil {
		t.Fatal(err)
	}
	if firstReport.Paths.Extensions.Go.Paths.Scanned[0] != "a.go" || firstReport.Paths.Extensions.Go.Paths.Scanned[1] != "b.go" {
		t.Fatalf("scanned paths not sorted: %#v", firstReport.Paths.Extensions.Go.Paths.Scanned)
	}
	if first.String() != second.String() {
		t.Fatalf("json output changed between runs:\nfirst:\n%s\nsecond:\n%s", first.String(), second.String())
	}
	if !reflect.DeepEqual(firstReport.Summary, secondReport.Summary) {
		t.Fatalf("summary changed: %#v %#v", firstReport.Summary, secondReport.Summary)
	}
}

// TestListRulesListsBuiltInCatalogueUnderAProjectConfig checks that list-rules prints the built-in catalogue even under a project config.
//
// A .gruff-go.yaml overriding severity, enablement or threshold leaves both formats on the release defaults, pinning the family listing.
// list-rules still loads the project config and refuses an invalid one with exit 2.
func TestListRulesListsBuiltInCatalogueUnderAProjectConfig(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	for _, format := range []string{"json", "text"} {
		var builtIn, builtInErr bytes.Buffer
		if code := Main([]string{"list-rules", "--no-config", "--format", format}, &builtIn, &builtInErr); code != 0 {
			t.Fatalf("list-rules --no-config --format %s exit = %d, stderr = %s", format, code, builtInErr.String())
		}
		config := "schemaVersion: gruff-go.config.v0.1\nrules:\n  sensitive-data.private-key:\n    enabled: false\n    severity: error\n  complexity.cognitive:\n    threshold: 3\n"
		if err := os.WriteFile(filepath.Join(root, ".gruff-go.yaml"), []byte(config), 0o644); err != nil {
			t.Fatal(err)
		}
		var configured, configuredErr bytes.Buffer
		if code := Main([]string{"list-rules", "--format", format}, &configured, &configuredErr); code != 0 {
			t.Fatalf("list-rules --format %s exit = %d, stderr = %s", format, code, configuredErr.String())
		}
		if configured.String() != builtIn.String() {
			t.Fatalf("list-rules --format %s changed under a project config:\nbuilt-in:\n%s\nconfigured:\n%s", format, builtIn.String(), configured.String())
		}
		if err := os.Remove(filepath.Join(root, ".gruff-go.yaml")); err != nil {
			t.Fatal(err)
		}
	}

	// A rule ID gruff-go does not know, like a typo under rules, makes the config broken, and list-rules must exit 2.
	broken := "schemaVersion: gruff-go.config.v0.1\nrules:\n  not.a-rule:\n    enabled: true\n"
	if err := os.WriteFile(filepath.Join(root, ".gruff-go.yaml"), []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	var brokenOut, brokenErr bytes.Buffer
	if code := Main([]string{"list-rules", "--format", "json"}, &brokenOut, &brokenErr); code != 2 {
		t.Fatalf("list-rules under a broken config exit = %d, want 2; stderr = %s", code, brokenErr.String())
	}
}

// TestListRulesAndDiagnostics checks the list-rules JSON catalogue and the exit 2 a user gets for a missing path or an unparsable file.
// Every medium- or low-confidence rule must ship false-positive guidance, and the catalogue is pinned at 80 rules with 43 medium or low.
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
	var catalogue struct {
		Rules []struct {
			ID                  string `json:"id"`
			Confidence          string `json:"confidence"`
			FalsePositiveShapes []struct {
				Shape      string `json:"shape"`
				Mitigation string `json:"mitigation"`
			} `json:"falsePositiveShapes"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(listOut.Bytes(), &catalogue); err != nil {
		t.Fatalf("invalid list-rules json: %v", err)
	}
	precisionRuleCount := 0
	// Check every medium- or low-confidence rule exactly as a catalogue user sees it.
	for _, listedRule := range catalogue.Rules {
		if listedRule.Confidence != "medium" && listedRule.Confidence != "low" {
			continue
		}
		precisionRuleCount++
		// Empty guidance would not help a user decide whether to edit or scope the rule.
		if len(listedRule.FalsePositiveShapes) == 0 || listedRule.FalsePositiveShapes[0].Shape == "" || listedRule.FalsePositiveShapes[0].Mitigation == "" {
			t.Fatalf("%s false-positive guidance = %#v", listedRule.ID, listedRule.FalsePositiveShapes)
		}
	}
	// Update these pinned counts when the catalogue total changes or a rule moves into or out of medium or low confidence.
	if len(catalogue.Rules) != 80 || precisionRuleCount != 43 {
		t.Fatalf("list-rules counts = %d total, %d medium/low; want 80 and 43", len(catalogue.Rules), precisionRuleCount)
	}

	// A path that does not exist, such as a typo on the command line, makes analyse exit 2.
	var missingOut, missingErr bytes.Buffer
	if code := Main([]string{"analyse", "missing.go"}, &missingOut, &missingErr); code != 2 {
		t.Fatalf("missing exit = %d, stderr = %s, stdout = %s", code, missingErr.String(), missingOut.String())
	}

	// A Go file with a syntax error, such as a half-saved edit, also makes analyse exit 2.
	writeFile(t, ".", "broken.go", "package main\nfunc broken( {\n")
	var parseOut, parseErr bytes.Buffer
	if code := Main([]string{"analyse", "broken.go"}, &parseOut, &parseErr); code != 2 {
		t.Fatalf("parse exit = %d, stderr = %s, stdout = %s", code, parseErr.String(), parseOut.String())
	}
}

// TestAnalyseJSONIncludesFindingsAndScore checks that analyse on complexFixture exits 1 with one complexity.cognitive finding in JSON.
// The finding needs a fingerprint and remediation, and the score must fall below 100 with a grade and exactly one finding-bearing pillar.
func TestAnalyseJSONIncludesFindingsAndScore(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	var out, errOut bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "."}, &out, &errOut); code != 1 {
		t.Fatalf("exit = %d, stderr = %s, stdout = %s", code, errOut.String(), out.String())
	}
	// Catalogue guidance must not add fields to the stable analysis-report rule objects.
	if strings.Contains(out.String(), `"falsePositiveShapes"`) {
		t.Fatalf("analysis JSON unexpectedly contains catalogue-only guidance: %s", out.String())
	}
	var parsed machineAnalysisReport
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("findings = %#v, want one", parsed.Findings)
	}
	reportedFinding := parsed.Findings[0]
	if reportedFinding.RuleID != "complexity.cognitive" || reportedFinding.Fingerprint == "" || reportedFinding.Remediation == "" {
		t.Fatalf("finding = %#v, want complete complexity finding", reportedFinding)
	}
	// Every rule-backed pillar now carries a row, so the finding-bearing count is read from the rows
	// themselves rather than from the length of a list that used to hold only penalised pillars.
	findingBearing := 0
	for _, pillar := range parsed.Score.Pillars {
		if pillar.Findings > 0 {
			findingBearing++
		}
	}
	if parsed.Score.Composite.Score >= 100 || parsed.Score.Composite.Grade == "" || findingBearing != 1 {
		t.Fatalf("score = %#v, want penalized score in exactly one pillar", parsed.Score)
	}
}

// TestAnalyseHonorsConfigThresholdAndBaseline checks that --config raising maxComplexity to 100 clears the complexity finding, exiting 0.
// A baseline written by gruff-go baseline then hides that finding on the next analyse: one suppressed, zero reported, exit 0.
func TestAnalyseHonorsConfigThresholdAndBaseline(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	writeFile(t, root, "config.yaml", `
schemaVersion: gruff-go.config.v0.1
rules:
  complexity.cognitive:
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
	var parsed machineAnalysisReport
	if err := json.Unmarshal(analysisOut.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Baseline.SuppressedFindings != 1 || parsed.Summary.Findings.Total != 0 {
		t.Fatalf("baseline summary = %#v summary = %#v, want one suppressed and no findings", parsed.Baseline, parsed.Summary)
	}
}

// TestAnalyseGenerateBaselineWritesUsableBaseline checks that analyse --generate-baseline writes a baseline the next --baseline run applies.
//
// This onboarding run must exit 0 and confirm the write; the steady-state run then hides the one finding.
// Its baseline section must carry all nine family keys, with generated false and an explicit source.
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
	var parsed machineAnalysisReport
	if err := json.Unmarshal(analysisOut.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Baseline.SuppressedFindings != 1 || parsed.Summary.Findings.Total != 0 {
		t.Fatalf("baseline summary = %#v summary = %#v, want one suppressed and no findings", parsed.Baseline, parsed.Summary)
	}
	// The family baseline contract names nine keys; a consumer must find every one without a per-port branch.
	var raw struct {
		Baseline map[string]any `json:"baseline"`
	}
	if err := json.Unmarshal(analysisOut.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"applied", "entries", "generated", "newFindings", "resolvedFindings", "source", "suppressedFindings", "unchangedFindings", "path"} {
		if _, ok := raw.Baseline[key]; !ok {
			t.Fatalf("baseline section lacks ratified key %q: %#v", key, raw.Baseline)
		}
	}
	if raw.Baseline["generated"] != false || raw.Baseline["source"] != "explicit" {
		t.Fatalf("baseline section = %#v, want generated false and an explicit source", raw.Baseline)
	}
}

// TestAnalyseGenerateBaselineRejectsPartialScopeFlags checks that --generate-baseline exits 2 beside a baseline, diff or display filter.
// This keeps a baseline from being generated after baseline suppression, diff filtering or display filters hid part of the findings.
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
		// --diff=- must be rejected before the stdin patch is read, so an interactive
		// or hook invocation returns the error instead of blocking on stdin.
		{"analyse", "--generate-baseline", "baseline.json", "--diff", "-", "complex.go"},
		{"analyse", "--generate-baseline", "baseline.json", "--include-rules", "complexity.cognitive", "complex.go"},
		{"analyse", "--generate-baseline", "baseline.json", "--exclude-rules", "complexity.cognitive", "complex.go"},
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

// TestAnalyseAutoLoadsGruffGoYAMLAndNoConfigSkipsIt checks that analyse picks up .gruff-go.yaml from the working directory without --config.
// That config's threshold of 100 clears the complexity finding (exit 0); --no-config ignores it, so the finding returns and the run exits 1.
func TestAnalyseAutoLoadsGruffGoYAMLAndNoConfigSkipsIt(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	writeFile(t, root, ".gruff-go.yaml", `
schemaVersion: gruff-go.config.v0.1
rules:
  complexity.cognitive:
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

// TestAnalyseSummarySARIFAndGitHubFormats checks that --format summary-json, sarif and github each print non-empty output.
// Each run must also exit 1, since the fixture's complexity finding fails the run whatever format renders it.
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
// With --exclude-rules complexity.cognitive the finding leaves the findings list, yet the run still exits 1 and the summary still counts it.
func TestAnalyseDisplayFiltersDoNotChangeExitOrScoreInputs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "complex.go", complexFixture())
	t.Chdir(root)

	var out, errOut bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "--exclude-rules", "complexity.cognitive", "complex.go"}, &out, &errOut); code != 1 {
		t.Fatalf("exit = %d, stderr = %s, stdout = %s", code, errOut.String(), out.String())
	}
	var parsed machineAnalysisReport
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Findings) != 0 || parsed.Summary.Findings.Total != 1 || parsed.DisplayFilter.HiddenFindings != 1 {
		t.Fatalf("findings = %#v summary = %#v display = %#v", parsed.Findings, parsed.Summary, parsed.DisplayFilter)
	}
}

// TestReportIncludeIgnoredOverridesGitignore checks that gruff-go report accepts --include-ignored and scans gitignored files.
//
// Without the flag, report --format json scans main.go and records ignored.go as skipped with reason gitignored.
// With it, ignored.go is scanned and no gitignored skip reason appears.
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

// complexFixture returns a Go source string whose only finding under the default rules is complexity.cognitive.
//
// Its run of independent ifs keeps complexity.cognitive above threshold; the exported name keeps dead-code.unused-private-function from firing.
// Tests write it as complex.go and assert exact counts, so a fixture change that adds or removes a finding breaks them.
func complexFixture() string {
	return `// Package sample is a test package.
package sample

// Risky is intentionally over the cognitive threshold for fixture use: twenty-six independent
// branches, since complexity.cyclomatic is off by default and a switch counts once.
func Risky(a int) {
	if a == 1 {
		_ = a
	}
	if a == 2 {
		_ = a
	}
	if a == 3 {
		_ = a
	}
	if a == 4 {
		_ = a
	}
	if a == 5 {
		_ = a
	}
	if a == 6 {
		_ = a
	}
	if a == 7 {
		_ = a
	}
	if a == 8 {
		_ = a
	}
	if a == 9 {
		_ = a
	}
	if a == 10 {
		_ = a
	}
	if a == 11 {
		_ = a
	}
	if a == 12 {
		_ = a
	}
	if a == 13 {
		_ = a
	}
	if a == 14 {
		_ = a
	}
	if a == 15 {
		_ = a
	}
	if a == 16 {
		_ = a
	}
	if a == 17 {
		_ = a
	}
	if a == 18 {
		_ = a
	}
	if a == 19 {
		_ = a
	}
	if a == 20 {
		_ = a
	}
	if a == 21 {
		_ = a
	}
	if a == 22 {
		_ = a
	}
	if a == 23 {
		_ = a
	}
	if a == 24 {
		_ = a
	}
	if a == 25 {
		_ = a
	}
	if a == 26 {
		_ = a
	}
}
`
}

// writeFile is a test helper that creates a file beneath root with the given contents.
//
// rel is the file path joined beneath root; missing parent directories are created first and an existing file there is replaced by contents.
// A directory or write failure stops the test with t.Fatal.
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
