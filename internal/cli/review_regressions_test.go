// Package cli tests cover 0.6.0 review regression scenarios across execution selectors, help text, hooks, root resolution, and migration.
//
// Each test invokes the real CLI entry point or helper with temporary workspaces so regressions fail at the observable contract boundary.
// Keeping these scenarios alongside unit tests protects the user-visible exit codes, error text, and migrated YAML output.
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blundergoat/gruff-go/internal/baseline"
	"github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestIncludeRuleOverridesInitDisabledRules ensures --include-rule executes an opt-in rule disabled in gruff-go init config.
func TestIncludeRuleOverridesInitDisabledRules(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if code := Main([]string{"init"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("init exit = %d, want 0", code)
	}
	complexSrc := "// Package p holds a complex function.\npackage p\n\n// Heavy branches repeatedly.\nfunc Heavy(x int) int {\n" +
		strings.Repeat("\tif x > 0 { x++ }\n", 25) + "\treturn x\n}\n"
	if err := os.WriteFile(filepath.Join(root, "heavy.go"), []byte(complexSrc), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Main([]string{"analyse", "--format", "json", "--include-rule", "complexity.cyclomatic", "--fail-on", "none", "."}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("analyse exit = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"complexity.cyclomatic"`) {
		t.Fatalf("expected complexity.cyclomatic finding under --include-rule, got:\n%s", stdout.String())
	}

	// Excluding the same rule via --exclude-rule must still win over --include-pillar.
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"analyse", "--format", "json", "--include-pillar", "complexity", "--exclude-rule", "complexity.cyclomatic", "--fail-on", "none", "."}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("analyse with exclude exit = %d, stderr=%s", code, stderr.String())
	}
	var payload struct {
		Findings []struct {
			RuleID string `json:"ruleId"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	for _, f := range payload.Findings {
		if f.RuleID == "complexity.cyclomatic" {
			t.Fatalf("expected --exclude-rule to beat --include-pillar, but complexity.cyclomatic fired")
		}
	}
}

// TestSummaryAndReportHelpOmitRefusedMinSeverity ensures summary --help and report --help exit 0 and never advertise --min-severity.
func TestSummaryAndReportHelpOmitRefusedMinSeverity(t *testing.T) {
	for _, cmd := range []string{"summary", "report"} {
		t.Run(cmd, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Main([]string{cmd, "--help"}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("%s --help exit = %d, stderr=%s", cmd, code, stderr.String())
			}
			combined := stdout.String() + stderr.String()
			if strings.Contains(combined, "min-severity") {
				t.Fatalf("%s --help advertised refused --min-severity:\n%s", cmd, combined)
			}
			if !strings.Contains(combined, "--fail-on") {
				t.Fatalf("%s --help omitted --fail-on:\n%s", cmd, combined)
			}
		})
	}
}

// TestHookRefusesMinSeverityWithMigrationMessage verifies gruff-go hook --min-severity emits the ratified 0.6.0 refusal message.
func TestHookRefusesMinSeverityWithMigrationMessage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main([]string{"hook", "--min-severity", "error", "."}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("hook --min-severity exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--fail-on") {
		t.Fatalf("stderr = %q, want migration refusal naming --fail-on", stderr.String())
	}

	// Passing --help as the value to --min-severity must not trigger help exit 0.
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"hook", "--min-severity", "--help"}, &stdout, &stderr); code != 2 {
		t.Fatalf("hook --min-severity --help exit = %d, want 2", code)
	}
}

// TestHookRejectsLeadingDashDiffRef ensures git option injection via --diff=--list is rejected before invoking git archive.
func TestHookRejectsLeadingDashDiffRef(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("// Package main is a fixture.\npackage main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	var stdout, stderr bytes.Buffer
	code := Main([]string{"hook", "--changed-ranges", "1-1", "--diff=--list", "."}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("hook --diff=--list exit = %d, want 2; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

// TestMigrateConfigHandlesSelectionRetiredRulesAndEmptyMinimumSeverity verifies migrate-config strips retired selection IDs and renames empty maps.
func TestMigrateConfigHandlesSelectionRetiredRulesAndEmptyMinimumSeverity(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "old.yaml")
	outPath := filepath.Join(dir, "new.yaml")
	legacy := "minimumSeverity:\r\n" +
		"excludeRules: [naming.negated-boolean, docs.package-comment]\r\n" +
		"selection:\r\n" +
		"  excludeRules:\r\n" +
		"    - design.hotspot-file\r\n" +
		"rules:\r\n" +
		"  naming-negated-boolean:\r\n" +
		"    enabled: false\r\n"
	if err := os.WriteFile(inPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"migrate-config", "--config", inPath, "--output", outPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("migrate-config exit = %d, stderr=%s", code, stderr.String())
	}
	written, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defaults := rule.Defaults()
	if _, err := config.Parse(written, defaults.Definitions()); err != nil {
		t.Fatalf("migrated config failed config.Parse: %v\n%s", err, written)
	}
	text := string(written)
	if strings.Contains(text, "naming.negated-boolean") || strings.Contains(text, "design.hotspot-file") || strings.Contains(text, "naming-negated-boolean") {
		t.Fatalf("retired rule remained in migrated config:\n%s", text)
	}
	if !strings.Contains(text, "docs.package-comment") {
		t.Fatalf("surviving rule docs.package-comment was dropped:\n%s", text)
	}
}

// TestProjectRootRejectsUnrelatedExternalProjects ensures summary/report/baseline reject multiple targets from unrelated projects.
func TestProjectRootRejectsUnrelatedExternalProjects(t *testing.T) {
	workspace := t.TempDir()
	launch := filepath.Join(workspace, "launch")
	projA := filepath.Join(workspace, "proj-a")
	projB := filepath.Join(workspace, "proj-b")
	for _, dir := range []string{launch, projA, projB} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(projA, "go.mod"), []byte("module example.com/a\n\ngo 1.25.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projB, "go.mod"), []byte("module example.com/b\n\ngo 1.25.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projA, "a.go"), []byte("// Package a.\npackage a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projB, "b.go"), []byte("// Package b.\npackage b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(launch)

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"summary", projA, projB}, &stdout, &stderr); code != 2 {
		t.Fatalf("summary on two unrelated external projects exit = %d, want 2; stderr=%s", code, stderr.String())
	}

	loose := filepath.Join(workspace, "loose")
	if err := os.MkdirAll(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(loose, "c.go"), []byte("// Package c.\npackage c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"summary", projA, loose}, &stdout, &stderr); code != 2 {
		t.Fatalf("summary mixing external project and unmarked folder exit = %d, want 2; stderr=%s", code, stderr.String())
	}
}

// TestHookBaselineCleansEscapingAbsolutePath ensures an uncleaned absolute baseline path outside projectRoot omits run.baseline.path.
func TestHookBaselineCleansEscapingAbsolutePath(t *testing.T) {
	workspace := t.TempDir()
	proj := filepath.Join(workspace, "proj")
	outside := filepath.Join(workspace, "outside")
	for _, dir := range []string{proj, outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	baseFile, err := baseline.FromFindings([]finding.Finding{})
	if err != nil {
		t.Fatal(err)
	}
	outsidePath := filepath.Join(outside, "base.json")
	if err := baseline.Write(outsidePath, baseFile); err != nil {
		t.Fatal(err)
	}
	// Construct an uncleaned absolute path starting with proj/.. that escapes proj.
	tricky := proj + string(filepath.Separator) + ".." + string(filepath.Separator) + "outside" + string(filepath.Separator) + "base.json"
	loaded, err := hookFindingBaselineFromFile(proj, tricky)
	if err != nil {
		t.Fatalf("hookFindingBaselineFromFile error = %v", err)
	}
	if loaded.path != "" {
		t.Fatalf("loaded.path = %q, want empty for external baseline outside projectRoot", loaded.path)
	}
}
