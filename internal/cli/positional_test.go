// Package cli tests the command-line behavior exposed by gruff-go.
// These tests pin what happens to positional arguments on commands that do not consume them, so a
// named scan target can never be accepted and then silently dropped.
package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCommandsRejectUnusedPositionalArguments verifies commands that take no operands fail loudly.
// The fixture path is real: rejection must come from the argument contract, not from a missing file.
func TestCommandsRejectUnusedPositionalArguments(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	t.Chdir(projectRoot)

	testCases := []struct {
		name            string
		arguments       []string
		expectedMessage string
	}{
		{
			name:            "list-rules",
			arguments:       []string{"list-rules", "--no-config", "main.go"},
			expectedMessage: "list-rules takes no positional arguments",
		},
		{
			// The dashboard names scan targets through flags, so an operand here is a target the
			// user asked for and the server would never scan.
			name:            "dashboard",
			arguments:       []string{"dashboard", "--no-config", "main.go"},
			expectedMessage: "dashboard takes no positional arguments",
		},
		{
			name:            "completion second shell",
			arguments:       []string{"completion", "bash", "zsh"},
			expectedMessage: "completion takes at most one shell argument",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			exitCode, stdout, stderr := captureCLIResult(testCase.arguments)
			if exitCode != 2 {
				t.Fatalf("exit = %d, want 2; stdout=%s stderr=%s", exitCode, stdout, stderr)
			}
			if !strings.Contains(stderr, testCase.expectedMessage) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr, testCase.expectedMessage)
			}
			if len(stdout) != 0 {
				t.Fatalf("stdout = %q, want empty so machine consumers never receive prose", stdout)
			}
		})
	}
}

// TestCommandsStillAcceptTheirSupportedForms verifies the guards reject only surplus operands.
// The dashboard is absent by necessity: its accepted form binds a listener and never returns.
func TestCommandsStillAcceptTheirSupportedForms(t *testing.T) {
	projectRoot := t.TempDir()
	t.Chdir(projectRoot)

	testCases := []struct {
		name      string
		arguments []string
	}{
		{name: "list-rules text", arguments: []string{"list-rules", "--no-config", "--format", "text"}},
		{name: "completion explicit shell", arguments: []string{"completion", "bash"}},
		{name: "completion default shell", arguments: []string{"completion"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			exitCode, stdout, stderr := captureCLIResult(testCase.arguments)
			if exitCode != 0 {
				t.Fatalf("exit = %d, want 0; stderr=%s", exitCode, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("stdout empty, want the command's normal output")
			}
		})
	}
}

// TestCompletionDefaultShellMatchesExplicitBash verifies the operand guard left the default intact.
// A guard written as NArg() > 0 instead of > 1 would silently break the bare-completion form.
func TestCompletionDefaultShellMatchesExplicitBash(t *testing.T) {
	t.Chdir(t.TempDir())

	defaultExit, defaultStdout, defaultStderr := captureCLIResult([]string{"completion"})
	explicitExit, explicitStdout, explicitStderr := captureCLIResult([]string{"completion", "bash"})

	if defaultExit != 0 || explicitExit != 0 {
		t.Fatalf("exits = %d and %d, want 0; stderr=%q and %q",
			defaultExit, explicitExit, defaultStderr, explicitStderr)
	}
	if string(defaultStdout) != string(explicitStdout) {
		t.Fatalf("bare completion and explicit bash differ: %d vs %d bytes",
			len(defaultStdout), len(explicitStdout))
	}
}

// TestJSONReportSurvivesADiagnosticAboutAFileOutsideTheProject pins the envelope against the one path that used to
// suppress it. A baseline the run cannot read produces a run-invalidating diagnostic naming that file; launched from
// a sibling directory the file sits outside the project, so it has no project-relative form. Publishing the report
// without the optional key is what the other four ports do, and §5 of the decided contract requires a refusal after
// argument parsing to publish the envelope rather than exit with an empty stdout.
func TestJSONReportSurvivesADiagnosticAboutAFileOutsideTheProject(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	launch := filepath.Join(root, "launch")
	for _, directory := range []string{project, launch} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", directory, err)
		}
	}
	writeFile(t, project, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")
	writeFile(t, root, "unreadable.json", "{\"schemaVersion\": \"gruff.baseline.v3\", \"toolLanguage\": \"go\", \"nope\": []}\n")

	t.Chdir(launch)
	exitCode, stdout, stderr := captureCLIResult([]string{"analyse", "--no-config", "--baseline", "../unreadable.json", "--fail-on", "none", "--format", "json", "../project"})
	if exitCode != 2 {
		t.Fatalf("outside diagnostic: exit %d, want 2; stderr=%q", exitCode, stderr)
	}
	if len(stdout) == 0 {
		t.Fatalf("outside diagnostic: stdout is empty, so the envelope was suppressed; stderr=%q", stderr)
	}
	var report struct {
		SchemaVersion string `json:"schemaVersion"`
		Diagnostics   []struct {
			Type string  `json:"type"`
			File *string `json:"file"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(stdout, &report); err != nil {
		t.Fatalf("outside diagnostic: stdout is not JSON: %v\n%s", err, stdout)
	}
	if report.SchemaVersion != "gruff.analysis.v3" {
		t.Fatalf("schemaVersion = %q, want gruff.analysis.v3", report.SchemaVersion)
	}
	if len(report.Diagnostics) != 1 || report.Diagnostics[0].Type != "baseline" {
		t.Fatalf("diagnostics = %#v, want one baseline diagnostic", report.Diagnostics)
	}
	if report.Diagnostics[0].File != nil {
		t.Fatalf("diagnostic file = %q, want it left out for a file outside the project", *report.Diagnostics[0].File)
	}
}

// TestLaunchDirectoryDoesNotChangeTheResult verifies analyse, summary and report JSON, and a generated baseline, come
// out the same whether the project is named from inside it, from a sibling directory (`../project`), or from one of
// its own subdirectories (`..`). Before the root came from the target, summary and report exited 2 with nothing on
// stdout from a sibling; before operands were read from the launch directory, `..` from a subdirectory scanned the
// directory above the project, here holding stray.go, and every command crashed on it.
func TestLaunchDirectoryDoesNotChangeTheResult(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	launches := map[string]string{filepath.Join(root, "launch"): "../project", filepath.Join(project, "sub"): ".."}
	for directory := range launches {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", directory, err)
		}
	}
	writeFile(t, project, "main.go", "package main\n\nfunc Exported(unused int) {}\n\nfunc main() {}\n")
	writeFile(t, root, "stray.go", "package stray\n\nfunc Stray(unused int) {}\n")

	run := func(directory string, commandArguments []string) (int, string) {
		t.Chdir(directory)
		exitCode, stdout, stderr := captureCLIResult(commandArguments)
		if len(stdout) == 0 {
			t.Fatalf("%v from %s: empty stdout, exit %d, stderr=%q", commandArguments, directory, exitCode, stderr)
		}
		return exitCode, string(stdout)
	}
	stable := func(label, stdout string) string {
		var envelope struct {
			Findings []map[string]any `json:"findings"`
			Score    map[string]any   `json:"score"`
			Summary  map[string]any   `json:"summary"`
		}
		if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
			t.Fatalf("%s: stdout is not JSON: %v", label, err)
		}
		encoded, _ := json.Marshal(envelope)
		return string(encoded)
	}
	for _, command := range []string{"analyse", "summary", "report"} {
		insideExit, insideStdout := run(project, []string{command, "--no-config", "--fail-on", "none", "--format", "json", "."})
		inside := stable(command+" inside", insideStdout)
		for directory, target := range launches {
			outsideExit, outsideStdout := run(directory, []string{command, "--no-config", "--fail-on", "none", "--format", "json", target})
			outside := stable(command+" "+target, outsideStdout)
			if insideExit != outsideExit || inside != outside {
				t.Fatalf("%s %s differs by launch directory:\ninside  exit %d %s\noutside exit %d %s", command, target, insideExit, inside, outsideExit, outside)
			}
		}
	}

	baselineOf := func(directory, target, name string) string {
		run(directory, []string{"analyse", "--no-config", "--generate-baseline", filepath.Join(root, name), target})
		contents, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var baseline struct {
			Occurrences []map[string]any `json:"occurrences"`
		}
		if err := json.Unmarshal(contents, &baseline); err != nil {
			t.Fatalf("%s is not JSON: %v", name, err)
		}
		encoded, _ := json.Marshal(baseline)
		return string(encoded)
	}
	inside := baselineOf(project, ".", "inside.json")
	for directory, target := range launches {
		outside := baselineOf(directory, target, "outside.json")
		if outside != inside || strings.Contains(outside, root) {
			t.Fatalf("baseline from %s differs by launch directory:\noutside %s\ninside  %s", target, outside, inside)
		}
	}
}

// TestProjectConfigIsReadFromTheProjectRoot verifies the project's .gruff-go.yaml applies whichever directory the scan
// is launched from. It was looked up in the launch directory, so a scan of /srv/checkout from elsewhere, the shape CI
// uses, silently ran without the project's rules, gates and sensitive exclusions.
func TestProjectConfigIsReadFromTheProjectRoot(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	launches := map[string]string{project: ".", filepath.Join(root, "launch"): "../project", filepath.Join(project, "sub"): ".."}
	for directory := range launches {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", directory, err)
		}
	}
	writeFile(t, project, "main.go", "package main\n\nfunc Exported() {}\n\nfunc main() {}\n")
	writeFile(t, project, ".gruff-go.yaml", "schemaVersion: gruff-go.config.v0.1\nrules:\n  docs.exported-symbol-comment:\n    enabled: false\n")

	for directory, target := range launches {
		t.Chdir(directory)
		exitCode, stdout, stderr := captureCLIResult([]string{"analyse", "--no-baseline", "--fail-on", "none", "--format", "json", target})
		if exitCode != 0 {
			t.Fatalf("%s from %s: exit %d, stderr=%q", target, directory, exitCode, stderr)
		}
		var envelope struct {
			Findings []struct {
				RuleID string `json:"ruleId"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(stdout, &envelope); err != nil {
			t.Fatalf("%s from %s: stdout is not JSON: %v", target, directory, err)
		}
		for _, finding := range envelope.Findings {
			if finding.RuleID == "docs.exported-symbol-comment" {
				t.Fatalf("%s from %s: the project config disables docs.exported-symbol-comment, but it reported", target, directory)
			}
		}
	}
}

// TestBaselinePathsAreReadFromTheLaunchDirectory verifies --generate-baseline and --baseline mean the path typed from
// two levels inside the project. The write already landed there; the read joined the path to the project root, missed
// the file, and published the joined host path in the diagnostic.
func TestBaselinePathsAreReadFromTheLaunchDirectory(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	nested := filepath.Join(project, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", nested, err)
	}
	writeFile(t, project, "main.go", "package main\n\nfunc Exported() {}\n\nfunc main() {}\n")
	t.Chdir(nested)

	if exitCode, _, stderr := captureCLIResult([]string{"analyse", "--no-config", "--fail-on", "none", "--generate-baseline", "../../base.json", "../.."}); exitCode != 0 {
		t.Fatalf("generate: exit %d, stderr=%q", exitCode, stderr)
	}
	if _, err := os.Stat(filepath.Join(project, "base.json")); err != nil {
		t.Fatalf("the baseline was not written at the project root: %v", err)
	}
	exitCode, stdout, stderr := captureCLIResult([]string{"analyse", "--no-config", "--fail-on", "none", "--format", "json", "--baseline", "../../base.json", "../.."})
	if exitCode != 0 {
		t.Fatalf("apply: exit %d, stderr=%q", exitCode, stderr)
	}
	var envelope struct {
		Baseline map[string]any `json:"baseline"`
	}
	if err := json.Unmarshal(stdout, &envelope); err != nil {
		t.Fatalf("apply: stdout is not JSON: %v", err)
	}
	if envelope.Baseline["applied"] != true || envelope.Baseline["path"] != "base.json" {
		t.Fatalf("baseline = %v, want applied with path base.json", envelope.Baseline)
	}

	_, stdout, _ = captureCLIResult([]string{"analyse", "--no-config", "--fail-on", "none", "--format", "json", "--baseline", "../../missing.json", "../.."})
	if strings.Contains(string(stdout), root) {
		t.Fatalf("a missing baseline's diagnostic names the host path: %s", stdout)
	}
}

// TestJSONReportSurvivesATargetAndABaselineOutsideTheLaunchDirectory verifies a scan launched from a sibling
// directory still publishes its report. The operand `../project` names the project itself, so the report lists it as
// `.`, and a baseline kept outside the project is applied and simply has no project-relative path to publish.
func TestJSONReportSurvivesATargetAndABaselineOutsideTheLaunchDirectory(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	launch := filepath.Join(root, "launch")
	for _, directory := range []string{project, launch} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", directory, err)
		}
	}
	writeFile(t, project, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")

	t.Chdir(launch)
	exitCode, stdout, stderr := captureCLIResult([]string{"analyse", "--no-config", "--no-baseline", "--fail-on", "none", "--format", "json", "../project"})
	if exitCode != 0 {
		t.Fatalf("relative target: exit %d, stderr=%q", exitCode, stderr)
	}
	var fromSibling struct {
		Run struct {
			Inputs []string `json:"inputs"`
		} `json:"run"`
	}
	if err := json.Unmarshal([]byte(stdout), &fromSibling); err != nil {
		t.Fatalf("relative target: stdout is not JSON: %v", err)
	}
	if len(fromSibling.Run.Inputs) != 1 || fromSibling.Run.Inputs[0] != "." {
		t.Fatalf("run.inputs = %v, want [.]", fromSibling.Run.Inputs)
	}

	t.Chdir(project)
	if exitCode, _, stderr := captureCLIResult([]string{"baseline", "--no-config", "--out", "../reviewed.json"}); exitCode != 0 {
		t.Fatalf("baseline generation: exit %d, stderr=%q", exitCode, stderr)
	}
	exitCode, stdout, stderr = captureCLIResult([]string{"analyse", "--no-config", "--baseline", "../reviewed.json", "--fail-on", "none", "--format", "json", "."})
	if exitCode != 0 {
		t.Fatalf("outside baseline: exit %d, stderr=%q", exitCode, stderr)
	}
	var withBaseline struct {
		Baseline map[string]any `json:"baseline"`
	}
	if err := json.Unmarshal([]byte(stdout), &withBaseline); err != nil {
		t.Fatalf("outside baseline: stdout is not JSON: %v", err)
	}
	if withBaseline.Baseline["applied"] != true {
		t.Fatalf("baseline.applied = %v, want true", withBaseline.Baseline["applied"])
	}
	if _, published := withBaseline.Baseline["path"]; published {
		t.Fatalf("baseline.path = %v, want it left out for a baseline outside the project", withBaseline.Baseline["path"])
	}
}
