// Package cli tests cover the init subcommand and the interactive config bootstrap that analyse offers.
//
// The init tests lock in the file contract: default path, refusal to overwrite, the --force merge that keeps tuning, and --force --reset.
//
// With no config, analyse can offer to write one; these tests check that -n and --no-config skip the offer.
// Here a y answer writes the file, an n answer keeps built-in defaults, and prompt text goes to stderr so JSON on stdout stays valid.
package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// TestInitWritesDefaultConfigFile checks plain gruff-go init writes .gruff-go.yaml in the working directory and that it parses cleanly.
//
// It also pins the stdout confirmation and the baseline hint, and that init prints the baseline command without creating gruff-baseline.json.
func TestInitWritesDefaultConfigFile(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init exit = %d, stderr = %s", code, stderr.String())
	}
	target := filepath.Join(root, ".gruff-go.yaml")
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("expected %s to exist: %v", target, err)
	}
	if _, err := cfgpkg.Parse(body, ruleDefinitionsForTest()); err != nil {
		t.Fatalf("generated config did not parse: %v\nbody:\n%s", err, body)
	}
	if !strings.Contains(stdout.String(), "wrote default config to .gruff-go.yaml") {
		t.Fatalf("stdout missing confirmation line: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "gruff-go analyse --generate-baseline gruff-baseline.json .") {
		t.Fatalf("stdout missing baseline fresh-start hint: %s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(root, "gruff-baseline.json")); !os.IsNotExist(err) {
		t.Fatalf("init should only print baseline guidance, not create gruff-baseline.json; stat err = %v", err)
	}
}

// TestInitRefusesToOverwriteWithoutForce makes sure a second init call does
// not silently clobber existing edits. The user must opt in with --force.
func TestInitRefusesToOverwriteWithoutForce(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.WriteFile(filepath.Join(root, ".gruff-go.yaml"), []byte("custom: yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init"}, &stdout, &stderr); code != 1 {
		t.Fatalf("init exit = %d, stderr = %s, stdout = %s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("stderr missing already-exists message: %s", stderr.String())
	}
	body, err := os.ReadFile(filepath.Join(root, ".gruff-go.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "custom: yes\n" {
		t.Fatalf("existing config was overwritten without --force: %s", body)
	}
}

// TestInitForceOverwritesExistingConfig confirms --force replaces an existing
// config and that the new file parses cleanly.
func TestInitForceOverwritesExistingConfig(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.WriteFile(filepath.Join(root, ".gruff-go.yaml"), []byte("custom: yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--force"}, &stdout, &stderr); code != 0 {
		t.Fatalf("force init exit = %d, stderr = %s", code, stderr.String())
	}
	body, err := os.ReadFile(filepath.Join(root, ".gruff-go.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) == "custom: yes\n" {
		t.Fatalf("--force did not replace the file")
	}
	if _, err := cfgpkg.Parse(body, ruleDefinitionsForTest()); err != nil {
		t.Fatalf("forced config did not parse: %v", err)
	}
}

// TestInitForcePreservesExistingTuning verifies init --force merges existing tuning into the regenerated config instead of clobbering it.
//
// A hand-tuned .gruff-go.yaml keeps its paths.ignore, allowlists and per-rule overrides, and stderr says the tuning was preserved.
func TestInitForcePreservesExistingTuning(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	tuned := `schemaVersion: "gruff-go.config.v0.1"
paths:
  ignore:
    - '.claude/**'
    - 'internal/rule/sensitive_test.go'
allowlists:
  acceptedAbbreviations:
    - ID
    - HTTP
rules:
  complexity.nesting-depth:
    enabled: true
    severity: warning
    threshold: 4
  docs.comment-rubric:
    enabled: true
    severity: warning
    threshold: 2
    options:
      requirePackageSummary: true
      requireFunctionComments: true
      minWordsBeyondSymbol: 3
`
	if err := os.WriteFile(filepath.Join(root, ".gruff-go.yaml"), []byte(tuned), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--force"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init --force exit = %d, stderr = %s", code, stderr.String())
	}
	body, err := os.ReadFile(filepath.Join(root, ".gruff-go.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(body)
	for _, want := range []string{".claude/**", "internal/rule/sensitive_test.go", "- ID", "- HTTP", "minWordsBeyondSymbol: 3", "requirePackageSummary: true"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("init --force lost preserved value %q\nrendered:\n%s", want, rendered)
		}
	}
	if !strings.Contains(rendered, "threshold: 4") {
		t.Fatalf("init --force lost preserved complexity.nesting-depth threshold:\n%s", rendered)
	}
	if !strings.Contains(stderr.String(), "preserved existing tuning") {
		t.Fatalf("stderr should describe preservation: %s", stderr.String())
	}
	cfg, err := cfgpkg.Parse(body, ruleDefinitionsForTest())
	if err != nil {
		t.Fatalf("merged config did not parse back: %v\nbody:\n%s", err, body)
	}
	if len(cfg.IgnorePaths) != 2 {
		t.Fatalf("merged config IgnorePaths = %#v, want 2 entries", cfg.IgnorePaths)
	}
}

// TestInitForcePreservesPreADR009Config locks in the v0.2.0 migration contract for init --force on a pre-0.2 config.
//
// Legacy severity overrides revert to registry defaults; paths.ignore, allowlists, thresholds and options must survive.
// When the strict load fails the old config must still be recovered; the prior-tuning-lost warning would mean it was not.
func TestInitForcePreservesPreADR009Config(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	tuned := `schemaVersion: "gruff-go.config.v0.1"
paths:
  ignore:
    - '.claude/**'
    - 'internal/rule/sensitive_test.go'
allowlists:
  acceptedAbbreviations:
    - ID
rules:
  complexity.nesting-depth:
    enabled: true
    severity: medium
    threshold: 4
  docs.comment-rubric:
    enabled: true
    severity: notice
    threshold: 2
    options:
      minWordsBeyondSymbol: 3
`
	if err := os.WriteFile(filepath.Join(root, ".gruff-go.yaml"), []byte(tuned), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--force"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init --force exit = %d, stderr = %s", code, stderr.String())
	}
	body, err := os.ReadFile(filepath.Join(root, ".gruff-go.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(body)
	for _, want := range []string{".claude/**", "internal/rule/sensitive_test.go", "- ID", "minWordsBeyondSymbol: 3", "threshold: 4"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("init --force lost preserved value %q\nrendered:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "severity: medium") || strings.Contains(rendered, "severity: notice") {
		t.Fatalf("legacy severity values must not round-trip; rendered:\n%s", rendered)
	}
	// The prior-tuning-lost warning means the old tuning was not recovered, so this legacy-severity fixture must never produce it.
	if strings.Contains(stderr.String(), "prior tuning was lost") {
		t.Fatalf("permissive fallback should suppress the parse-error warning: %s", stderr.String())
	}
	cfg, err := cfgpkg.Parse(body, ruleDefinitionsForTest())
	if err != nil {
		t.Fatalf("merged config did not parse back: %v\nbody:\n%s", err, body)
	}
	if len(cfg.IgnorePaths) != 2 {
		t.Fatalf("merged config IgnorePaths = %#v, want 2 entries", cfg.IgnorePaths)
	}
}

// TestInitForcePreservesFailOnBlock is the regression test for ADR-010's preservation contract on the failOn block.
//
// A project that tuned failOn, for example analyse: error, must keep every entry across init --force and see the count on stderr.
// The regenerated file must also parse back with the tuned analyse and dashboard entries intact.
func TestInitForcePreservesFailOnBlock(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	tuned := `schemaVersion: "gruff-go.config.v0.1"
failOn:
  analyse: error
  summary: error
  report: warning
  dashboard: advisory
`
	if err := os.WriteFile(filepath.Join(root, ".gruff-go.yaml"), []byte(tuned), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--force"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init --force exit = %d, stderr = %s", code, stderr.String())
	}
	body, err := os.ReadFile(filepath.Join(root, ".gruff-go.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(body)
	for _, want := range []string{
		"analyse: error",
		"summary: error",
		"report: warning",
		"dashboard: advisory",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("init --force lost preserved failOn entry %q\nrendered:\n%s", want, rendered)
		}
	}
	if !strings.Contains(stderr.String(), "failOn entries") {
		t.Fatalf("stderr should mention preserved failOn count: %s", stderr.String())
	}
	cfg, err := cfgpkg.Parse(body, ruleDefinitionsForTest())
	if err != nil {
		t.Fatalf("merged config did not parse back: %v\nbody:\n%s", err, body)
	}
	if cfg.FailOn["analyse"] != "error" || cfg.FailOn["dashboard"] != "advisory" {
		t.Fatalf("round-trip lost FailOn entries: %#v", cfg.FailOn)
	}
}

// TestInitForceResetDiscardsExistingTuning verifies the explicit escape hatch, init --force --reset, for users who want a fresh defaults file.
//
// Here the old destructive overwrite is wanted: preserved paths.ignore entries vanish and the file carries an empty ignore list.
func TestInitForceResetDiscardsExistingTuning(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	tuned := `schemaVersion: "gruff-go.config.v0.1"
paths:
  ignore:
    - '.claude/**'
`
	if err := os.WriteFile(filepath.Join(root, ".gruff-go.yaml"), []byte(tuned), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--force", "--reset"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init --force --reset exit = %d, stderr = %s", code, stderr.String())
	}
	body, err := os.ReadFile(filepath.Join(root, ".gruff-go.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), ".claude/**") {
		t.Fatalf("--reset must wipe preserved values; got:\n%s", body)
	}
	if !strings.Contains(string(body), "ignore: []") {
		t.Fatalf("--reset must emit empty paths.ignore; got:\n%s", body)
	}
}

// TestInitResetRequiresForce locks in the destructive-reset guard documented in
// the setup footgun: --reset is only meaningful with --force.
func TestInitResetRequiresForce(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--reset"}, &stdout, &stderr); code != 2 {
		t.Fatalf("init --reset exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--reset requires --force") {
		t.Fatalf("stderr missing reset guard: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".gruff-go.yaml")); !os.IsNotExist(err) {
		t.Fatalf("bare --reset must not create a config; stat err = %v", err)
	}
}

// TestBootstrapPromptCreatesConfigOnYes runs analyse with a faked TTY stdin that answers y, as a first run in a project with no config would.
//
// The file must be written before the scan continues with the configured registry, and the prompt, confirmation and baseline hint go to stderr.
func TestBootstrapPromptCreatesConfigOnYes(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")

	withFakeTerminalStdin(t, strings.NewReader("y\n"))

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"analyse", "."}, &stdout, &stderr); code != 0 {
		t.Fatalf("analyse exit = %d, stderr = %s, stdout = %s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".gruff-go.yaml")); err != nil {
		t.Fatalf("expected .gruff-go.yaml to be created: %v", err)
	}
	if strings.Contains(stdout.String(), "Generate one with default settings?") {
		t.Fatalf("stdout must not contain prompt text: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Generate one with default settings?") {
		t.Fatalf("stderr missing prompt: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "wrote default config to .gruff-go.yaml") {
		t.Fatalf("stderr missing write confirmation: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "gruff-go analyse --generate-baseline gruff-baseline.json .") {
		t.Fatalf("stderr missing baseline fresh-start hint: %s", stderr.String())
	}
}

// TestBootstrapPromptDoesNotCorruptJSONOutput verifies interactive bootstrap
// text never precedes machine-readable stdout.
func TestBootstrapPromptDoesNotCorruptJSONOutput(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")

	withFakeTerminalStdin(t, strings.NewReader("y\n"))

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"analyse", "--format", "json", "."}, &stdout, &stderr); code != 0 {
		t.Fatalf("analyse json exit = %d, stderr = %s, stdout = %s", code, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String(), "Generate one with default settings?") {
		t.Fatalf("stdout must not contain prompt text: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Generate one with default settings?") {
		t.Fatalf("stderr missing prompt: %s", stderr.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("stdout is not valid JSON:\n%s", stdout.String())
	}
}

// TestBootstrapPromptSkippedOnNoInteraction asserts that -n keeps analyse
// quiet: no prompt text, no config file on disk, scan still completes.
func TestBootstrapPromptSkippedOnNoInteraction(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")

	withFakeTerminalStdin(t, strings.NewReader("y\n"))

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"-n", "analyse", "."}, &stdout, &stderr); code != 0 {
		t.Fatalf("analyse exit = %d, stderr = %s, stdout = %s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".gruff-go.yaml")); !os.IsNotExist(err) {
		t.Fatalf("expected no .gruff-go.yaml under -n; stat err = %v", err)
	}
	if strings.Contains(stdout.String(), "Generate one with default settings?") {
		t.Fatalf("-n must suppress the prompt; stdout = %s", stdout.String())
	}
}

// TestBootstrapPromptSkippedWithNoConfig confirms --no-config is treated as a
// firm "do not autoload" intent and never triggers the bootstrap prompt.
func TestBootstrapPromptSkippedWithNoConfig(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")

	withFakeTerminalStdin(t, strings.NewReader("y\n"))

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"analyse", "--no-config", "."}, &stdout, &stderr); code != 0 {
		t.Fatalf("analyse exit = %d, stderr = %s, stdout = %s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".gruff-go.yaml")); !os.IsNotExist(err) {
		t.Fatalf("--no-config must skip the bootstrap; stat err = %v", err)
	}
	if strings.Contains(stdout.String(), "Generate one with default settings?") {
		t.Fatalf("--no-config must suppress the prompt; stdout = %s", stdout.String())
	}
}

// TestBootstrapPromptDecliningKeepsBuiltInDefaults verifies that answering n leaves no config file on disk.
//
// The scan still completes with exit 0 on built-in defaults, and the prompt still appears on stderr only.
func TestBootstrapPromptDecliningKeepsBuiltInDefaults(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	writeFile(t, root, "main.go", "// Package main is a test fixture.\npackage main\n\nfunc main() {}\n")

	withFakeTerminalStdin(t, strings.NewReader("n\n"))

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"analyse", "."}, &stdout, &stderr); code != 0 {
		t.Fatalf("analyse exit = %d, stderr = %s, stdout = %s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".gruff-go.yaml")); !os.IsNotExist(err) {
		t.Fatalf("declining the prompt must not create a config; stat err = %v", err)
	}
	if strings.Contains(stdout.String(), "Generate one with default settings?") {
		t.Fatalf("stdout must not contain prompt text: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Generate one with default settings?") {
		t.Fatalf("stderr missing prompt: %s", stderr.String())
	}
}

// withFakeTerminalStdin makes the bootstrap prompt read its answer from reader and forces the TTY check to pass for one test.
//
// Cleanup restores whatever reader and terminal check were set before, so later tests do not share this fake input.
func withFakeTerminalStdin(t *testing.T, reader io.Reader) {
	t.Helper()
	prevReader := promptStdin
	prevCheck := stdinTerminalCheck
	promptStdin = reader
	stdinTerminalCheck = func() bool { return true }
	t.Cleanup(func() {
		promptStdin = prevReader
		stdinTerminalCheck = prevCheck
	})
}

// ruleDefinitionsForTest returns the live registry's catalogue so config.Parse
// can validate the rendered file against the real rule set.
func ruleDefinitionsForTest() []rule.Definition {
	defaults := rule.Defaults()
	return defaults.Definitions()
}
