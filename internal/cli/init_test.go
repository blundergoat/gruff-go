// Package cli tests cover the init subcommand and the interactive bootstrap.
// The init checks lock in the file-creation contract (default path, --force
// behaviour, refusal to clobber); the bootstrap checks lock in the prompt
// gating (skip on -n, skip on non-TTY stdin, skip when --config or --no-config
// already disambiguate intent, write the file on an affirmative answer).
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

// TestInitWritesDefaultConfigFile checks the default invocation path: the
// file lands at .gruff-go.yaml in the working directory and parses cleanly
// through the config loader.
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

// TestInitForcePreservesExistingTuning is the regression test for the
// 8282478-style wipe: a hand-tuned .gruff-go.yaml must survive `init --force`
// with its paths.ignore, allowlists, and per-rule overrides intact. The
// regenerate is a merge, not a clobber.
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

// TestInitForceResetDiscardsExistingTuning verifies the explicit escape hatch:
// `init --force --reset` performs the old destructive overwrite for callers
// who really do want a fresh defaults file.
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

// TestBootstrapPromptCreatesConfigOnYes runs the analyse path with a faked
// TTY stdin that answers "y" and confirms the file gets written before the
// scan continues with the configured registry.
func TestBootstrapPromptCreatesConfigOnYes(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")

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
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")

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
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")

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
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")

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

// TestBootstrapPromptDecliningKeepsBuiltInDefaults verifies that answering
// anything other than "y" leaves no config file on disk and still completes
// the scan.
func TestBootstrapPromptDecliningKeepsBuiltInDefaults(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")

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

// withFakeTerminalStdin swaps the prompt reader (and forces the TTY check to
// pass) for the duration of a test, restoring the prior state afterwards so
// neighbouring tests are not affected.
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
