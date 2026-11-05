// Package config tests cover the default-config renderer behind gruff-go init.
//
// Render must emit a YAML body that Parse reads back into the same enablement, severity and threshold values that rule.Defaults() exposes.
// That keeps the file gruff-go init and the interactive bootstrap write from silently drifting from the live registry.
package config

import (
	"reflect"
	"strings"
	"testing"
)

// TestRenderRoundTripsThroughParse verifies that every rule's enablement, severity and thresholds survive a Render -> Parse cycle.
//
// Rule-value mismatches mean a fresh gruff-go init file would load with different enablement, severity or thresholds.
// It also requires the schemaVersion line and the analyse --generate-baseline fresh-start hint.
func TestRenderRoundTripsThroughParse(t *testing.T) {
	definitions := defaultDefinitions()
	rendered := Render(definitions, RenderOptions{})
	if !strings.Contains(string(rendered), "schemaVersion") {
		t.Fatalf("rendered config missing schemaVersion line:\n%s", rendered)
	}
	if !strings.Contains(string(rendered), "gruff-go analyse --generate-baseline gruff-baseline.json .") {
		t.Fatalf("rendered config missing fresh-start baseline hint:\n%s", rendered)
	}
	cfg, err := Parse(rendered, definitions)
	if err != nil {
		t.Fatalf("rendered config did not parse: %v\nbody:\n%s", err, rendered)
	}
	options := cfg.RuleOptions()
	for _, definition := range definitions {
		if got, want := options.Enabled[definition.ID], definition.DefaultEnabled; got != want {
			t.Fatalf("rule %s enabled = %v, want %v", definition.ID, got, want)
		}
		if got, want := options.Severities[definition.ID], definition.Severity; got != want {
			t.Fatalf("rule %s severity = %q, want %q", definition.ID, got, want)
		}
		for name, want := range definition.Thresholds {
			got, ok := options.Thresholds[definition.ID][name]
			if !ok {
				t.Fatalf("rule %s threshold %q missing from rendered config", definition.ID, name)
			}
			if got != want {
				t.Fatalf("rule %s threshold %q = %v, want %v", definition.ID, name, got, want)
			}
		}
	}
}

// TestRenderEmitsCanonicalSeverityNames asserts the rendered file uses the ADR-009 severity names advisory, warning and error verbatim.
//
// There is no notice/warn alias layer, so the internal severity name equals the rendered name.
// A legacy name such as low, critical, info or notice on a severity line fails the test.
func TestRenderEmitsCanonicalSeverityNames(t *testing.T) {
	body := string(Render(defaultDefinitions(), RenderOptions{}))
	for _, name := range []string{"advisory", "warning", "error"} {
		if !strings.Contains(body, "severity: "+name) {
			t.Fatalf("rendered body missing canonical severity name %q:\n%s", name, body)
		}
	}
	for _, legacy := range []string{"low", "medium", "high", "critical", "info", "notice"} {
		if strings.Contains(body, "severity: "+legacy+"\n") {
			t.Fatalf("rendered body should not emit legacy severity name %q:\n%s", legacy, body)
		}
	}
}

// TestRenderPreservesEveryDefaultEnabledRule asserts the rendered file holds a rule block for every definition defaultDefinitions returns.
// Looking for each rule's block header is the cheap check; TestRenderRoundTripsThroughParse proves field-level fidelity.
func TestRenderPreservesEveryDefaultEnabledRule(t *testing.T) {
	definitions := defaultDefinitions()
	body := string(Render(definitions, RenderOptions{}))
	for _, definition := range definitions {
		if !strings.Contains(body, "\n  "+definition.ID+":\n") {
			t.Fatalf("rendered config missing rule block %q", definition.ID)
		}
	}
}

// TestRenderPreservesExistingScaffoldTuning verifies that paths.ignore and allowlists.acceptedAbbreviations survive a regenerate.
//
// This is the safeguard that makes gruff-go init --force merge project-wide tuning from RenderOptions.Existing rather than clobber it.
func TestRenderPreservesExistingScaffoldTuning(t *testing.T) {
	definitions := defaultDefinitions()
	existing := &Config{
		IgnorePaths:           []string{".claude/**", "internal/rule/sensitive_test.go"},
		AcceptedAbbreviations: []string{"ID", "HTTP"},
	}
	body := string(Render(definitions, RenderOptions{Existing: existing}))
	for _, want := range []string{".claude/**", "internal/rule/sensitive_test.go", "- ID", "- HTTP"} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered body missing preserved value %q:\n%s", want, body)
		}
	}
	// An empty ignore list here means Render dropped the user's paths.ignore, so init --force would wipe their tuning.
	if strings.Contains(body, "ignore: []") {
		t.Fatalf("paths.ignore should not be empty when preserved values were supplied:\n%s", body)
	}
}

// TestInitAcceptedAbbreviationsFamilySeed pins a fresh gruff-go init file to the ratified 16-word family abbreviation list.
// Preserving an existing config's list is left to TestRenderPreservesExistingScaffoldTuning.
func TestInitAcceptedAbbreviationsFamilySeed(t *testing.T) {
	definitions := defaultDefinitions()
	configBody := Render(definitions, RenderOptions{})
	parsed, err := Parse(configBody, definitions)
	if err != nil {
		t.Fatalf("fresh init config did not parse: %v", err)
	}
	want := []string{"age", "app", "db", "fs", "id", "io", "key", "log", "max", "min", "now", "raw", "rx", "tx", "ui", "url"}
	if got := parsed.AcceptedAbbreviations; !reflect.DeepEqual(got, want) {
		t.Fatalf("fresh init acceptedAbbreviations = %q, want family seed %q", got, want)
	}
}

// TestRenderOmitsTheRemovedSecretPreviewsKey keeps the generator from writing a key the loader now refuses.
//
// Section 5 made category markers unconditional, so a generated file offering to configure them would produce a
// configuration that fails to load on the very port that wrote it.
func TestRenderOmitsTheRemovedSecretPreviewsKey(t *testing.T) {
	definitions := defaultDefinitions()
	body := string(Render(definitions, RenderOptions{}))
	if strings.Contains(body, "secretPreviews") {
		t.Fatalf("rendered config still offers the removed secretPreviews key:\n%s", body)
	}
	if strings.Contains(body, "unconditional") == false {
		t.Fatalf("rendered config does not explain that markers are unconditional:\n%s", body)
	}
	// A failure here means gruff-go init writes a file that the same binary then refuses to load.
	if _, err := Parse([]byte(body), definitions); err != nil {
		t.Fatalf("generated config does not load on the port that wrote it: %v", err)
	}
}

// TestRenderWritesBothSeverityKeys pins the split the family contract ratified: failOn gates, minimumSeverity displays.
func TestRenderWritesBothSeverityKeys(t *testing.T) {
	body := string(Render(defaultDefinitions(), RenderOptions{}))
	for _, want := range []string{"failOn:", "  analyse: advisory", "minimumSeverity: advisory", "failOn above is what gates a build"} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered config missing %q:\n%s", want, body)
		}
	}
}

// TestRenderPreservesPerRuleOverrides confirms a regenerated config keeps an existing config's per-rule threshold, disable and options overrides.
// The fixture also sets a severity override without asserting it; rules without overrides still render registry defaults.
func TestRenderPreservesPerRuleOverrides(t *testing.T) {
	definitions := defaultDefinitions()
	customThreshold := 4.0
	acronymCaseEnabled := false
	existing := &Config{
		Rules: map[string]RuleConfig{
			"complexity.nesting-depth": {
				Severity:  "warning",
				Threshold: &customThreshold,
			},
			"docs.comment-rubric": {
				Options: map[string]any{
					"requirePackageSummary":   true,
					"requireFunctionComments": true,
					"minWordsBeyondSymbol":    3,
				},
			},
			"naming.acronym-case": {
				Enabled: &acronymCaseEnabled,
			},
		},
	}
	body := string(Render(definitions, RenderOptions{Existing: existing}))
	cfg, err := Parse([]byte(body), definitions)
	if err != nil {
		t.Fatalf("rendered body did not parse: %v\nbody:\n%s", err, body)
	}
	options := cfg.RuleOptions()
	if got := options.Thresholds["complexity.nesting-depth"]["maxDepth"]; got != 4 {
		t.Fatalf("complexity.nesting-depth maxDepth = %v, want 4 (preserved)", got)
	}
	if got := options.Enabled["naming.acronym-case"]; got {
		t.Fatalf("naming.acronym-case enabled = true, want false (preserved disable)")
	}
	rubricOptions := options.Options["docs.comment-rubric"]
	if rubricOptions["requirePackageSummary"] != true {
		t.Fatalf("docs.comment-rubric.requirePackageSummary = %v, want true (preserved)", rubricOptions["requirePackageSummary"])
	}
	if rubricOptions["minWordsBeyondSymbol"] == nil {
		t.Fatalf("docs.comment-rubric.minWordsBeyondSymbol missing from preserved options: %#v", rubricOptions)
	}
}

// TestRenderEmitsSingleThresholdAsScalar checks the singular threshold: form for a rule with exactly one knob, such as size.file-length.
//
// A rule with several knobs, such as design.hotspot-file, keeps the plural thresholds: map.
// The singular form matches the convention used in the dogfood .gruff-go.yaml and in adopters' configs.
func TestRenderEmitsSingleThresholdAsScalar(t *testing.T) {
	body := string(Render(defaultDefinitions(), RenderOptions{}))
	if !strings.Contains(body, "size.file-length:\n    enabled: true\n    severity: error\n    threshold: 1000\n") {
		t.Fatalf("expected singular threshold form for size.file-length; got:\n%s", body)
	}
	if !strings.Contains(body, "design.hotspot-file:\n    enabled: true\n    severity: advisory\n    thresholds:\n      minFindings: 3\n      minPillars: 2\n") {
		t.Fatalf("expected plural thresholds form for design.hotspot-file; got:\n%s", body)
	}
}
