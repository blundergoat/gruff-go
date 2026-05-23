// Package config tests cover the default-config renderer.
// These checks lock in the round-trip: the YAML body Render emits must parse
// back into the same enablement, severity, and threshold values that
// rule.Defaults() exposes, so `gruff-go init` and the interactive bootstrap
// produce a file that does not silently drift from the live registry.
package config

import (
	"strings"
	"testing"
)

// TestRenderRoundTripsThroughParse verifies that every rule's defaults survive
// a Render -> Parse cycle, so the rendered file is exactly equivalent to the
// registry's built-in policy on first load.
func TestRenderRoundTripsThroughParse(t *testing.T) {
	definitions := defaultDefinitions()
	rendered := Render(definitions)
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

// TestRenderEmitsGruffSeverityAliases checks that severity emission stays in
// the gruff-family vocabulary (notice/warning/error) so the file matches the
// hand-written .gruff-go.yaml style adopters see in docs and existing configs.
func TestRenderEmitsGruffSeverityAliases(t *testing.T) {
	body := string(Render(defaultDefinitions()))
	for _, alias := range []string{"notice", "warning", "error"} {
		if !strings.Contains(body, "severity: "+alias) {
			t.Fatalf("rendered body missing gruff severity alias %q:\n%s", alias, body)
		}
	}
	if strings.Contains(body, "severity: low") || strings.Contains(body, "severity: medium") || strings.Contains(body, "severity: high") {
		t.Fatalf("rendered body should use gruff aliases instead of canonical severity names:\n%s", body)
	}
}

// TestRenderPreservesEveryDefaultEnabledRule asserts the rendered file does
// not silently drop a rule. Counting is the cheap check; the parse round-trip
// above proves field-level fidelity.
func TestRenderPreservesEveryDefaultEnabledRule(t *testing.T) {
	definitions := defaultDefinitions()
	body := string(Render(definitions))
	for _, definition := range definitions {
		if !strings.Contains(body, "\n  "+definition.ID+":\n") {
			t.Fatalf("rendered config missing rule block %q", definition.ID)
		}
	}
}

// TestRenderEmitsSingleThresholdAsScalar checks the singular `threshold:` form
// when a rule has exactly one knob, matching the convention used in the
// dogfood .gruff-go.yaml and in adopters' configs.
func TestRenderEmitsSingleThresholdAsScalar(t *testing.T) {
	body := string(Render(defaultDefinitions()))
	if !strings.Contains(body, "size.file-length:\n    enabled: true\n    severity: warning\n    threshold: 500\n") {
		t.Fatalf("expected singular threshold form for size.file-length; got:\n%s", body)
	}
	if !strings.Contains(body, "design.hotspot-file:\n    enabled: true\n    severity: notice\n    thresholds:\n      minFindings: 3\n      minPillars: 2\n") {
		t.Fatalf("expected plural thresholds form for design.hotspot-file; got:\n%s", body)
	}
}
