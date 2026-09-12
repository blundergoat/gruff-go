// Package config tests cover the ratified sensitiveExclusions section.
// The cases mirror gruff-spec/fixtures/sensitive-exclusions/cases.v1.json so the
// port's own gate fails on the same inputs the family conformance suite uses.
package config

import (
	"strings"
	"testing"
)

// awsExclusionRule is the section 13a acceptance case's rule ID.
const awsExclusionRule = "sensitive-data.aws-access-key"

// jwtExclusionRule is the second rule the two-distinct-entries case uses.
const jwtExclusionRule = "sensitive-data.jwt-token"

// nonSensitiveExclusionRule is a real rule outside the sensitive-data pillar.
const nonSensitiveExclusionRule = "size.file-length"

// awsExclusionPath is the synthetic corpus path the acceptance cases exclude.
const awsExclusionPath = "secrets/aws.env"

// parseSensitiveExclusions parses a sensitiveExclusions YAML body against the
// live registry and returns the parsed config or the fatal diagnostic.
func parseSensitiveExclusions(t *testing.T, body string) (Config, error) {
	t.Helper()
	return Parse([]byte(body), defaultDefinitions())
}

// TestSensitiveExclusionsAcceptsRatifiedShape covers the acceptance cases:
// a rule plus a path, an entry that narrows by symbol, and two distinct entries.
// Parsing the mapping-item list at all is the construction seam here - the
// hand-rolled YAML parser accepted only scalar list items before this section.
func TestSensitiveExclusionsAcceptsRatifiedShape(t *testing.T) {
	body := strings.Join([]string{
		"schemaVersion: gruff-go.config.v0.1",
		"sensitiveExclusions:",
		"  - rule: " + awsExclusionRule,
		"    path: " + awsExclusionPath,
		"    reason: Synthetic AWS key used by the redaction corpus; not a live credential.",
		"  - rule: " + jwtExclusionRule,
		"    path: secrets/jwt.env",
		"    symbol: SyntheticFixtureSymbol",
		"    reason: Narrowed to one symbol while the fixture is refactored.",
	}, "\n")

	cfg, err := parseSensitiveExclusions(t, body)
	if err != nil {
		t.Fatalf("ratified sensitiveExclusions shape rejected: %v", err)
	}
	if len(cfg.SensitiveExclusions) != 2 {
		t.Fatalf("parsed %d entries, want 2", len(cfg.SensitiveExclusions))
	}
	first := cfg.SensitiveExclusions[0]
	if first.Rule != awsExclusionRule || first.Path != awsExclusionPath {
		t.Fatalf("entry 0 = {%q, %q}, want {%q, %q}", first.Rule, first.Path, awsExclusionRule, awsExclusionPath)
	}
	if first.Symbol != "" {
		t.Fatalf("entry 0 symbol = %q, want empty", first.Symbol)
	}
	if !strings.HasPrefix(first.Reason, "Synthetic AWS key") {
		t.Fatalf("entry 0 reason = %q, want the configured rationale", first.Reason)
	}
	if got := cfg.SensitiveExclusions[1].Symbol; got != "SyntheticFixtureSymbol" {
		t.Fatalf("entry 1 symbol = %q, want SyntheticFixtureSymbol", got)
	}
}

// TestSensitiveExclusionsNormalizesPathToDisplayForm verifies a leading `./`
// is folded away, so an entry claims findings by the same project-relative
// display path the finding carries regardless of how the user wrote it.
func TestSensitiveExclusionsNormalizesPathToDisplayForm(t *testing.T) {
	body := strings.Join([]string{
		"schemaVersion: gruff-go.config.v0.1",
		"sensitiveExclusions:",
		"  - rule: " + awsExclusionRule,
		"    path: ./" + awsExclusionPath,
		"    reason: Synthetic key in the loader fixture.",
	}, "\n")

	cfg, err := parseSensitiveExclusions(t, body)
	if err != nil {
		t.Fatalf("dot-prefixed path rejected: %v", err)
	}
	if got := cfg.SensitiveExclusions[0].Path; got != awsExclusionPath {
		t.Fatalf("path = %q, want %q", got, awsExclusionPath)
	}
}

// TestSensitiveExclusionsRejectsUnreviewableEntries covers every numbered
// rejection in section 13a. Each is fatal, and each diagnostic must name the
// entry index and the offending key so a reviewer can find the entry without
// counting list items.
func TestSensitiveExclusionsRejectsUnreviewableEntries(t *testing.T) {
	cases := []struct {
		name    string
		entries []string
		mention string
	}{
		{
			name:    "missing-reason",
			entries: []string{"  - rule: " + awsExclusionRule, "    path: " + awsExclusionPath},
			mention: "reason",
		},
		{
			name:    "blank-reason",
			entries: []string{"  - rule: " + awsExclusionRule, "    path: " + awsExclusionPath, "    reason: '   '"},
			mention: "reason",
		},
		{
			name:    "wildcard-rule",
			entries: []string{"  - rule: '*'", "    path: " + awsExclusionPath, "    reason: Everything here is synthetic."},
			mention: "rule",
		},
		{
			name:    "pillar-selector-rule",
			entries: []string{"  - rule: sensitive-data", "    path: " + awsExclusionPath, "    reason: Everything here is synthetic."},
			mention: "rule",
		},
		{
			name:    "glob-selector-rule",
			entries: []string{"  - rule: 'sensitive-data.*'", "    path: " + awsExclusionPath, "    reason: Everything here is synthetic."},
			mention: "rule",
		},
		{
			name:    "unknown-rule",
			entries: []string{"  - rule: sensitive-data.not-a-real-rule", "    path: " + awsExclusionPath, "    reason: Synthetic fixture."},
			mention: "rule",
		},
		{
			name:    "non-sensitive-rule",
			entries: []string{"  - rule: " + nonSensitiveExclusionRule, "    path: " + awsExclusionPath, "    reason: Synthetic fixture."},
			mention: "sensitive",
		},
		{
			name:    "absolute-path",
			entries: []string{"  - rule: " + awsExclusionRule, "    path: /etc/secrets/aws.env", "    reason: Synthetic fixture."},
			mention: "path",
		},
		{
			name:    "parent-escape-path",
			entries: []string{"  - rule: " + awsExclusionRule, "    path: ../secrets/aws.env", "    reason: Synthetic fixture."},
			mention: "path",
		},
		{
			name:    "glob-path",
			entries: []string{"  - rule: " + awsExclusionRule, "    path: 'secrets/*.env'", "    reason: Synthetic fixture."},
			mention: "path",
		},
		{
			name:    "message-matching",
			entries: []string{"  - rule: " + awsExclusionRule, "    path: " + awsExclusionPath, "    message_contains: AKIA", "    reason: Synthetic fixture."},
			mention: "message_contains",
		},
		{
			name:    "camel-message-matching",
			entries: []string{"  - rule: " + awsExclusionRule, "    path: " + awsExclusionPath, "    messageContains: AKIA", "    reason: Synthetic fixture."},
			mention: "messageContains",
		},
		{
			name:    "value-matching",
			entries: []string{"  - rule: " + awsExclusionRule, "    path: " + awsExclusionPath, "    value: AKIA", "    reason: Synthetic fixture."},
			mention: "value",
		},
		{
			name:    "preview-matching",
			entries: []string{"  - rule: " + awsExclusionRule, "    path: " + awsExclusionPath, "    preview: '[redacted:aws-access-key]'", "    reason: Synthetic fixture."},
			mention: "preview",
		},
		{
			name: "duplicate-scope",
			entries: []string{
				"  - rule: " + awsExclusionRule, "    path: " + awsExclusionPath, "    reason: First rationale.",
				"  - rule: " + awsExclusionRule, "    path: " + awsExclusionPath, "    reason: Second rationale.",
			},
			mention: "duplicate",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			body := strings.Join(append([]string{"schemaVersion: gruff-go.config.v0.1", "sensitiveExclusions:"}, testCase.entries...), "\n")
			_, err := parseSensitiveExclusions(t, body)
			if err == nil {
				t.Fatalf("%s was accepted; section 13a requires a fatal diagnostic", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.mention) {
				t.Fatalf("diagnostic %q does not name %q", err.Error(), testCase.mention)
			}
			if !strings.Contains(err.Error(), "sensitiveExclusions[") {
				t.Fatalf("diagnostic %q does not name the entry index", err.Error())
			}
		})
	}
}

// TestSensitiveExclusionsNameTheOffendingEntryIndex verifies the index in the
// diagnostic is the failing entry's own position, not always the first.
func TestSensitiveExclusionsNameTheOffendingEntryIndex(t *testing.T) {
	body := strings.Join([]string{
		"schemaVersion: gruff-go.config.v0.1",
		"sensitiveExclusions:",
		"  - rule: " + awsExclusionRule,
		"    path: " + awsExclusionPath,
		"    reason: Synthetic AWS key in the redaction corpus.",
		"  - rule: " + jwtExclusionRule,
		"    path: secrets/jwt.env",
		"    value: header.payload.signature",
		"    reason: Synthetic fixture.",
	}, "\n")

	_, err := parseSensitiveExclusions(t, body)
	if err == nil {
		t.Fatal("a value key on the second entry was accepted")
	}
	if !strings.Contains(err.Error(), "sensitiveExclusions[1]") {
		t.Fatalf("diagnostic %q does not name entry index 1", err.Error())
	}
}

// TestSensitiveExclusionsSurviveRenderRoundTrip verifies `init --force` keeps
// accepted suppressions: the rendered file must parse back into the same
// entries, so regenerating config never silently drops a reviewed exclusion.
func TestSensitiveExclusionsSurviveRenderRoundTrip(t *testing.T) {
	definitions := defaultDefinitions()
	existing := Config{SensitiveExclusions: []SensitiveExclusion{{
		Rule:   awsExclusionRule,
		Path:   awsExclusionPath,
		Symbol: "SyntheticFixtureSymbol",
		Reason: "Synthetic AWS key used by the redaction corpus; not a live credential.",
	}}}

	rendered := Render(definitions, RenderOptions{Existing: &existing})
	if !strings.Contains(string(rendered), "sensitiveExclusions:") {
		t.Fatalf("rendered config lost the sensitiveExclusions section:\n%s", rendered)
	}
	cfg, err := Parse(rendered, definitions)
	if err != nil {
		t.Fatalf("rendered config with exclusions did not parse: %v", err)
	}
	if len(cfg.SensitiveExclusions) != 1 {
		t.Fatalf("round-tripped %d entries, want 1", len(cfg.SensitiveExclusions))
	}
	got, want := cfg.SensitiveExclusions[0], existing.SensitiveExclusions[0]
	if got.Rule != want.Rule || got.Path != want.Path || got.Symbol != want.Symbol || got.Reason != want.Reason {
		t.Fatalf("round-tripped entry = %+v, want %+v", got, want)
	}
}

// TestRenderDocumentsManualSensitiveExclusionAuthoring verifies the generated
// config tells a user the section exists and that entries are written by hand,
// so nobody expects a reported preview to become an exclusion automatically.
func TestRenderDocumentsManualSensitiveExclusionAuthoring(t *testing.T) {
	rendered := string(Render(defaultDefinitions(), RenderOptions{}))
	for _, want := range []string{
		"sensitiveExclusions: []",
		"requires a written reason",
		"written by hand",
		"suppressions array",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("generated config missing %q:\n%s", want, rendered)
		}
	}
}
