// Package rule defines gruff-go's rule registry and analysers.
// This file covers Definition validation and Registry dispatch semantics.
package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

// TestDefinitionValidationRejectsBadIDs ensures Definition.Validate refuses malformed rule IDs.
func TestDefinitionValidationRejectsBadIDs(t *testing.T) {
	definition := validDefinition("bad_id")
	if err := definition.Validate(); err == nil {
		t.Fatal("expected invalid id error")
	}
}

// TestDefinitionValidateDefaultsCapability confirms an empty Capability defaults to CapabilityParser.
func TestDefinitionValidateDefaultsCapability(t *testing.T) {
	definition := validDefinition("size.file-length")
	definition.Capability = ""

	if err := definition.Validate(); err != nil {
		t.Fatal(err)
	}
	if definition.Capability != CapabilityParser {
		t.Fatalf("capability = %q, want %q", definition.Capability, CapabilityParser)
	}
}

// TestDefinitionValidateRejectsInvalidCapability ensures unknown capability values are rejected.
func TestDefinitionValidateRejectsInvalidCapability(t *testing.T) {
	definition := validDefinition("size.file-length")
	definition.Capability = Capability("magic")

	if err := definition.Validate(); err == nil {
		t.Fatal("expected invalid capability error")
	}
}

// TestRegistryRejectsDuplicateIDs verifies NewRegistry returns an error when two rules share an ID.
func TestRegistryRejectsDuplicateIDs(t *testing.T) {
	ruleA := fakeUnitRule{id: "size.file-length"}
	ruleB := fakeUnitRule{id: "size.file-length"}
	if _, err := NewRegistry([]UnitRule{ruleA, ruleB}, nil); err == nil {
		t.Fatal("expected duplicate rule error")
	}
}

// TestRegistrySortsAndDispatchesRuleShapes checks Registry sorts definitions and dispatches both unit and project rules.
func TestRegistrySortsAndDispatchesRuleShapes(t *testing.T) {
	unit := parser.Unit{File: source.File{Path: "b.go", Type: source.FileTypeGo}}
	unitRule := fakeUnitRule{id: "size.file-length"}
	projectRule := fakeProjectRule{id: "design.project-shape"}

	registry, err := NewRegistry([]UnitRule{unitRule}, []ProjectRule{projectRule})
	if err != nil {
		t.Fatal(err)
	}

	definitions := registry.Definitions()
	if len(definitions) != 2 || definitions[0].ID != "design.project-shape" || definitions[1].ID != "size.file-length" {
		t.Fatalf("definitions = %#v, want sorted definitions", definitions)
	}

	findings := registry.Analyze([]parser.Unit{unit}, Context{})
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	if findings[0].Fingerprint == "" || findings[1].Fingerprint == "" {
		t.Fatalf("findings missing fingerprints: %#v", findings)
	}
}

// TestRegistryCachesDefinitionsForDispatch ensures Definition() is invoked only once per rule.
func TestRegistryCachesDefinitionsForDispatch(t *testing.T) {
	calls := 0
	registry, err := NewRegistry([]UnitRule{countedUnitRule{id: "size.file-length", calls: &calls}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("Definition calls after construction = %d, want 1", calls)
	}

	unit := parser.Unit{File: source.File{Path: "a.go", Type: source.FileTypeGo}}
	registry.Analyze([]parser.Unit{unit, unit}, Context{})
	if calls != 1 {
		t.Fatalf("Definition calls after dispatch = %d, want cached definition reuse", calls)
	}
}

// TestRegistryDoesNotDispatchDisabledRules confirms rules with DefaultEnabled=false are skipped during Analyze.
func TestRegistryDoesNotDispatchDisabledRules(t *testing.T) {
	calls := 0
	registry, err := NewRegistry([]UnitRule{disabledUnitRule{id: "size.parameter-count", calls: &calls}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	unit := parser.Unit{File: source.File{Path: "a.go", Type: source.FileTypeGo}}
	registry.Analyze([]parser.Unit{unit}, Context{})
	if calls != 0 {
		t.Fatalf("disabled rule dispatch calls = %d, want 0", calls)
	}
}

// TestDefaultsCapability asserts every built-in rule advertises CapabilityParser.
func TestDefaultsCapability(t *testing.T) {
	defaults := Defaults()
	definitions := defaults.Definitions()
	if len(definitions) == 0 {
		t.Fatal("expected built-in definitions")
	}
	for _, definition := range definitions {
		if definition.Capability != CapabilityParser {
			t.Fatalf("rule %s capability = %q, want %q", definition.ID, definition.Capability, CapabilityParser)
		}
	}
}

// TestRegistryDefinitionsCapabilityInvariant verifies a freshly built Registry exposes parser-capability definitions.
func TestRegistryDefinitionsCapabilityInvariant(t *testing.T) {
	registry, err := NewRegistry([]UnitRule{fakeUnitRule{id: "size.file-length"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	definitions := registry.Definitions()
	if len(definitions) != 1 {
		t.Fatalf("definitions = %d, want 1", len(definitions))
	}
	if definitions[0].Capability != CapabilityParser {
		t.Fatalf("definition capability = %q, want %q", definitions[0].Capability, CapabilityParser)
	}
}

// fakeUnitRule is a minimal UnitRule stub used to exercise registry plumbing.
type fakeUnitRule struct{ id string }

// Definition returns a valid Definition keyed by the stub's id.
func (r fakeUnitRule) Definition() Definition {
	return validDefinition(r.id)
}

// AnalyzeUnit returns a single canned unit-level finding for the given unit.
func (r fakeUnitRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return []finding.Finding{{
		Message:  "unit finding",
		File:     unit.File.Path,
		Location: &finding.Location{Line: 1},
	}}
}

// fakeProjectRule is a minimal ProjectRule stub used to exercise registry plumbing.
type fakeProjectRule struct{ id string }

// Definition returns a valid Definition keyed by the stub's id.
func (r fakeProjectRule) Definition() Definition {
	return validDefinition(r.id)
}

// AnalyzeProject returns a single canned project-level finding for the given units.
func (r fakeProjectRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	return []finding.Finding{{
		Message: "project finding",
		File:    units[0].File.Path,
	}}
}

// countedUnitRule records each Definition invocation in calls so tests can assert caching.
type countedUnitRule struct {
	id    string
	calls *int
}

// Definition increments the call counter and returns a valid Definition for the stub id.
func (r countedUnitRule) Definition() Definition {
	(*r.calls)++
	return validDefinition(r.id)
}

// AnalyzeUnit returns a single canned unit-level finding for the given unit.
func (countedUnitRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return []finding.Finding{{
		Message:  "unit finding",
		File:     unit.File.Path,
		Location: &finding.Location{Line: 1},
	}}
}

// disabledUnitRule advertises DefaultEnabled=false and records dispatch attempts in calls.
type disabledUnitRule struct {
	id    string
	calls *int
}

// Definition returns a Definition that opts the rule out of default execution.
func (r disabledUnitRule) Definition() Definition {
	definition := validDefinition(r.id)
	definition.DefaultEnabled = false
	return definition
}

// AnalyzeUnit increments the call counter so tests can assert the registry skipped this rule.
func (r disabledUnitRule) AnalyzeUnit(parser.Unit, Context) []finding.Finding {
	(*r.calls)++
	return nil
}

// validDefinition builds a minimal Definition that passes Validate using the supplied id.
func validDefinition(id string) Definition {
	return Definition{
		ID:             id,
		Title:          "Test rule",
		Pillar:         finding.PillarSize,
		Severity:       finding.SeverityMedium,
		Confidence:     finding.ConfidenceHigh,
		DefaultEnabled: true,
	}
}
