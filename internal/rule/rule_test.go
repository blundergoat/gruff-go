package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

func TestDefinitionValidationRejectsBadIDs(t *testing.T) {
	definition := validDefinition("bad.id")
	if err := definition.Validate(); err == nil {
		t.Fatal("expected invalid id error")
	}
}

func TestRegistryRejectsDuplicateIDs(t *testing.T) {
	ruleA := fakeUnitRule{id: "size-file-length"}
	ruleB := fakeUnitRule{id: "size-file-length"}
	if _, err := NewRegistry([]UnitRule{ruleA, ruleB}, nil); err == nil {
		t.Fatal("expected duplicate rule error")
	}
}

func TestRegistrySortsAndDispatchesRuleShapes(t *testing.T) {
	unit := parser.Unit{File: source.File{Path: "b.go", Type: source.FileTypeGo}}
	unitRule := fakeUnitRule{id: "size-file-length"}
	projectRule := fakeProjectRule{id: "design-project-shape"}

	registry, err := NewRegistry([]UnitRule{unitRule}, []ProjectRule{projectRule})
	if err != nil {
		t.Fatal(err)
	}

	definitions := registry.Definitions()
	if len(definitions) != 2 || definitions[0].ID != "design-project-shape" || definitions[1].ID != "size-file-length" {
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

type fakeUnitRule struct{ id string }

func (r fakeUnitRule) Definition() Definition {
	return validDefinition(r.id)
}

func (r fakeUnitRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return []finding.Finding{{
		Message:  "unit finding",
		File:     unit.File.Path,
		Location: &finding.Location{Line: 1},
	}}
}

type fakeProjectRule struct{ id string }

func (r fakeProjectRule) Definition() Definition {
	return validDefinition(r.id)
}

func (r fakeProjectRule) AnalyzeProject(units []parser.Unit, _ Context) []finding.Finding {
	return []finding.Finding{{
		Message: "project finding",
		File:    units[0].File.Path,
	}}
}

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
