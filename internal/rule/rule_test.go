package rule

import (
	"testing"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
	"github.com/blundergoat/gruff-go/internal/source"
)

func TestDefinitionValidationRejectsBadIDs(t *testing.T) {
	definition := validDefinition("bad_id")
	if err := definition.Validate(); err == nil {
		t.Fatal("expected invalid id error")
	}
}

func TestRegistryRejectsDuplicateIDs(t *testing.T) {
	ruleA := fakeUnitRule{id: "size.file-length"}
	ruleB := fakeUnitRule{id: "size.file-length"}
	if _, err := NewRegistry([]UnitRule{ruleA, ruleB}, nil); err == nil {
		t.Fatal("expected duplicate rule error")
	}
}

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

type countedUnitRule struct {
	id    string
	calls *int
}

func (r countedUnitRule) Definition() Definition {
	(*r.calls)++
	return validDefinition(r.id)
}

func (countedUnitRule) AnalyzeUnit(unit parser.Unit, _ Context) []finding.Finding {
	return []finding.Finding{{
		Message:  "unit finding",
		File:     unit.File.Path,
		Location: &finding.Location{Line: 1},
	}}
}

type disabledUnitRule struct {
	id    string
	calls *int
}

func (r disabledUnitRule) Definition() Definition {
	definition := validDefinition(r.id)
	definition.DefaultEnabled = false
	return definition
}

func (r disabledUnitRule) AnalyzeUnit(parser.Unit, Context) []finding.Finding {
	(*r.calls)++
	return nil
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
