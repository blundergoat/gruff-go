// Package rule defines scanner rule contracts and deterministic dispatch.
// It owns the interfaces implemented by rule families, registry construction,
// finding ordering, default enablement overrides, and metadata application.
package rule

import (
	"fmt"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// Context carries run-level information shared with rule implementations.
type Context struct {
	// Root is the project root directory that file paths are reported relative to.
	Root string
}

// Config carries rule enablement and override values derived from config files.
type Config struct {
	// Enabled overrides the default enablement state of named rules; map key is the rule ID.
	Enabled map[string]bool
	// Thresholds carries per-rule numeric overrides keyed by rule ID then threshold name.
	Thresholds map[string]map[string]float64
	// Severities overrides the default severity of named rules; map key is the rule ID.
	Severities map[string]finding.Severity
	// Options carries per-rule non-numeric overrides keyed by rule ID then option name.
	Options map[string]map[string]any
	// SensitiveDataPreviewAllowlist lists file path globs allowed to include redacted secret previews.
	SensitiveDataPreviewAllowlist []string
	// AcceptedAbbreviations lists project-specific abbreviations the acronym-case rule should tolerate.
	AcceptedAbbreviations []string
}

// UnitRule analyzes one parsed source unit at a time.
type UnitRule interface {
	Definition() Definition
	AnalyzeUnit(parser.Unit, Context) []finding.Finding
}

// ProjectRule analyzes the full parsed unit set for package-level signals.
type ProjectRule interface {
	Definition() Definition
	AnalyzeProject([]parser.Unit, Context) []finding.Finding
}

// CompositeRule derives score-neutral findings from already-emitted findings.
type CompositeRule interface {
	Definition() Definition
	AnalyzeFindings([]finding.Finding, Context) []finding.Finding
}

// Registry stores all rule definitions plus the configured active dispatch set.
type Registry struct {
	unitRules            []unitRuleEntry
	projectRules         []projectRuleEntry
	compositeRules       []compositeRuleEntry
	activeUnitRules      []unitRuleEntry
	activeProjectRules   []projectRuleEntry
	activeCompositeRules []compositeRuleEntry
	definitions          []Definition
	enabled              map[string]bool
	severities           map[string]finding.Severity
}

// unitRuleEntry caches a unit rule with its validated definition.
type unitRuleEntry struct {
	rule       UnitRule
	definition Definition
}

// projectRuleEntry caches a project rule with its validated definition.
type projectRuleEntry struct {
	rule       ProjectRule
	definition Definition
}

// compositeRuleEntry caches a composite rule with its validated definition.
type compositeRuleEntry struct {
	rule       CompositeRule
	definition Definition
}

// NewRegistry builds a registry for unit and project rules.
func NewRegistry(unitRules []UnitRule, projectRules []ProjectRule) (Registry, error) {
	return NewRegistryWithComposite(unitRules, projectRules, nil)
}

// NewRegistryWithComposite builds a registry that also dispatches composites.
func NewRegistryWithComposite(unitRules []UnitRule, projectRules []ProjectRule, compositeRules []CompositeRule) (Registry, error) {
	seen := map[string]struct{}{}
	definitions := []Definition{}
	unitEntries := make([]unitRuleEntry, 0, len(unitRules))
	for _, rule := range unitRules {
		definition := rule.Definition()
		var err error
		definition, err = addDefinition(definition, seen, &definitions)
		if err != nil {
			return Registry{}, err
		}
		unitEntries = append(unitEntries, unitRuleEntry{rule: rule, definition: definition})
	}
	projectEntries := make([]projectRuleEntry, 0, len(projectRules))
	for _, rule := range projectRules {
		definition := rule.Definition()
		var err error
		definition, err = addDefinition(definition, seen, &definitions)
		if err != nil {
			return Registry{}, err
		}
		projectEntries = append(projectEntries, projectRuleEntry{rule: rule, definition: definition})
	}
	compositeEntries := make([]compositeRuleEntry, 0, len(compositeRules))
	for _, rule := range compositeRules {
		definition := rule.Definition()
		var err error
		definition, err = addDefinition(definition, seen, &definitions)
		if err != nil {
			return Registry{}, err
		}
		compositeEntries = append(compositeEntries, compositeRuleEntry{rule: rule, definition: definition})
	}
	slices.SortFunc(definitions, func(a, b Definition) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(unitEntries, func(a, b unitRuleEntry) int {
		return strings.Compare(a.definition.ID, b.definition.ID)
	})
	slices.SortFunc(projectEntries, func(a, b projectRuleEntry) int {
		return strings.Compare(a.definition.ID, b.definition.ID)
	})
	slices.SortFunc(compositeEntries, func(a, b compositeRuleEntry) int {
		return strings.Compare(a.definition.ID, b.definition.ID)
	})
	registry := Registry{
		unitRules:      unitEntries,
		projectRules:   projectEntries,
		compositeRules: compositeEntries,
		definitions:    definitions,
	}
	registry.refreshActiveRules()
	return registry, nil
}

// Definitions returns the sorted public rule-definition catalogue.
func (r *Registry) Definitions() []Definition {
	out := make([]Definition, len(r.definitions))
	copy(out, r.definitions)
	return out
}

// applyEnablement overlays configured enabled/disabled state onto definitions.
func (r *Registry) applyEnablement(enabled map[string]bool) {
	if len(enabled) == 0 {
		return
	}
	r.enabled = map[string]bool{}
	for index := range r.definitions {
		if value, ok := enabled[r.definitions[index].ID]; ok {
			r.definitions[index].DefaultEnabled = value
			r.enabled[r.definitions[index].ID] = value
		}
	}
}

// applySeverities overlays configured severity values onto definitions.
func (r *Registry) applySeverities(severities map[string]finding.Severity) {
	if len(severities) == 0 {
		return
	}
	r.severities = map[string]finding.Severity{}
	for index := range r.definitions {
		if value, ok := severities[r.definitions[index].ID]; ok {
			r.definitions[index].Severity = value
			r.severities[r.definitions[index].ID] = value
		}
	}
}

// refreshActiveRules rebuilds dispatch slices from configured definitions.
func (r *Registry) refreshActiveRules() {
	r.activeUnitRules = r.activeUnitRules[:0]
	for _, entry := range r.unitRules {
		definition := r.configuredDefinition(entry.definition)
		if !r.ruleEnabled(definition) {
			continue
		}
		entry.definition = definition
		r.activeUnitRules = append(r.activeUnitRules, entry)
	}
	r.activeProjectRules = r.activeProjectRules[:0]
	for _, entry := range r.projectRules {
		definition := r.configuredDefinition(entry.definition)
		if !r.ruleEnabled(definition) {
			continue
		}
		entry.definition = definition
		r.activeProjectRules = append(r.activeProjectRules, entry)
	}
	r.activeCompositeRules = r.activeCompositeRules[:0]
	for _, entry := range r.compositeRules {
		definition := r.configuredDefinition(entry.definition)
		if !r.ruleEnabled(definition) {
			continue
		}
		entry.definition = definition
		r.activeCompositeRules = append(r.activeCompositeRules, entry)
	}
}

// Analyze dispatches active rules and returns findings in deterministic order.
func (r *Registry) Analyze(units []parser.Unit, context Context) []finding.Finding {
	findings := []finding.Finding{}
	for _, unit := range units {
		for _, entry := range r.activeUnitRules {
			definition := entry.definition
			for _, item := range entry.rule.AnalyzeUnit(unit, context) {
				findings = append(findings, applyDefinition(item, definition))
			}
		}
	}
	for _, entry := range r.activeProjectRules {
		definition := entry.definition
		for _, item := range entry.rule.AnalyzeProject(units, context) {
			findings = append(findings, applyDefinition(item, definition))
		}
	}
	baseFindings := append([]finding.Finding(nil), findings...)
	for _, entry := range r.activeCompositeRules {
		definition := entry.definition
		for _, item := range entry.rule.AnalyzeFindings(baseFindings, context) {
			findings = append(findings, applyDefinition(item, definition))
		}
	}
	slices.SortFunc(findings, CompareFindings)
	return findings
}

// configuredDefinition applies registry-level overrides to one definition.
func (r *Registry) configuredDefinition(definition Definition) Definition {
	if value, ok := r.enabled[definition.ID]; ok {
		definition.DefaultEnabled = value
	}
	if value, ok := r.severities[definition.ID]; ok {
		definition.Severity = value
	}
	return definition
}

// ruleEnabled reports whether a definition should be included in dispatch.
func (r *Registry) ruleEnabled(definition Definition) bool {
	if value, ok := r.enabled[definition.ID]; ok {
		return value
	}
	return definition.DefaultEnabled
}

// CompareFindings orders findings by stable public identity fields.
func CompareFindings(a, b finding.Finding) int {
	if a.File != b.File {
		return strings.Compare(a.File, b.File)
	}
	if locationLine(a) != locationLine(b) {
		return locationLine(a) - locationLine(b)
	}
	if locationColumn(a) != locationColumn(b) {
		return locationColumn(a) - locationColumn(b)
	}
	if a.RuleID != b.RuleID {
		return strings.Compare(a.RuleID, b.RuleID)
	}
	if a.Message != b.Message {
		return strings.Compare(a.Message, b.Message)
	}
	return strings.Compare(a.Fingerprint, b.Fingerprint)
}

// addDefinition validates and deduplicates one rule definition.
func addDefinition(definition Definition, seen map[string]struct{}, definitions *[]Definition) (Definition, error) {
	if err := definition.Validate(); err != nil {
		return Definition{}, err
	}
	if _, ok := seen[definition.ID]; ok {
		return Definition{}, fmt.Errorf("duplicate rule id %q", definition.ID)
	}
	seen[definition.ID] = struct{}{}
	*definitions = append(*definitions, definition)
	return definition, nil
}

// applyDefinition fills rule metadata, calibrations, and fingerprints.
func applyDefinition(item finding.Finding, definition Definition) finding.Finding {
	hadSeverity := item.Severity != ""
	if item.RuleID == "" {
		item.RuleID = definition.ID
	}
	if item.Severity == "" {
		item.Severity = definition.Severity
	}
	if item.Confidence == "" {
		item.Confidence = definition.Confidence
	}
	if item.Pillar == "" {
		item.Pillar = definition.Pillar
	}
	if len(item.SecondaryPillars) == 0 {
		item.SecondaryPillars = definition.SecondaryPillars
	}
	if item.Remediation == "" {
		item.Remediation = definition.Remediation
	}
	if !hadSeverity && shouldCalibrateTestSizeFinding(item, definition) {
		item.Severity = finding.SeverityAdvisory
		item.Confidence = finding.ConfidenceMedium
	}
	return item.WithFingerprint()
}

// locationLine returns a finding's start line or zero when absent.
func locationLine(f finding.Finding) int {
	if f.Location == nil {
		return 0
	}
	return f.Location.Line
}

// locationColumn returns a finding's start column or zero when absent.
func locationColumn(f finding.Finding) int {
	if f.Location == nil {
		return 0
	}
	return f.Location.Column
}
