// Package rule defines scanner rule contracts and deterministic dispatch for every gruff-go scan.
//
// It owns the interfaces implemented by rule families, registry construction, and the enablement and severity overrides set in config.
// It also orders findings and applies rule metadata, so the same input lists the same findings in the same order on every run.
package rule

import (
	"fmt"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

// Context carries the project information rules need to explain a user's scan.
//
// It distinguishes files selected for reporting from siblings parsed only for proof.
// A missing sibling unit means the rule must keep any warning that needs it.
type Context struct {
	// Root is the project root directory that file paths are reported relative to.
	Root string
	// IncludeIgnored is true when the run intentionally scans gitignored, default-ignored, or generated files.
	IncludeIgnored bool
	// ReportableFiles lists the file paths whose findings survive into the report; an empty set makes every discovered file reportable.
	//
	// Explicit-file scans pull in sibling files for project context but report only the requested files.
	// Project rules should anchor package-level findings to a reportable file so the post-filter does not drop them.
	ReportableFiles map[string]struct{}
	// ProjectUnits includes parsed sibling files even when the user scans one file.
	// An empty slice gives a rule no cross-file evidence for suppressing a warning.
	ProjectUnits []parser.Unit
}

// isReportable reports whether findings anchored to path survive the report filter.
//
// An empty ReportableFiles set means every discovered file is reportable, the default for whole-directory scans.
// False means path is outside a non-empty ReportableFiles, so a finding anchored there would be dropped from the report.
func (c Context) isReportable(path string) bool {
	if len(c.ReportableFiles) == 0 {
		return true
	}
	_, ok := c.ReportableFiles[path]
	return ok
}

// Config carries rule enablement and override values derived from config files such as .gruff-go.yaml.
//
// Each map is keyed by rule ID; a rule missing from a map keeps its built-in setting, so an empty Config changes nothing.
type Config struct {
	// Enabled overrides the default enablement state of named rules; map key is the rule ID.
	Enabled map[string]bool
	// Thresholds carries per-rule numeric overrides keyed by rule ID then threshold name.
	Thresholds map[string]map[string]float64
	// Severities overrides the default severity of named rules; map key is the rule ID.
	Severities map[string]finding.Severity
	// Options carries per-rule non-numeric overrides keyed by rule ID then option name.
	Options map[string]map[string]any
	// AcceptedAbbreviations lists project-specific abbreviations the acronym-case rule should tolerate.
	AcceptedAbbreviations []string
}

// UnitRule analyzes one parsed source unit at a time.
//
// While the rule is active, the registry calls AnalyzeUnit once per selected unit with the shared Context.
// Definition supplies defaults for the RuleID, Severity, Confidence, Pillar, SecondaryPillars and Remediation a returned finding leaves empty.
type UnitRule interface {
	Definition() Definition
	AnalyzeUnit(parser.Unit, Context) []finding.Finding
}

// ProjectRule analyzes the full parsed unit set for package-level signals.
//
// While the rule is active, AnalyzeProject runs once per scan over every project unit, including siblings parsed only for proof.
// The analysis caller later drops findings outside the reportable files, so anchor each one to a reportable file.
type ProjectRule interface {
	Definition() Definition
	AnalyzeProject([]parser.Unit, Context) []finding.Finding
}

// CompositeRule derives score-neutral findings from already-emitted findings.
//
// While the rule is active, AnalyzeFindings sees the unit and project findings of the same scan, never another composite rule's output.
type CompositeRule interface {
	Definition() Definition
	AnalyzeFindings([]finding.Finding, Context) []finding.Finding
}

// Registry stores all rule definitions plus the configured active dispatch set.
//
// Definitions lists every registered rule, while only active rules run during a scan.
// The enabled and severities maps hold config overrides; a nil map means no override of that kind was applied.
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
//
// unitRules and projectRules are registered with no composite rules; each Definition is validated and its ID must be unique across both lists.
// It returns the registry with definitions and dispatch entries sorted by rule ID; only DefaultEnabled rules are active at first.
// It fails with the zero Registry and an error when a definition fails validation or repeats an earlier rule ID.
func NewRegistry(unitRules []UnitRule, projectRules []ProjectRule) (Registry, error) {
	return NewRegistryWithComposite(unitRules, projectRules, nil)
}

// NewRegistryWithComposite builds a registry that also dispatches composites.
//
// unitRules, projectRules and compositeRules supply the rules; each Definition is validated and its ID must be unique across all three lists.
// It returns the registry with definitions and dispatch entries sorted by rule ID; only DefaultEnabled rules are active at first.
// It fails with the zero Registry and an error when a definition fails validation or repeats an earlier rule ID.
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
	// Sorting by rule ID keeps the catalogue and dispatch order the same on every run, whatever order the rules were registered in.
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
//
// The result is a fresh copy in rule ID order that includes any applied enablement or severity override.
// It is empty only for a registry with no rules.
func (r *Registry) Definitions() []Definition {
	out := make([]Definition, len(r.definitions))
	copy(out, r.definitions)
	return out
}

// applyEnablement overlays configured enabled/disabled state onto definitions.
// enabled maps rule IDs to the user's on or off choice; unknown IDs are ignored, and an empty map leaves every rule as it was.
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

// isSeverityConfigured reports whether config overrode this rule's severity.
// ruleID is the rule to look up; the result is false when applySeverities recorded no override for it.
func (r *Registry) isSeverityConfigured(ruleID string) bool {
	_, severityConfigured := r.severities[ruleID]
	return severityConfigured
}

// applySeverities overlays configured severity values onto definitions.
// severities maps rule IDs to configured severities; IDs without a registered definition are ignored, and an empty map changes nothing.
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
// A disabled rule is left out and adds no findings; an enablement or severity override reaches a scan only after this runs again.
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
//
// units serve as both the analysed files and the project set, and context is passed to every unit, project and composite rule.
// The result is empty, not nil, when no active rule fires.
func (r *Registry) Analyze(units []parser.Unit, context Context) []finding.Finding {
	return r.AnalyzeWithProjectContext(units, units, context)
}

// AnalyzeWithProjectContext checks the user's selected files with sibling package facts available.
//
// The analysis caller filters findings to reportable files; an empty sibling set supplies no extra proof.
//
// units feed the unit rules, projectUnits feed the project rules and become context.ProjectUnits, and context is passed to every rule.
// Composite rules see only the unit and project findings, never other composite output.
// It returns every finding with definition metadata applied, sorted by CompareFindings; the slice is empty, not nil, when no rule fires.
func (r *Registry) AnalyzeWithProjectContext(units []parser.Unit, projectUnits []parser.Unit, context Context) []finding.Finding {
	context.ProjectUnits = projectUnits
	findings := []finding.Finding{}
	for _, unit := range units {
		for _, entry := range r.activeUnitRules {
			definition := entry.definition
			for _, item := range entry.rule.AnalyzeUnit(unit, context) {
				findings = append(findings, applyDefinition(item, definition, r.isSeverityConfigured(definition.ID)))
			}
		}
	}
	for _, entry := range r.activeProjectRules {
		definition := entry.definition
		for _, item := range entry.rule.AnalyzeProject(projectUnits, context) {
			findings = append(findings, applyDefinition(item, definition, r.isSeverityConfigured(definition.ID)))
		}
	}
	// Composite rules read this copy, taken before any of them run, so a composite finding never feeds another composite rule.
	baseFindings := append([]finding.Finding(nil), findings...)
	for _, entry := range r.activeCompositeRules {
		definition := entry.definition
		for _, item := range entry.rule.AnalyzeFindings(baseFindings, context) {
			findings = append(findings, applyDefinition(item, definition, r.isSeverityConfigured(definition.ID)))
		}
	}
	slices.SortFunc(findings, CompareFindings)
	return findings
}

// configuredDefinition applies registry-level overrides to one definition.
// It returns a copy of definition with any enabled or severity override for its ID applied; with no override the copy is unchanged.
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
// A config override for the ID of definition wins over DefaultEnabled; false keeps the rule from running, so it adds no findings.
func (r *Registry) ruleEnabled(definition Definition) bool {
	if value, ok := r.enabled[definition.ID]; ok {
		return value
	}
	return definition.DefaultEnabled
}

// CompareFindings orders findings by stable public identity fields.
//
// a and b are compared by file, start line, start column, rule ID, message, then fingerprint; a nil Location counts as line and column zero.
// It returns a negative number when a sorts first, a positive number when b sorts first, and zero when every compared field matches.
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
//
// definition is passed through withReviewedFalsePositiveShapes before validation; seen holds the IDs added so far.
// It returns the definition exactly as appended to definitions, after recording its ID in seen.
// It fails with the zero Definition and an error when Validate rejects it or seen already holds its ID; seen and definitions stay unchanged.
func addDefinition(definition Definition, seen map[string]struct{}, definitions *[]Definition) (Definition, error) {
	definition = withReviewedFalsePositiveShapes(definition)
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

// applyDefinition fills rule metadata, calibrations, and fingerprints on a finding before it reaches the report.
//
// Empty fields of item are filled from definition; any finding isLowerBandFinding accepts then becomes advisory.
// severityConfigured marks a config-overridden severity, which bypasses test-file calibration just like an explicit finding severity.
// It returns the updated copy of item with its fingerprint computed.
func applyDefinition(item finding.Finding, definition Definition, severityConfigured bool) finding.Finding {
	findingHasSeverity := item.Severity != ""
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
	// Only scanner defaults are softened; explicit rule or project choices stay visible to users.
	if !findingHasSeverity && !severityConfigured && shouldCalibrateTestSizeFinding(item, definition) {
		item.Severity = finding.SeverityAdvisory
		item.Confidence = finding.ConfidenceMedium
	}
	// A unit just over its limit gets an advisory notice whatever the default or configured severity.
	if isLowerBandFinding(item) {
		item.Severity = finding.SeverityAdvisory
	}
	return item.WithFingerprint()
}

// locationLine returns a finding's start line or zero when absent.
// f is the finding whose Location is read; a nil Location is the absent case.
func locationLine(f finding.Finding) int {
	if f.Location == nil {
		return 0
	}
	return f.Location.Line
}

// locationColumn returns a finding's start column or zero when absent.
// f is the finding whose Location is read; a nil Location is the absent case.
func locationColumn(f finding.Finding) int {
	if f.Location == nil {
		return 0
	}
	return f.Location.Column
}
