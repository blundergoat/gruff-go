package rule

import (
	"fmt"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/parser"
)

type Context struct {
	Root string
}

type Config struct {
	Enabled                       map[string]bool
	Thresholds                    map[string]map[string]float64
	Severities                    map[string]finding.Severity
	SensitiveDataPreviewAllowlist []string
}

type UnitRule interface {
	Definition() Definition
	AnalyzeUnit(parser.Unit, Context) []finding.Finding
}

type ProjectRule interface {
	Definition() Definition
	AnalyzeProject([]parser.Unit, Context) []finding.Finding
}

type Registry struct {
	unitRules    []UnitRule
	projectRules []ProjectRule
	definitions  []Definition
	enabled      map[string]bool
	severities   map[string]finding.Severity
}

func NewRegistry(unitRules []UnitRule, projectRules []ProjectRule) (Registry, error) {
	seen := map[string]struct{}{}
	definitions := []Definition{}
	for _, rule := range unitRules {
		definition := rule.Definition()
		if err := addDefinition(definition, seen, &definitions); err != nil {
			return Registry{}, err
		}
	}
	for _, rule := range projectRules {
		definition := rule.Definition()
		if err := addDefinition(definition, seen, &definitions); err != nil {
			return Registry{}, err
		}
	}
	slices.SortFunc(definitions, func(a, b Definition) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(unitRules, func(a, b UnitRule) int {
		return strings.Compare(a.Definition().ID, b.Definition().ID)
	})
	slices.SortFunc(projectRules, func(a, b ProjectRule) int {
		return strings.Compare(a.Definition().ID, b.Definition().ID)
	})
	return Registry{unitRules: unitRules, projectRules: projectRules, definitions: definitions}, nil
}

func Defaults() Registry {
	registry, err := DefaultsConfigured(Config{})
	if err != nil {
		panic(err)
	}
	return registry
}

func DefaultsConfigured(config Config) (Registry, error) {
	registry, err := NewRegistry([]UnitRule{
		FileLengthRule{MaxLines: intThreshold(config, "size-file-length", "maxLines", fileLengthThreshold)},
		FunctionLengthRule{MaxLines: intThreshold(config, "size-function-length", "maxLines", functionLengthThreshold)},
		CyclomaticComplexityRule{MaxComplexity: intThreshold(config, "complexity-cyclomatic", "maxComplexity", cyclomaticThreshold)},
		SensitiveDataRule{PreviewAllowlist: config.SensitiveDataPreviewAllowlist},
		EmptyBlockRule{},
		ShellCommandRule{},
		SkippedTestRule{},
		ParameterCountRule{MaxParameters: intThreshold(config, "size-parameter-count", "maxParameters", parameterCountThreshold)},
		NestingDepthRule{MaxDepth: intThreshold(config, "complexity-nesting-depth", "maxDepth", nestingDepthThreshold)},
		ExportedSymbolCommentRule{},
	}, []ProjectRule{
		PackageCommentRule{},
		PackageNameUnderscoreRule{},
	})
	if err != nil {
		return Registry{}, err
	}
	registry.applyEnablement(config.Enabled)
	registry.applySeverities(config.Severities)
	return registry, nil
}

func (r Registry) Definitions() []Definition {
	out := make([]Definition, len(r.definitions))
	copy(out, r.definitions)
	return out
}

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

func (r Registry) Analyze(units []parser.Unit, context Context) []finding.Finding {
	findings := []finding.Finding{}
	for _, unit := range units {
		for _, rule := range r.unitRules {
			definition := r.configuredDefinition(rule.Definition())
			if !r.ruleEnabled(definition) {
				continue
			}
			for _, item := range rule.AnalyzeUnit(unit, context) {
				findings = append(findings, applyDefinition(item, definition))
			}
		}
	}
	for _, rule := range r.projectRules {
		definition := r.configuredDefinition(rule.Definition())
		if !r.ruleEnabled(definition) {
			continue
		}
		for _, item := range rule.AnalyzeProject(units, context) {
			findings = append(findings, applyDefinition(item, definition))
		}
	}
	slices.SortFunc(findings, CompareFindings)
	return findings
}

func (r Registry) configuredDefinition(definition Definition) Definition {
	if value, ok := r.enabled[definition.ID]; ok {
		definition.DefaultEnabled = value
	}
	if value, ok := r.severities[definition.ID]; ok {
		definition.Severity = value
	}
	return definition
}

func (r Registry) ruleEnabled(definition Definition) bool {
	if value, ok := r.enabled[definition.ID]; ok {
		return value
	}
	return definition.DefaultEnabled
}

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

func addDefinition(definition Definition, seen map[string]struct{}, definitions *[]Definition) error {
	if err := definition.Validate(); err != nil {
		return err
	}
	if _, ok := seen[definition.ID]; ok {
		return fmt.Errorf("duplicate rule id %q", definition.ID)
	}
	seen[definition.ID] = struct{}{}
	*definitions = append(*definitions, definition)
	return nil
}

func applyDefinition(item finding.Finding, definition Definition) finding.Finding {
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
	return item.WithFingerprint()
}

func locationLine(f finding.Finding) int {
	if f.Location == nil {
		return 0
	}
	return f.Location.Line
}

func locationColumn(f finding.Finding) int {
	if f.Location == nil {
		return 0
	}
	return f.Location.Column
}

func intThreshold(config Config, ruleID string, name string, fallback int) int {
	values, ok := config.Thresholds[ruleID]
	if !ok {
		return fallback
	}
	value, ok := values[name]
	if !ok || value <= 0 {
		return fallback
	}
	return int(value)
}
