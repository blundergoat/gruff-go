// Package config loads and validates gruff-go configuration files.
// It owns the strict .gruff-go.yaml schema, legacy rule-ID compatibility,
// default config discovery, and conversion into rule-registry options.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// SchemaVersion identifies the supported config document contract.
const SchemaVersion = "gruff-go.config.v0.1"

// defaultConfigFiles lists auto-discovered config files in precedence order.
var defaultConfigFiles = []string{".gruff-go.yaml"}

// Config is the canonical in-memory representation of gruff config.
type Config struct {
	// SchemaVersion identifies the gruff-go config schema this file targets.
	SchemaVersion string `json:"schemaVersion,omitempty"`
	// Select restricts the active rule set to the listed rule IDs (or aliases).
	Select []string `json:"select,omitempty"`
	// ExcludeRules disables the named rule IDs even when they would otherwise run.
	ExcludeRules []string `json:"excludeRules,omitempty"`
	// IgnorePaths lists glob patterns the discovery layer skips entirely.
	IgnorePaths []string `json:"ignorePaths,omitempty"`
	// AcceptedAbbreviations is the project-wide allowlist for identifier abbreviations.
	AcceptedAbbreviations []string `json:"acceptedAbbreviations,omitempty"`
	// Rules holds per-rule overrides for enablement, thresholds, severity, and options.
	Rules map[string]RuleConfig `json:"rules,omitempty"`
	// SensitiveData carries policy for the sensitive-data.* rule family.
	SensitiveData SensitiveDataConfig `json:"sensitiveData,omitempty"`
	// Paths nests path-scoped policy (currently the canonical `ignore` list).
	Paths PathsConfig `json:"paths,omitempty"`
	// Allowlists nests project-wide allowlists folded into top-level fields by Normalized.
	Allowlists AllowlistsConfig `json:"allowlists,omitempty"`
	// Selection nests rule/pillar selection policy folded into Select/ExcludeRules by Normalized.
	Selection SelectionConfig `json:"selection,omitempty"`
	// MinimumGoVersion documents the minimum Go toolchain version this config supports.
	MinimumGoVersion string `json:"minimumGoVersion,omitempty"`
}

// RuleConfig stores per-rule overrides from `.gruff-go.yaml`.
type RuleConfig struct {
	// Enabled toggles the rule on or off; nil means honour the registry default.
	Enabled *bool `json:"enabled,omitempty"`
	// Threshold sets a single primary numeric threshold for the rule.
	Threshold *float64 `json:"threshold,omitempty"`
	// Thresholds sets named numeric thresholds when the rule has more than one knob.
	Thresholds map[string]float64 `json:"thresholds,omitempty"`
	// Options carries rule-specific configuration values keyed by option name.
	Options map[string]any `json:"options,omitempty"`
	// Severity overrides the rule's default severity using a gruff-family alias or canonical level.
	Severity string `json:"severity,omitempty"`
}

// PathsConfig stores source discovery path policy.
type PathsConfig struct {
	// Ignore lists glob patterns the discovery layer skips; Normalized folds this into top-level IgnorePaths.
	Ignore []string `json:"ignore,omitempty"`
}

// AllowlistsConfig stores explicit project acceptances for noisy signals.
type AllowlistsConfig struct {
	// AcceptedAbbreviations is the gruff-family alias folded into Config.AcceptedAbbreviations.
	AcceptedAbbreviations []string `json:"acceptedAbbreviations,omitempty"`
	// SecretPreviews lists path patterns where the sensitive-data rules may emit the matched preview.
	SecretPreviews []string `json:"secretPreviews,omitempty"`
}

// SelectionConfig stores rule and pillar allowlist/denylist policy.
type SelectionConfig struct {
	// Tiers names rule tier labels reserved for future selection grouping.
	Tiers []string `json:"tiers,omitempty"`
	// Pillars selects rules by quality pillar (documentation, naming, size, etc.).
	Pillars []string `json:"pillars,omitempty"`
	// Rules is the gruff-family alias for the top-level Select field.
	Rules []string `json:"rules,omitempty"`
	// ExcludePillars disables every rule that belongs to one of the listed pillars.
	ExcludePillars []string `json:"excludePillars,omitempty"`
	// ExcludeRules is the gruff-family alias for the top-level ExcludeRules field.
	ExcludeRules []string `json:"excludeRules,omitempty"`
}

// SensitiveDataConfig stores sensitive-data rule preview exceptions.
type SensitiveDataConfig struct {
	// PreviewAllowlist lists path patterns where the sensitive-data rules may emit the matched secret preview.
	PreviewAllowlist []string `json:"previewAllowlist,omitempty"`
}

// Loaded returns parsed config together with the file path that supplied it.
type Loaded struct {
	// Config is the parsed and normalized configuration payload.
	Config Config
	// Path is the absolute filesystem location the configuration was read from.
	Path string
}

// LoadAuto resolves the configured path and parses config unless disabled.
func LoadAuto(root string, explicitPath string, noConfig bool, definitions []rule.Definition) (Loaded, error) {
	if noConfig {
		return Loaded{Config: Config{}}, nil
	}
	path, ok, err := ResolvePath(root, explicitPath)
	if err != nil || !ok {
		return Loaded{Config: Config{}}, err
	}
	cfg, err := Load(path, definitions)
	if err != nil {
		return Loaded{}, err
	}
	return Loaded{Config: cfg, Path: filepath.ToSlash(path)}, nil
}

// ResolvePath finds the explicit or auto-discovered config path for a root.
func ResolvePath(root string, explicitPath string) (string, bool, error) {
	if root == "" {
		root = "."
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", false, err
	}
	if explicitPath != "" {
		path := explicitPath
		if !filepath.IsAbs(path) {
			path = filepath.Join(rootAbs, path)
		}
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return "", false, fmt.Errorf("config file not found: %s", explicitPath)
			}
			return "", false, err
		}
		if info.IsDir() {
			return "", false, fmt.Errorf("config path is a directory: %s", explicitPath)
		}
		return path, true, nil
	}
	for _, name := range defaultConfigFiles {
		path := filepath.Join(rootAbs, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, true, nil
		}
	}
	return "", false, nil
}

// Load reads and parses a config file from disk.
func Load(path string, definitions []rule.Definition) (Config, error) {
	// #nosec G304 -- CLI intentionally reads an explicit user-provided config path.
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseFile(path, data, definitions)
}

// Parse parses config bytes using the supported strict YAML subset.
func Parse(data []byte, definitions []rule.Definition) (Config, error) {
	return parseYAML(data, definitions)
}

// ParseFile parses config bytes after validating the file extension.
func ParseFile(path string, data []byte, definitions []rule.Definition) (Config, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml":
		return parseYAML(data, definitions)
	default:
		return Config{}, fmt.Errorf("unsupported config file extension %q (want .yaml)", filepath.Ext(path))
	}
}

// decodeConfigPayload unmarshals canonical JSON payloads from the YAML parser.
func decodeConfigPayload(data []byte, definitions []rule.Definition) (Config, error) {
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, fmt.Errorf("config contains trailing values")
	}
	cfg = cfg.Normalized()
	if err := cfg.Validate(definitions); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks schema, rule, threshold, option, path, and severity contracts.
func (cfg Config) Validate(definitions []rule.Definition) error {
	if cfg.SchemaVersion != "" && cfg.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schemaVersion %q", cfg.SchemaVersion)
	}
	byID := map[string]rule.Definition{}
	for _, definition := range definitions {
		byID[definition.ID] = definition
	}
	cfg = cfg.Normalized()
	checks := []func() error{
		func() error { return validateRuleIDs("selected", cfg.Select, byID) },
		func() error { return validateRuleIDs("excluded", cfg.ExcludeRules, byID) },
		func() error { return validatePatterns("ignorePaths", cfg.IgnorePaths) },
		func() error { return validateAbbreviations(cfg.AcceptedAbbreviations) },
		func() error {
			return validatePatterns("sensitiveData.previewAllowlist", cfg.SensitiveData.PreviewAllowlist)
		},
		func() error { return validateRuleConfig(cfg.Rules, byID) },
		func() error { return validateSelection(cfg.Selection) },
	}
	return runChecks(checks)
}

// RuleOptions converts parsed config into registry enablement and overrides.
func (cfg Config) RuleOptions() rule.Config {
	cfg = cfg.Normalized()
	options := rule.Config{
		Enabled:                       map[string]bool{},
		Thresholds:                    map[string]map[string]float64{},
		Severities:                    map[string]finding.Severity{},
		Options:                       map[string]map[string]any{},
		SensitiveDataPreviewAllowlist: cfg.SensitiveData.PreviewAllowlist,
		AcceptedAbbreviations:         cfg.AcceptedAbbreviations,
	}
	defaults := rule.Defaults()
	definitions := defaults.Definitions()
	if len(cfg.Select) > 0 || len(cfg.Selection.Pillars) > 0 {
		selected := map[string]struct{}{}
		byID := definitionsByID(definitions)
		for _, id := range cfg.Select {
			if canonical, ok := canonicalRuleID(id, byID); ok {
				selected[canonical] = struct{}{}
			}
		}
		selectedPillars := map[finding.Pillar]struct{}{}
		for _, pillar := range cfg.Selection.Pillars {
			selectedPillars[finding.Pillar(pillar)] = struct{}{}
		}
		for _, definition := range definitions {
			_, selectedRule := selected[definition.ID]
			_, selectedPillar := selectedPillars[definition.Pillar]
			options.Enabled[definition.ID] = selectedRule || selectedPillar
		}
	}
	for id, ruleConfig := range cfg.Rules {
		canonical, _ := canonicalRuleID(id, definitionsByID(definitions))
		if ruleConfig.Enabled != nil {
			options.Enabled[canonical] = *ruleConfig.Enabled
		}
		thresholds := copyThresholds(ruleConfig.Thresholds)
		if ruleConfig.Threshold != nil {
			definition := definitionsByID(definitions)[canonical]
			for name := range definition.Thresholds {
				thresholds[name] = *ruleConfig.Threshold
			}
		}
		if len(thresholds) > 0 {
			options.Thresholds[canonical] = thresholds
		}
		if ruleConfig.Severity != "" {
			severity, _ := parseConfigSeverity(ruleConfig.Severity)
			options.Severities[canonical] = severity
		}
		if len(ruleConfig.Options) > 0 {
			options.Options[canonical] = ruleConfig.Options
		}
	}
	for _, id := range cfg.ExcludeRules {
		canonical, _ := canonicalRuleID(id, definitionsByID(definitions))
		options.Enabled[canonical] = false
	}
	for _, pillar := range cfg.Selection.ExcludePillars {
		for _, definition := range definitions {
			if definition.Pillar == finding.Pillar(pillar) {
				options.Enabled[definition.ID] = false
			}
		}
	}
	return options
}

// copyThresholds returns an isolated copy of rule threshold overrides.
func copyThresholds(input map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

// Normalized folds legacy and gruff-family fields into canonical locations.
func (cfg Config) Normalized() Config {
	if len(cfg.Paths.Ignore) > 0 {
		cfg.IgnorePaths = mergeStringLists(cfg.IgnorePaths, cfg.Paths.Ignore)
	}
	if len(cfg.Allowlists.AcceptedAbbreviations) > 0 {
		cfg.AcceptedAbbreviations = mergeStringLists(cfg.AcceptedAbbreviations, cfg.Allowlists.AcceptedAbbreviations)
	}
	if len(cfg.Allowlists.SecretPreviews) > 0 {
		cfg.SensitiveData.PreviewAllowlist = mergeStringLists(cfg.SensitiveData.PreviewAllowlist, cfg.Allowlists.SecretPreviews)
	}
	if len(cfg.Selection.Rules) > 0 {
		cfg.Select = mergeStringLists(cfg.Select, cfg.Selection.Rules)
	}
	if len(cfg.Selection.ExcludeRules) > 0 {
		cfg.ExcludeRules = mergeStringLists(cfg.ExcludeRules, cfg.Selection.ExcludeRules)
	}
	cfg.Select = sortedCopy(cfg.Select)
	cfg.ExcludeRules = sortedCopy(cfg.ExcludeRules)
	cfg.IgnorePaths = sortedCopy(cfg.IgnorePaths)
	cfg.AcceptedAbbreviations = sortedCopy(cfg.AcceptedAbbreviations)
	cfg.SensitiveData.PreviewAllowlist = sortedCopy(cfg.SensitiveData.PreviewAllowlist)
	return cfg
}

// mergeStringLists appends gruff-family aliases to their legacy top-level
// counterparts before the deterministic sort step.
func mergeStringLists(primary, alias []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range append(append([]string(nil), primary...), alias...) {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// sortedCopy returns a deterministic copy of string-slice config values.
func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	slices.Sort(out)
	return out
}

// canonicalRuleID maps accepted legacy rule aliases onto live rule IDs.
func canonicalRuleID(id string, definitions map[string]rule.Definition) (string, bool) {
	if _, ok := definitions[id]; ok {
		return id, true
	}
	if strings.HasPrefix(id, "documentation.") {
		candidate := "docs." + strings.TrimPrefix(id, "documentation.")
		if _, ok := definitions[candidate]; ok {
			return candidate, true
		}
	}
	if strings.HasPrefix(id, "documentation-") {
		candidate := "docs." + strings.TrimPrefix(id, "documentation-")
		if _, ok := definitions[candidate]; ok {
			return candidate, true
		}
	}
	for definitionID := range definitions {
		if strings.ReplaceAll(definitionID, ".", "-") == id {
			return definitionID, true
		}
	}
	return "", false
}

// definitionsByID indexes rule definitions by canonical rule ID.
func definitionsByID(definitions []rule.Definition) map[string]rule.Definition {
	out := make(map[string]rule.Definition, len(definitions))
	for _, definition := range definitions {
		out[definition.ID] = definition
	}
	return out
}

// parseConfigSeverity validates a per-rule severity override. Per ADR-009 the
// hard-break migration accepts only the 3-bucket names; legacy 5-bucket names
// (critical/high/medium/low/info) and the old aliases (notice/warn) must be
// migrated in the user's config before the file will load.
func parseConfigSeverity(input string) (finding.Severity, error) {
	return finding.ParseSeverity(input)
}
