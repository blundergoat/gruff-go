// Package config loads and validates strict gruff-go configuration files.
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

const SchemaVersion = "gruff-go.config.v0.1"

var defaultConfigFiles = []string{".gruff.yaml", ".gruff.yml", ".gruff.json"}

type Config struct {
	SchemaVersion         string                `json:"schemaVersion,omitempty"`
	Select                []string              `json:"select,omitempty"`
	ExcludeRules          []string              `json:"excludeRules,omitempty"`
	IgnorePaths           []string              `json:"ignorePaths,omitempty"`
	AcceptedAbbreviations []string              `json:"acceptedAbbreviations,omitempty"`
	Rules                 map[string]RuleConfig `json:"rules,omitempty"`
	SensitiveData         SensitiveDataConfig   `json:"sensitiveData,omitempty"`
	Paths                 PathsConfig           `json:"paths,omitempty"`
	Allowlists            AllowlistsConfig      `json:"allowlists,omitempty"`
	Selection             SelectionConfig       `json:"selection,omitempty"`
	MinimumGoVersion      string                `json:"minimumGoVersion,omitempty"`
}

type RuleConfig struct {
	Enabled    *bool              `json:"enabled,omitempty"`
	Threshold  *float64           `json:"threshold,omitempty"`
	Thresholds map[string]float64 `json:"thresholds,omitempty"`
	Options    map[string]any     `json:"options,omitempty"`
	Severity   string             `json:"severity,omitempty"`
}

type PathsConfig struct {
	Ignore []string `json:"ignore,omitempty"`
}

type AllowlistsConfig struct {
	AcceptedAbbreviations []string `json:"acceptedAbbreviations,omitempty"`
	SecretPreviews        []string `json:"secretPreviews,omitempty"`
}

type SelectionConfig struct {
	Tiers          []string `json:"tiers,omitempty"`
	Pillars        []string `json:"pillars,omitempty"`
	Rules          []string `json:"rules,omitempty"`
	ExcludePillars []string `json:"excludePillars,omitempty"`
	ExcludeRules   []string `json:"excludeRules,omitempty"`
}

type SensitiveDataConfig struct {
	PreviewAllowlist []string `json:"previewAllowlist,omitempty"`
}

type Loaded struct {
	Config Config
	Path   string
}

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

func Load(path string, definitions []rule.Definition) (Config, error) {
	// #nosec G304 -- CLI intentionally reads an explicit user-provided config path.
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseFile(path, data, definitions)
}

func Parse(data []byte, definitions []rule.Definition) (Config, error) {
	return parseJSON(data, definitions)
}

func ParseFile(path string, data []byte, definitions []rule.Definition) (Config, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return parseYAML(data, definitions)
	default:
		return parseJSON(data, definitions)
	}
}

func parseJSON(data []byte, definitions []rule.Definition) (Config, error) {
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, fmt.Errorf("config contains trailing JSON values")
	}
	cfg = cfg.Normalized()
	if err := cfg.Validate(definitions); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

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

func (cfg Config) RuleOptions() rule.Config {
	options := rule.Config{
		Enabled:                       map[string]bool{},
		Thresholds:                    map[string]map[string]float64{},
		Severities:                    map[string]finding.Severity{},
		Options:                       map[string]map[string]any{},
		SensitiveDataPreviewAllowlist: cfg.SensitiveData.PreviewAllowlist,
	}
	cfg = cfg.Normalized()
	definitions := rule.Defaults().Definitions()
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

func copyThresholds(input map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func (cfg Config) Normalized() Config {
	if len(cfg.Paths.Ignore) > 0 {
		cfg.IgnorePaths = cfg.Paths.Ignore
	}
	if len(cfg.Allowlists.AcceptedAbbreviations) > 0 {
		cfg.AcceptedAbbreviations = cfg.Allowlists.AcceptedAbbreviations
	}
	if len(cfg.Allowlists.SecretPreviews) > 0 {
		cfg.SensitiveData.PreviewAllowlist = cfg.Allowlists.SecretPreviews
	}
	if len(cfg.Selection.Rules) > 0 {
		cfg.Select = cfg.Selection.Rules
	}
	if len(cfg.Selection.ExcludeRules) > 0 {
		cfg.ExcludeRules = cfg.Selection.ExcludeRules
	}
	cfg.Select = sortedCopy(cfg.Select)
	cfg.ExcludeRules = sortedCopy(cfg.ExcludeRules)
	cfg.IgnorePaths = sortedCopy(cfg.IgnorePaths)
	cfg.AcceptedAbbreviations = sortedCopy(cfg.AcceptedAbbreviations)
	cfg.SensitiveData.PreviewAllowlist = sortedCopy(cfg.SensitiveData.PreviewAllowlist)
	return cfg
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	slices.Sort(out)
	return out
}

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

func definitionsByID(definitions []rule.Definition) map[string]rule.Definition {
	out := make(map[string]rule.Definition, len(definitions))
	for _, definition := range definitions {
		out[definition.ID] = definition
	}
	return out
}

func parseConfigSeverity(input string) (finding.Severity, error) {
	switch input {
	case "notice":
		return finding.SeverityLow, nil
	case "warning", "warn":
		return finding.SeverityMedium, nil
	case "error":
		return finding.SeverityHigh, nil
	default:
		return finding.ParseSeverity(input)
	}
}
