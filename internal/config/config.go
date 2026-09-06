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

// DefaultDeepScanMaxLines and DefaultDeepScanMaxBytes bound expensive Go syntax analysis.
const (
	DefaultDeepScanMaxLines = 20_000
	DefaultDeepScanMaxBytes = 2_000_000
)

// defaultConfigFiles lists auto-discovered config files in precedence order.
var defaultConfigFiles = []string{".gruff-go.yaml"}

// Config is the canonical in-memory representation of gruff config.
type Config struct {
	// SchemaVersion identifies the gruff-go config schema this file targets.
	SchemaVersion string `json:"schemaVersion,omitempty"`
	// MinimumSeverity is the display floor: the lowest severity a report shows. It never changes an exit code, a
	// score, or a baseline. Before 0.6.0 this key was the per-command exit gate, which is why the map form is refused
	// rather than reinterpreted.
	MinimumSeverity SeverityFloor `json:"minimumSeverity,omitempty"`
	// FailOn sets the per-command exit-code threshold that minimumSeverity used to carry. Keys are command names
	// (analyse, summary, report, dashboard); values are FailThreshold strings (advisory, warning, error, none). A bare
	// string applies to every command. Absent keys fall back to finding.DefaultFailThresholdFor(cmd).
	FailOn CommandThresholds `json:"failOn,omitempty"`
	// DeepScanBudget bounds AST-backed analysis after .go source classification.
	DeepScanBudget DeepScanBudgetConfig `json:"deepScanBudget,omitempty"`
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
	// SensitiveExclusions suppresses individual sensitive-data findings by exact
	// rule ID and project-relative path, each with a required written rationale.
	// Deliberately separate from Select/ExcludeRules so the ban on message- and
	// value-matching keys is structural (FAMILY-CONTRACT.md section 13a).
	SensitiveExclusions []SensitiveExclusion `json:"sensitiveExclusions,omitempty"`
	// Paths nests path-scoped policy (currently the canonical `ignore` list).
	Paths PathsConfig `json:"paths,omitempty"`
	// Allowlists nests project-wide allowlists folded into top-level fields by Normalized.
	Allowlists AllowlistsConfig `json:"allowlists,omitempty"`
	// Selection nests rule/pillar selection policy folded into Select/ExcludeRules by Normalized.
	Selection SelectionConfig `json:"selection,omitempty"`
	// MinimumGoVersion documents the minimum Go toolchain version this config supports.
	MinimumGoVersion string `json:"minimumGoVersion,omitempty"`
}

// DeepScanBudgetConfig carries optional user overrides; pointers preserve omitted values.
type DeepScanBudgetConfig struct {
	Enabled  *bool `json:"enabled,omitempty"`
	MaxLines *int  `json:"maxLines,omitempty"`
	MaxBytes *int  `json:"maxBytes,omitempty"`
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
	// SecretPreviews is refused rather than read, and kept as raw JSON so an empty list is still detected. Section 5
	// makes category markers unconditional, so from 0.6.0 the key authorises nothing; a configuration carrying it is
	// telling the user something untrue about their redaction, whatever it lists.
	SecretPreviews json.RawMessage `json:"secretPreviews,omitempty"`
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
	// PreviewAllowlist is the removed pre-0.6.0 spelling of allowlists.secretPreviews, kept as raw JSON only so its
	// presence can be refused with the section 5 explanation rather than ignored.
	PreviewAllowlist json.RawMessage `json:"previewAllowlist,omitempty"`
}

// SensitiveExclusion is one ratified sensitive-data suppression scope: exactly
// one rule, exactly one project-relative path, an optional symbol narrowing,
// and the rationale a reviewer reads in place of the suppressed finding.
// The four fields below are the whole key set an entry may carry. Every other
// key - notably message_contains, messageContains, value and preview - is a
// fatal configuration error, so value-based suppression cannot re-enter this
// section under a new name (FAMILY-CONTRACT.md section 13a).
type SensitiveExclusion struct {
	// Rule is the exact sensitive-data rule ID this entry suppresses.
	Rule string `json:"rule"`
	// Path is the project-relative display path the entry is scoped to.
	Path string `json:"path"`
	// Symbol narrows the scope to findings carrying that exact symbol; empty matches any.
	Symbol string `json:"symbol,omitempty"`
	// Reason is the required rationale published in the report's suppression audit row.
	Reason string `json:"reason"`
	// UnsupportedKeys records the keys this entry carried outside the four above,
	// so validation can name the offender together with the entry index. Never
	// serialised: it is decode state, not configuration.
	UnsupportedKeys []string `json:"-"`
}

// UnmarshalJSON decodes one entry while collecting keys outside the closed set
// rather than failing on the first one. The shared decoder's DisallowUnknownFields
// reports such a key without the entry index, and section 13a requires the
// diagnostic to name both.
func (entry *SensitiveExclusion) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	targets := map[string]*string{"rule": &entry.Rule, "path": &entry.Path, "symbol": &entry.Symbol, "reason": &entry.Reason}
	for key, value := range raw {
		target, supported := targets[key]
		if !supported {
			entry.UnsupportedKeys = append(entry.UnsupportedKeys, key)
			continue
		}
		if err := json.Unmarshal(value, target); err != nil {
			return fmt.Errorf("sensitiveExclusions entry key %q must be a string", key)
		}
	}
	slices.Sort(entry.UnsupportedKeys)
	return nil
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

// LoadPermissive reads and parses a config file for migration or preservation
// purposes. Per-rule severity overrides that fail strict ADR-009 validation
// (legacy 5-bucket names like notice/medium/critical) are dropped from the
// returned Config so paths.ignore, allowlists, thresholds, and options can
// still flow through init --force's preserve path. Affected rules fall back
// to registry defaults in the rendered output via tryParseSeverity.
//
// Do NOT use this for runtime scans - it would silently weaken severity gates.
func LoadPermissive(path string, definitions []rule.Definition) (Config, error) {
	// #nosec G304 -- CLI intentionally reads an explicit user-provided config path.
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return parseYAMLPermissive(data, definitions)
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
	cfg, err := decodeConfigUnvalidated(data)
	if err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(definitions); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// decodeConfigPayloadPermissive unmarshals canonical JSON payloads like
// decodeConfigPayload, then drops any per-rule severity override that does
// not parse against the current 3-bucket vocabulary before validation. Used
// by LoadPermissive for the init --force preserve path.
func decodeConfigPayloadPermissive(data []byte, definitions []rule.Definition) (Config, error) {
	cfg, err := decodeConfigUnvalidated(data)
	if err != nil {
		return Config{}, err
	}
	for id, rc := range cfg.Rules {
		if rc.Severity == "" {
			continue
		}
		if _, perr := parseConfigSeverity(rc.Severity); perr != nil {
			rc.Severity = ""
			cfg.Rules[id] = rc
		}
	}
	if err := cfg.Validate(definitions); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// decodeConfigUnvalidated decodes the canonical JSON payload into a normalised
// Config without running structural validation. Shared by the strict and
// permissive load paths so the two cannot drift on decode behaviour.
func decodeConfigUnvalidated(data []byte) (Config, error) {
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
	return cfg.Normalized(), nil
}

// Validate checks schema, rule, threshold, option, path, and severity contracts.
func (cfg Config) Validate(definitions []rule.Definition) error {
	if cfg.SchemaVersion != "" && cfg.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schemaVersion %q; expected %q. Run `gruff-go init --force` to regenerate the config (your tuning is preserved)", cfg.SchemaVersion, SchemaVersion)
	}
	byID := map[string]rule.Definition{}
	for _, definition := range definitions {
		byID[definition.ID] = definition
	}
	cfg = cfg.Normalized()
	checks := []func() error{
		func() error { return validateDeepScanBudget(cfg.DeepScanBudget) },
		func() error { return validateRuleIDs("selected", cfg.Select, byID) },
		func() error { return validateRuleIDs("excluded", cfg.ExcludeRules, byID) },
		func() error { return validatePatterns("ignorePaths", cfg.IgnorePaths) },
		func() error { return validateAbbreviations(cfg.AcceptedAbbreviations) },
		func() error { return refuseSecretPreviews(cfg) },
		func() error { return validateRuleConfig(cfg.Rules, byID) },
		func() error { return validateSelection(cfg.Selection) },
		func() error { return validateSensitiveExclusions(cfg.SensitiveExclusions, byID) },
		func() error { return validateSeverityFloor(cfg.MinimumSeverity) },
		func() error { return validateCommandThresholds("failOn", cfg.FailOn) },
	}
	return runChecks(checks)
}

// RuleOptions converts parsed config into registry enablement and overrides.
func (cfg Config) RuleOptions() rule.Config {
	cfg = cfg.Normalized()
	defaults := rule.Defaults()
	definitions := defaults.Definitions()
	byID := definitionsByID(definitions)
	options := newRuleOptions(cfg)
	applySelectedRules(&options, cfg, definitions, byID)
	applyRuleOverrides(&options, cfg, definitions, byID)
	applyExcludedRules(&options, cfg, definitions, byID)
	return options
}

// newRuleOptions seeds registry options with project-wide config knobs.
func newRuleOptions(cfg Config) rule.Config {
	return rule.Config{
		Enabled:               map[string]bool{},
		Thresholds:            map[string]map[string]float64{},
		Severities:            map[string]finding.Severity{},
		Options:               map[string]map[string]any{},
		AcceptedAbbreviations: cfg.AcceptedAbbreviations,
	}
}

// applySelectedRules converts selection allowlists into explicit enablement.
func applySelectedRules(options *rule.Config, cfg Config, definitions []rule.Definition, byID map[string]rule.Definition) {
	if len(cfg.Select) > 0 || len(cfg.Selection.Pillars) > 0 {
		selected := map[string]struct{}{}
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
}

// applyRuleOverrides overlays per-rule enablement, severity, thresholds, and options.
func applyRuleOverrides(options *rule.Config, cfg Config, definitions []rule.Definition, byID map[string]rule.Definition) {
	for id, ruleConfig := range cfg.Rules {
		canonical, _ := canonicalRuleID(id, byID)
		if ruleConfig.Enabled != nil {
			options.Enabled[canonical] = *ruleConfig.Enabled
		}
		thresholds := copyThresholds(ruleConfig.Thresholds)
		if ruleConfig.Threshold != nil {
			definition := byID[canonical]
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
}

// applyExcludedRules removes rule and pillar denylist entries after selection and overrides.
func applyExcludedRules(options *rule.Config, cfg Config, definitions []rule.Definition, byID map[string]rule.Definition) {
	for _, id := range cfg.ExcludeRules {
		canonical, _ := canonicalRuleID(id, byID)
		options.Enabled[canonical] = false
	}
	for _, pillar := range cfg.Selection.ExcludePillars {
		for _, definition := range definitions {
			if definition.Pillar == finding.Pillar(pillar) {
				options.Enabled[definition.ID] = false
			}
		}
	}
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
	cfg.SensitiveExclusions = normalizedSensitiveExclusions(cfg.SensitiveExclusions)
	return cfg
}

// normalizedSensitiveExclusions rewrites each entry's path into the same
// project-relative display form a finding carries, so the caller's working
// directory cannot change which findings an entry claims. Order is preserved:
// the entry index is user-visible in both diagnostics and audit rows.
func normalizedSensitiveExclusions(entries []SensitiveExclusion) []SensitiveExclusion {
	if len(entries) == 0 {
		return entries
	}
	out := append([]SensitiveExclusion(nil), entries...)
	for index := range out {
		out[index].Path = strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(out[index].Path)), "./")
	}
	return out
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
