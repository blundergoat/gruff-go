// Package config loads and validates the .gruff-go.yaml a user keeps at the project root or names as an explicit config path.
//
// It owns the strict schema, legacy rule-ID compatibility, default config discovery, and conversion into rule-registry options.
// A file that fails any check here stops the load with an error instead of being half-applied.
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

// Config is the canonical in-memory representation of the .gruff-go.yaml a user writes.
//
// Gruff-family alias sections such as paths, allowlists and selection are folded into the top-level fields by Normalized, except selection pillars.
// An empty Config, from noConfig or no file found, leaves every rule at its registry default.
type Config struct {
	// SchemaVersion identifies the gruff-go config schema this file targets.
	SchemaVersion string `json:"schemaVersion,omitempty"`
	// MinimumSeverity is the configured display floor, the lowest severity shown by a command that applies it.
	//
	// It never changes an exit code, a score, or a baseline.
	// Before 0.6.0 this key was the per-command exit gate, which is why the map form is refused rather than reinterpreted.
	MinimumSeverity SeverityFloor `json:"minimumSeverity,omitempty"`
	// FailOn sets the per-command exit-code threshold that minimumSeverity used to carry.
	//
	// Keys are command names (analyse, summary, report, dashboard); values are FailThreshold strings (advisory, warning, error, none).
	// A bare string applies to every command. Absent keys fall back to finding.DefaultFailThresholdFor(cmd).
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
	// SensitiveExclusions suppresses individual sensitive-data findings by exact rule ID and project-relative path.
	//
	// Each entry carries a required written rationale.
	// It is kept apart from Select/ExcludeRules so the ban on message- and value-matching keys is structural (FAMILY-CONTRACT.md section 13a).
	SensitiveExclusions []SensitiveExclusion `json:"sensitiveExclusions,omitempty"`
	// Paths nests path-scoped policy (currently the canonical `ignore` list).
	Paths PathsConfig `json:"paths,omitempty"`
	// Allowlists nests project-wide allowlists folded into top-level fields by Normalized.
	Allowlists AllowlistsConfig `json:"allowlists,omitempty"`
	// Selection nests rule and pillar selectors; Normalized folds only Rules and ExcludeRules into the top-level Select and ExcludeRules.
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
	// Enabled turns the rule on or off when set; nil keeps whatever select or the registry default already decided.
	Enabled *bool `json:"enabled,omitempty"`
	// Threshold sets the value for a rule with exactly one declared threshold; it cannot be combined with Thresholds.
	Threshold *float64 `json:"threshold,omitempty"`
	// Thresholds sets named numeric thresholds when the rule has more than one knob.
	Thresholds map[string]float64 `json:"thresholds,omitempty"`
	// Options carries rule-specific configuration values keyed by option name.
	Options map[string]any `json:"options,omitempty"`
	// Severity overrides the rule's default severity with advisory, warning or error.
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

// SensitiveExclusion is one ratified sensitive-data suppression scope a user writes under sensitiveExclusions.
//
// It names one rule, one project-relative path, an optional symbol narrowing, and the rationale a reviewer reads in place of the finding.
//
// The four fields below are the whole key set an entry may carry.
// Any other key, such as message_contains, messageContains, value or preview, is a fatal configuration error (FAMILY-CONTRACT.md section 13a).
// That keeps value-based suppression from re-entering this section under a new name.
type SensitiveExclusion struct {
	// Rule is the exact sensitive-data rule ID this entry suppresses.
	Rule string `json:"rule"`
	// Path is the project-relative display path the entry is scoped to.
	Path string `json:"path"`
	// Symbol narrows the scope to findings carrying that exact symbol; empty matches any.
	Symbol string `json:"symbol,omitempty"`
	// Reason is the required rationale published in the report's suppression audit row.
	Reason string `json:"reason"`
	// UnsupportedKeys records the keys this entry carried outside the four above, so validation can name the offender with the entry index.
	//
	// Never serialised: it is decode state, not configuration.
	UnsupportedKeys []string `json:"-"`
}

// UnmarshalJSON decodes one sensitiveExclusions entry, collecting keys outside the closed set rather than failing on the first one.
//
// The shared decoder's DisallowUnknownFields reports such a key without the entry index, and section 13a requires the diagnostic to name both.
//
// The data argument is the raw JSON object for one sensitiveExclusions entry; unsupported keys are recorded, sorted, in UnsupportedKeys.
// It returns an error when data does not decode into a map of keys, or when a rule, path, symbol or reason value is neither a string nor null.
func (entry *SensitiveExclusion) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	targets := map[string]*string{"rule": &entry.Rule, "path": &entry.Path, "symbol": &entry.Symbol, "reason": &entry.Reason}
	for key, value := range raw {
		target, supported := targets[key]
		// A message_contains or value key lands here; Validate later refuses the entry and names its index.
		if !supported {
			entry.UnsupportedKeys = append(entry.UnsupportedKeys, key)
			continue
		}
		// A rule or reason written as a number or a list, such as rule: 42, lands here and the config fails to load.
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
//
// When noConfig is true no file is read; otherwise explicitPath, joined to root when relative, or discovery under root selects the file.
// An empty root means the current directory.
//
// It returns the Config validated against definitions with its absolute slash-separated Path; with noConfig or no file found, both are zero.
// An empty or comment-only file skips validation and gives a zero Config, though Path is still set.
//
// It returns an error when the explicit path is missing or a directory, or when the file cannot be read, parsed or validated.
func LoadAuto(root string, explicitPath string, noConfig bool, definitions []rule.Definition) (Loaded, error) {
	if noConfig {
		return Loaded{Config: Config{}}, nil
	}
	path, ok, err := ResolvePath(root, explicitPath)
	// An explicit path that is missing fails here; no .gruff-go.yaml under root is not an error and leaves every rule at its registry default.
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
//
// An empty root means the current directory; a relative explicitPath is joined to the absolute root, and an empty one triggers discovery.
// It returns an absolute path and true for a file, or an empty path, false and nil if discovery finds none, skipping directories and stat errors.
// It returns an error when the explicit file is missing, is a directory, or cannot be checked, or when root cannot be made absolute.
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
			// A typo in the explicit config path lands here, and the error names the path as the user typed it.
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
	// Discovery checks only root itself for .gruff-go.yaml; parent directories are never searched.
	for _, name := range defaultConfigFiles {
		path := filepath.Join(rootAbs, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, true, nil
		}
	}
	return "", false, nil
}

// Load reads and parses a config file from disk.
//
// The file at path is read and passed to ParseFile, which requires a .yaml extension and checks rule references against definitions.
// It returns the parsed Config, or a zero Config without validation when the file is empty or holds only blank and comment lines.
// It returns an error when the file cannot be read, is not .yaml, or fails parsing or validation.
func Load(path string, definitions []rule.Definition) (Config, error) {
	// #nosec G304 -- CLI intentionally reads an explicit user-provided config path.
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseFile(path, data, definitions)
}

// LoadPermissive reads a config file for migration or preservation, such as init --force regenerating it with the user's tuning kept.
//
// Per-rule severity overrides that fail strict ADR-009 validation are cleared, so those rules keep their registry default severity.
// Do NOT use this for runtime scans - it would silently weaken severity gates.
//
// The file at path is read and parsed with definitions, the known rules the cleaned config is still validated against.
// Empty or comment-only content gives a zero Config without that validation.
// It returns an error when the file cannot be read or the remaining config fails parsing or validation.
func LoadPermissive(path string, definitions []rule.Definition) (Config, error) {
	// #nosec G304 -- CLI intentionally reads an explicit user-provided config path.
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return parseYAMLPermissive(data, definitions)
}

// Parse parses config bytes using the supported strict YAML subset.
//
// The data bytes are the config file contents and definitions are the known rules its rule references are checked against.
// It returns the parsed Config, or a zero Config without validation when data is empty or holds only blank and comment lines.
// It returns an error when data falls outside the supported YAML subset or fails validation.
func Parse(data []byte, definitions []rule.Definition) (Config, error) {
	return parseYAML(data, definitions)
}

// ParseFile parses config bytes after validating the file extension.
//
// Only the extension of path matters and must match .yaml case-insensitively; definitions are the known rules the config is checked against.
// For a .yaml path it returns the Config parsed from data, or a zero Config without validation when data is empty or comment-only.
// It returns an error when the extension is not .yaml or data does not parse or validate.
func ParseFile(path string, data []byte, definitions []rule.Definition) (Config, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml":
		return parseYAML(data, definitions)
	default:
		return Config{}, fmt.Errorf("unsupported config file extension %q (want .yaml)", filepath.Ext(path))
	}
}

// decodeConfigPayload unmarshals canonical JSON payloads from the YAML parser.
//
// The data bytes are the canonical JSON the YAML parser produced, and definitions are the known rules the decoded Config is validated against.
// It returns the normalised Config, or a zero Config and an error when decoding or validation fails.
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

// decodeConfigPayloadPermissive decodes canonical JSON like decodeConfigPayload, for LoadPermissive on the init --force preserve path.
//
// Before validation it drops any per-rule severity override that does not parse against the current 3-bucket vocabulary.
//
// The data bytes are the canonical JSON payload, and definitions are the known rules the cleaned Config is validated against.
// It returns the normalised Config with unparseable severity overrides cleared, or a zero Config and an error when decoding or validation fails.
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

// decodeConfigUnvalidated decodes the canonical JSON payload into a normalised Config without running structural validation.
//
// Shared by the strict and permissive load paths so the two cannot drift on decode behaviour.
// The data bytes must hold exactly one canonical JSON value with no removed preview keys.
// Unknown fields are rejected except inside sensitiveExclusions entries, where UnsupportedKeys records them for Validate.
//
// It returns the Normalized Config, or a zero Config and an error when any of those checks or the decode fails.
func decodeConfigUnvalidated(data []byte) (Config, error) {
	// The removed preview key is refused before the strict decoder sees it, so a 0.5 user reads the section 5
	// explanation rather than an unknown-field error that looks like a typo.
	if err := refuseRemovedPreviewKeys(data); err != nil {
		return Config{}, err
	}
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	var trailing struct{}
	// Any value left after the one config object lands here and the whole file is refused.
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, fmt.Errorf("config contains trailing values")
	}
	return cfg.Normalized(), nil
}

// Validate checks schema, rule, threshold, option, path, and severity contracts.
//
// Rule references in Select, ExcludeRules, Rules and SensitiveExclusions are checked against definitions, the known rule registry entries.
// It returns an error when schemaVersion is absent or unsupported or when any check fails, and nil for a valid config.
func (cfg Config) Validate(definitions []rule.Definition) error {
	// A missing schemaVersion stops loading with the init --force hint, as gruff-php, gruff-py, gruff-rs and gruff-ts also refuse such a file.
	// init always writes the key, so only a hand-written config reaches this.
	if cfg.SchemaVersion == "" {
		return fmt.Errorf("config must include `schemaVersion: %s` at the top. Run `gruff-go init --force` to regenerate the config (your tuning is preserved)", SchemaVersion)
	}
	// A schemaVersion typo, or a config written for another schema, stops here with the init --force hint.
	if cfg.SchemaVersion != SchemaVersion {
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
		func() error { return validateRuleConfig(cfg.Rules, byID) },
		func() error { return validateSelection(cfg.Selection) },
		func() error { return validateSensitiveExclusions(cfg.SensitiveExclusions, byID) },
		func() error { return validateSeverityFloor(cfg.MinimumSeverity) },
		func() error { return validateCommandThresholds("failOn", cfg.FailOn) },
	}
	return runChecks(checks)
}

// RuleOptions converts parsed config into registry enablement and overrides for the scan.
//
// It returns a rule.Config built against rule.Defaults whose maps hold only the selections, overrides and exclusions this config makes.
// A config with none of those yields empty maps plus its AcceptedAbbreviations, so every rule keeps its registry default.
// Exclusions apply last, so excludeRules or excludePillars beats both select and a rule's enabled: true.
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
//
// Only the AcceptedAbbreviations slice of cfg is carried over; the Enabled, Thresholds, Severities and Options maps start empty.
// It returns a rule.Config with those empty, non-nil maps for the apply steps to fill.
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
//
// When cfg lists Select rules or Selection.Pillars, every rule in definitions gets an explicit options.Enabled entry, true only if selected.
// With no pillar selected, listing one rule under select turns every unlisted rule off here; a later enabled: true can turn one back on.
// Select IDs resolve through byID, the definitions keyed by ID, and unknown IDs are skipped; with no selection, options is left unchanged.
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

// applyRuleOverrides overlays per-rule enablement, severity, thresholds, and options from the rules section.
//
// Each Rules key in cfg is resolved through byID, the definitions keyed by ID, and its settings are written into options under the canonical ID.
// A single Threshold value is applied to every threshold name byID lists for that rule; the definitions slice is not read here.
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

// applyExcludedRules removes rule and pillar denylist entries after selection and overrides, so an exclusion always wins.
//
// Each ExcludeRules ID in cfg is resolved through byID, the definitions keyed by ID, and disabled in options.
// Every rule in definitions whose pillar appears in Selection.ExcludePillars is disabled as well.
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
// A nil or empty input yields an empty, non-nil map, so callers can add entries to the result.
func copyThresholds(input map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

// Normalized folds legacy and gruff-family fields into canonical locations.
//
// It returns a copy with each non-empty alias list merged, without duplicates, into its top-level field.
// Select, ExcludeRules, IgnorePaths and AcceptedAbbreviations are then sorted, and any of them with no entries comes back nil.
// The nested alias fields keep their values, and SensitiveExclusions paths are cleaned by normalizedSensitiveExclusions.
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

// normalizedSensitiveExclusions rewrites each entry's path into the project-relative display form a finding carries.
//
// Removing a leading ./ lets an entry match a finding whose display path omits that prefix.
// Order is preserved: the entry index is user-visible in both diagnostics and audit rows.
//
// The entries slice is not modified; each Path is trimmed of whitespace, converted to forward slashes, and stripped of one leading ./ prefix.
// It returns a new slice with those paths, or entries itself when it is nil or empty.
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

// mergeStringLists appends gruff-family aliases to their legacy top-level counterparts before the deterministic sort step.
// It returns a new slice holding the values from primary then from alias, first occurrence kept, and an empty non-nil slice when both are empty.
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

// sortedCopy returns a sorted copy of values so config output is deterministic; an empty or nil values gives nil.
func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	slices.Sort(out)
	return out
}

// canonicalRuleID maps accepted legacy rule aliases onto live rule IDs, so an old rule ID in a config keeps working.
//
// The id is tried as written, then with a documentation. or documentation- prefix turned into docs., then as a live ID with each dot as a hyphen.
// The definitions map holds the live rules by ID; it returns the canonical ID and true, or an empty string and false when no form matches.
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
//
// It returns a new map from each definition's ID to that definition, empty but non-nil when definitions is empty.
// A later definition with a duplicate ID replaces the earlier one.
func definitionsByID(definitions []rule.Definition) map[string]rule.Definition {
	out := make(map[string]rule.Definition, len(definitions))
	for _, definition := range definitions {
		out[definition.ID] = definition
	}
	return out
}

// parseConfigSeverity validates a per-rule severity override from a rule's severity key.
//
// Per ADR-009 the hard-break migration accepts only the 3-bucket names advisory, warning and error.
// Legacy 5-bucket names (critical/high/medium/low/info) and the old aliases (notice/warn) must be migrated in the user's config before it loads.
//
// The input string is the severity text from a rule's config entry, passed to finding.ParseSeverity unchanged.
// It returns the matching finding.Severity, or an error when input is not one of the accepted 3-bucket names.
func parseConfigSeverity(input string) (finding.Severity, error) {
	return finding.ParseSeverity(input)
}
