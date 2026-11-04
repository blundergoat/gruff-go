// Package config validation helpers check rule overrides against registry defaults.
//
// They enforce known rule IDs, supported pillar IDs, positive thresholds and deep-scan budgets, and safe path patterns.
// Each validator returns an error naming the offending config entry, so the user can find it in their config file.
package config

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/pathfilter"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// runChecks runs config validation closures in order and returns the first error, so the user sees only the first of several problems.
// It stops at the first of the checks that fails, and returns nil when every closure passes or checks is empty.
func runChecks(checks []func() error) error {
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// validateRuleIDs rejects unknown rule IDs in a config select or exclude list, such as a misspelt rule ID.
//
// Each entry in ids must resolve to a known rule in definitions through canonicalRuleID; label names the list in the message.
// It returns an error naming label and the first unknown ID, or nil when every ID resolves or ids is empty.
func validateRuleIDs(label string, ids []string, definitions map[string]rule.Definition) error {
	for _, id := range ids {
		if _, ok := canonicalRuleID(id, definitions); !ok {
			return fmt.Errorf("unknown %s rule %q", label, id)
		}
	}
	return nil
}

// validatePatterns ensures each glob pattern in a config path list stays inside the project root.
//
// Each entry in patterns is checked with pathfilter.Validate, and label names the list in the message along with the failing index.
// It returns an error wrapping the pathfilter.Validate failure for the first invalid pattern, or nil when patterns is empty or all are valid.
func validatePatterns(label string, patterns []string) error {
	for index, pattern := range patterns {
		if err := pathfilter.Validate(pattern); err != nil {
			return fmt.Errorf("%s[%d]: %w", label, index, err)
		}
	}
	return nil
}

// validateAbbreviations rejects blank acceptedAbbreviations entries, such as an empty list item left in the config file.
//
// Case is not enforced: naming.acronym-case trims and lowercases entries for matching, see lowerStringSet in internal/rule/naming_acronym.go.
// The sibling gruff-rs, gruff-ts, gruff-py and gruff-php ports all accept the same lowercase universal vocabulary list.
//
// Each of the values is trimmed only for the blank test; it returns an error naming the index of the first blank entry, or nil when none is blank.
func validateAbbreviations(values []string) error {
	for index, abbreviation := range values {
		if strings.TrimSpace(abbreviation) == "" {
			return fmt.Errorf("acceptedAbbreviations[%d] must not be blank", index)
		}
	}
	return nil
}

// validateDeepScanBudget rejects deepScanBudget limits in the config file that cannot represent an exact positive file bound.
//
// The budget fields MaxLines and MaxBytes are optional, and a nil field passes unchecked.
// It returns an error naming the first field set to zero or below, checking MaxLines before MaxBytes, or nil when both are unset or positive.
func validateDeepScanBudget(budget DeepScanBudgetConfig) error {
	if budget.MaxLines != nil && *budget.MaxLines <= 0 {
		return fmt.Errorf("deepScanBudget.maxLines must be a positive integer")
	}
	if budget.MaxBytes != nil && *budget.MaxBytes <= 0 {
		return fmt.Errorf("deepScanBudget.maxBytes must be a positive integer")
	}
	return nil
}

// validateRuleConfig validates every per-rule override entry from the config file.
//
// Each entry in rules maps a configured rule ID to its override and goes through validateOneRuleConfig with definitions.
// It returns the first error found, or nil when every entry is valid or rules is empty.
// With two bad overrides, map iteration order picks which error the user sees, so it can differ between runs.
func validateRuleConfig(rules map[string]RuleConfig, definitions map[string]rule.Definition) error {
	for id, ruleConfig := range rules {
		if err := validateOneRuleConfig(id, ruleConfig, definitions); err != nil {
			return err
		}
	}
	return nil
}

// validateOneRuleConfig checks thresholds, options, and severity for one rule override, catching a misspelt rule ID or a zero threshold.
//
// The id is the configured key, resolved through canonicalRuleID against definitions; ruleConfig holds the override being checked.
// It returns an error for an unknown id, the first threshold or option failure, or a non-empty Severity parseConfigSeverity rejects, else nil.
func validateOneRuleConfig(id string, ruleConfig RuleConfig, definitions map[string]rule.Definition) error {
	canonical, ok := canonicalRuleID(id, definitions)
	if !ok {
		return fmt.Errorf("unknown rule %q", id)
	}
	definition := definitions[canonical]
	if err := validateSingularThreshold(id, ruleConfig, definition); err != nil {
		return err
	}
	if err := validateNamedThresholds(id, ruleConfig, definition); err != nil {
		return err
	}
	if err := validateOptions(id, ruleConfig, definition); err != nil {
		return err
	}
	// Only a set severity is checked; a value parseConfigSeverity rejects, such as a typo, fails with the rule ID and the bad value.
	if ruleConfig.Severity != "" {
		if _, err := parseConfigSeverity(ruleConfig.Severity); err != nil {
			return fmt.Errorf("rule %q has invalid severity %q", id, ruleConfig.Severity)
		}
	}
	return nil
}

// validateSingularThreshold ensures the legacy single-threshold form of a rule override is allowed and positive.
//
// The id names the rule in messages, and definition must declare exactly one threshold for the Threshold in ruleConfig to be accepted.
// It returns nil when Threshold is unset and an error when Thresholds is also set, the threshold count is wrong, or the value is not positive.
func validateSingularThreshold(id string, ruleConfig RuleConfig, definition rule.Definition) error {
	if ruleConfig.Threshold == nil {
		return nil
	}
	if len(ruleConfig.Thresholds) > 0 {
		return fmt.Errorf("rule %q cannot combine threshold and thresholds", id)
	}
	// A rule with no threshold or several named ones rejects a bare threshold value; the named ones belong in the thresholds map.
	if len(definition.Thresholds) != 1 {
		return fmt.Errorf("rule %q cannot use singular threshold", id)
	}
	if *ruleConfig.Threshold <= 0 {
		return fmt.Errorf("rule %q threshold must be positive", id)
	}
	return nil
}

// validateNamedThresholds rejects unknown threshold keys and non-positive values in a rule override's thresholds map.
//
// The id names the rule in messages; each key of the Thresholds map in ruleConfig must be declared by definition and hold a value above zero.
// It returns an error for the first unknown key or non-positive value in map iteration order, or nil when every entry passes or none is set.
func validateNamedThresholds(id string, ruleConfig RuleConfig, definition rule.Definition) error {
	for name, value := range ruleConfig.Thresholds {
		if _, ok := definition.Thresholds[name]; !ok {
			return fmt.Errorf("rule %q has unknown threshold %q", id, name)
		}
		if value <= 0 {
			return fmt.Errorf("rule %q threshold %q must be positive", id, name)
		}
	}
	return nil
}

// validateOptions rejects unknown option keys in a rule override, such as a misspelt option name.
//
// The id names the rule in messages; each key of the Options map in ruleConfig must be declared by definition, and option values are not checked.
// It returns an error for the first unknown key in map iteration order, or nil when every key is known or no options are set.
func validateOptions(id string, ruleConfig RuleConfig, definition rule.Definition) error {
	for name := range ruleConfig.Options {
		if _, ok := definition.Options[name]; !ok {
			return fmt.Errorf("rule %q has unknown option %q", id, name)
		}
	}
	return nil
}

// minimumSeverityCommands is the set of CLI command names valid as failOn keys in the config file.
//
// Despite its name it does not key minimumSeverity, which is one scalar display floor.
// It mirrors the keyed-default map in finding.DefaultFailThresholdFor, under the lockstep contract documented in ADR-010.
// Any new gating command must be added in both places.
//
// A key outside this set, such as hook or baseline, fails config validation with an unknown command error.
var minimumSeverityCommands = map[string]struct{}{
	"analyse":   {},
	"summary":   {},
	"report":    {},
	"dashboard": {},
}

// validateCommandThresholds checks the config file's per-command failOn map, which sets exit-code thresholds by command.
//
// The entries map command names to fail-threshold values, and label is the config key prefixed to every message.
// Keys must appear in minimumSeverityCommands and values must parse with finding.ParseFailThreshold; empty entries return nil.
//
// Keys are checked in sorted order, so with several bad entries the first error runChecks returns is stable across runs.
// It returns an error for the first unknown command or unparseable value in that order.
func validateCommandThresholds(label string, entries CommandThresholds) error {
	if len(entries) == 0 {
		return nil
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sortedKeys := append([]string(nil), keys...)
	sortStringSlice(sortedKeys)
	for _, cmd := range sortedKeys {
		if _, ok := minimumSeverityCommands[cmd]; !ok {
			return fmt.Errorf("%s has unknown command %q", label, cmd)
		}
		value := entries[cmd]
		// A value ParseFailThreshold rejects, such as a misspelt level, fails as label.command followed by the parser's reason.
		if _, err := finding.ParseFailThreshold(value); err != nil {
			return fmt.Errorf("%s.%s: %s", label, cmd, err.Error())
		}
	}
	return nil
}

// sortStringSlice sorts values in place in ascending byte-wise order, so config errors are reported in a stable order.
// It uses insertion sort rather than importing sort, keeping validate.go's import list minimal; an empty or one-element slice is unchanged.
func sortStringSlice(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j-1] > values[j]; j-- {
			values[j-1], values[j] = values[j], values[j-1]
		}
	}
}

// validateSelection rejects unknown pillar IDs and unsupported tier selections in the config file's selection block.
//
// Every pillar listed in selection, under Pillars or ExcludePillars, must be a valid finding.Pillar, and its Tiers list must be empty.
// It returns an error for the first unknown pillar, checking Pillars before ExcludePillars, then for any tier entry, or nil otherwise.
func validateSelection(selection SelectionConfig) error {
	for _, pillar := range append(append([]string{}, selection.Pillars...), selection.ExcludePillars...) {
		if !finding.Pillar(pillar).Valid() {
			return fmt.Errorf("unknown pillar %q", pillar)
		}
	}
	// Any selection.tiers entry fails rather than being ignored, so the user never believes a tier filter took effect.
	if len(selection.Tiers) > 0 {
		return fmt.Errorf("selection.tiers is not supported by gruff-go")
	}
	return nil
}

// sensitiveExclusionRulePatterns are the glob, selector, and regular-expression metacharacters a sensitiveExclusions rule ID may never contain.
//
// The dot is absent on purpose: every rule ID carries one.
// A pattern entry such as sensitive-data.* is rejected, so one exclusion can never silence a whole family of rules.
const sensitiveExclusionRulePatterns = "*?[]{}()|^$+\\"

// sensitiveExclusionPathPatterns are the glob metacharacters a sensitiveExclusions path may never contain.
//
// A path names one file, so a pattern would suppress findings across files nobody enumerated.
const sensitiveExclusionPathPatterns = "*?[]{}"

// validateSensitiveExclusions enforces the ratified section 13a entry contract on the config file's sensitiveExclusions list.
//
// Each failure is fatal and names both the entry index and the offending key, so a reviewer can find the entry without counting list items.
// Each of the entries is checked in order by validateOneSensitiveExclusion against definitions.
//
// An entry whose rule, path and symbol repeat an earlier entry's scope is rejected as a duplicate naming both indices.
// It returns the first such error, or nil when every entry passes or entries is empty.
func validateSensitiveExclusions(entries []SensitiveExclusion, definitions map[string]rule.Definition) error {
	scopes := map[string]int{}
	for index, entry := range entries {
		if err := validateOneSensitiveExclusion(index, entry, definitions); err != nil {
			return err
		}
		// Two entries claiming one scope would split the audit count arbitrarily.
		scope := strings.Join([]string{entry.Rule, entry.Path, entry.Symbol}, "\x00")
		if first, duplicated := scopes[scope]; duplicated {
			return fmt.Errorf("sensitiveExclusions[%d] is a duplicate scope of sensitiveExclusions[%d]; rule, path and symbol must name one entry", index, first)
		}
		scopes[scope] = index
	}
	return nil
}

// validateOneSensitiveExclusion checks the closed key set, the rule, the path, and the rationale of a single entry, in that order.
//
// The index is the entry's list position used in each message, entry is the parsed item, and definitions is the rule registry for the rule check.
// It returns an error for an unsupported key, an invalid rule or path, or a blank reason, and nil when the entry passes every check.
// The symbol field is not validated here.
func validateOneSensitiveExclusion(index int, entry SensitiveExclusion, definitions map[string]rule.Definition) error {
	// A misspelt or extra key, such as reasons or severity, fails here, and only the first unsupported key is named.
	if len(entry.UnsupportedKeys) > 0 {
		return fmt.Errorf("sensitiveExclusions[%d] has unsupported key %q; only rule, path, symbol and reason are allowed", index, entry.UnsupportedKeys[0])
	}
	if err := validateSensitiveExclusionRule(index, entry.Rule, definitions); err != nil {
		return err
	}
	if err := validateSensitiveExclusionPath(index, entry.Path); err != nil {
		return err
	}
	// A missing or whitespace-only reason fails, so every exclusion carries an audit rationale a reviewer can read.
	if strings.TrimSpace(entry.Reason) == "" {
		return fmt.Errorf("sensitiveExclusions[%d].reason must be a non-empty rationale", index)
	}
	return nil
}

// validateSensitiveExclusionRule rejects a sensitiveExclusions rule value that is not one exact sensitive-data rule ID.
//
// It rejects a blank, a pattern, a pillar selector, an unknown ID, or a known ID from another pillar, in that order.
// The index names the entry in messages, id is the configured rule value, and definitions is looked up by exact key with no alias resolution.
// It returns an error for the first failed check, or nil when id is a known sensitive-data rule ID.
func validateSensitiveExclusionRule(index int, id string, definitions map[string]rule.Definition) error {
	label := fmt.Sprintf("sensitiveExclusions[%d].rule", index)
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%s must name exactly one rule ID", label)
	}
	if strings.ContainsAny(id, sensitiveExclusionRulePatterns) {
		return fmt.Errorf("%s must name exactly one rule ID, not the pattern %q", label, id)
	}
	// A bare pillar name such as sensitive-data fails here: one exclusion may silence one rule, never a whole pillar.
	if finding.Pillar(id).Valid() {
		return fmt.Errorf("%s must name exactly one rule ID, not the pillar %q", label, id)
	}
	definition, known := definitions[id]
	if !known {
		return fmt.Errorf("%s names unknown rule %q", label, id)
	}
	// A real rule from another pillar, such as size.file-length, fails because these exclusions only cover sensitive-data findings.
	if definition.Pillar != finding.PillarSensitiveData {
		return fmt.Errorf("%s names %q, which is outside the sensitive-data pillar", label, id)
	}
	return nil
}

// validateSensitiveExclusionPath rejects a sensitiveExclusions path that is not one project-relative file.
//
// It rejects a blank, an absolute path, a parent traversal, or a glob, in that order.
// The index names the entry in messages and path is the configured file; a parent traversal is any slash-separated segment equal to two dots.
// It returns an error for the first failed check, or nil when path passes them all.
func validateSensitiveExclusionPath(index int, path string) error {
	label := fmt.Sprintf("sensitiveExclusions[%d].path", index)
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s must name exactly one project-relative file", label)
	}
	// The leading-slash test catches /etc/app.env on Windows too, where filepath.IsAbs alone would accept it as relative.
	if strings.HasPrefix(path, "/") || filepath.IsAbs(path) {
		return fmt.Errorf("%s must be project-relative, not the absolute path %q", label, path)
	}
	// Any .. segment fails, even one that stays inside the project such as config/../app.env.
	if slices.Contains(strings.Split(path, "/"), "..") {
		return fmt.Errorf("%s must stay inside the project; %q escapes it", label, path)
	}
	if strings.ContainsAny(path, sensitiveExclusionPathPatterns) {
		return fmt.Errorf("%s must name exactly one file, not the pattern %q", label, path)
	}
	return nil
}
