// Package config validation helpers check rule overrides against registry defaults.
// They enforce supported pillar IDs, threshold ranges, and path pattern rules.
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

// runChecks evaluates a list of validation closures and returns the first error.
func runChecks(checks []func() error) error {
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// validateRuleIDs rejects unknown rule IDs from select/exclude lists.
func validateRuleIDs(label string, ids []string, definitions map[string]rule.Definition) error {
	for _, id := range ids {
		if _, ok := canonicalRuleID(id, definitions); !ok {
			return fmt.Errorf("unknown %s rule %q", label, id)
		}
	}
	return nil
}

// validatePatterns ensures each glob pattern stays inside the project root.
func validatePatterns(label string, patterns []string) error {
	for index, pattern := range patterns {
		if err := pathfilter.Validate(pattern); err != nil {
			return fmt.Errorf("%s[%d]: %w", label, index, err)
		}
	}
	return nil
}

// validateAbbreviations rejects blank accepted-abbreviation entries. Case is
// not enforced: the rule consumer (naming.acronym-case, see
// internal/rule/naming_acronym.go `lowerStringSet`) trims and lowercases
// entries for matching, and the sibling gruff-rs / gruff-ts / gruff-py /
// gruff-php ports all accept the same lowercase universal vocabulary list.
func validateAbbreviations(values []string) error {
	for index, abbreviation := range values {
		if strings.TrimSpace(abbreviation) == "" {
			return fmt.Errorf("acceptedAbbreviations[%d] must not be blank", index)
		}
	}
	return nil
}

// validateDeepScanBudget rejects limits that cannot represent an exact positive file bound.
func validateDeepScanBudget(budget DeepScanBudgetConfig) error {
	if budget.MaxLines != nil && *budget.MaxLines <= 0 {
		return fmt.Errorf("deepScanBudget.maxLines must be a positive integer")
	}
	if budget.MaxBytes != nil && *budget.MaxBytes <= 0 {
		return fmt.Errorf("deepScanBudget.maxBytes must be a positive integer")
	}
	return nil
}

// validateRuleConfig validates every per-rule override entry.
func validateRuleConfig(rules map[string]RuleConfig, definitions map[string]rule.Definition) error {
	for id, ruleConfig := range rules {
		if err := validateOneRuleConfig(id, ruleConfig, definitions); err != nil {
			return err
		}
	}
	return nil
}

// validateOneRuleConfig checks thresholds, options, and severity for one rule entry.
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
	if ruleConfig.Severity != "" {
		if _, err := parseConfigSeverity(ruleConfig.Severity); err != nil {
			return fmt.Errorf("rule %q has invalid severity %q", id, ruleConfig.Severity)
		}
	}
	return nil
}

// validateSingularThreshold ensures the legacy single-threshold form is allowed and positive.
func validateSingularThreshold(id string, ruleConfig RuleConfig, definition rule.Definition) error {
	if ruleConfig.Threshold == nil {
		return nil
	}
	if len(ruleConfig.Thresholds) > 0 {
		return fmt.Errorf("rule %q cannot combine threshold and thresholds", id)
	}
	if len(definition.Thresholds) != 1 {
		return fmt.Errorf("rule %q cannot use singular threshold", id)
	}
	if *ruleConfig.Threshold <= 0 {
		return fmt.Errorf("rule %q threshold must be positive", id)
	}
	return nil
}

// validateNamedThresholds rejects unknown threshold keys and non-positive values.
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

// validateOptions rejects unknown option keys for the given rule.
func validateOptions(id string, ruleConfig RuleConfig, definition rule.Definition) error {
	for name := range ruleConfig.Options {
		if _, ok := definition.Options[name]; !ok {
			return fmt.Errorf("rule %q has unknown option %q", id, name)
		}
	}
	return nil
}

// minimumSeverityCommands is the set of CLI command names valid as
// minimumSeverity keys. Mirrors the keyed-default map in
// finding.DefaultFailThresholdFor; any new gating command must be added in
// both places (per the lockstep contract documented in ADR-010).
var minimumSeverityCommands = map[string]struct{}{
	"analyse":   {},
	"summary":   {},
	"report":    {},
	"dashboard": {},
}

// validateCommandThresholds rejects unknown command keys and unknown FailThreshold
// values. Deterministic iteration: map keys are sorted before reporting so the
// first-error returned by runChecks is stable across runs.
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
		if _, err := finding.ParseFailThreshold(value); err != nil {
			return fmt.Errorf("%s.%s: %s", label, cmd, err.Error())
		}
	}
	return nil
}

// sortStringSlice sorts a string slice in place. Inlined here rather than
// importing sort to keep validate.go's import list minimal.
func sortStringSlice(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j-1] > values[j]; j-- {
			values[j-1], values[j] = values[j], values[j-1]
		}
	}
}

// validateSelection rejects unknown pillar IDs and unsupported tier selections.
func validateSelection(selection SelectionConfig) error {
	for _, pillar := range append(append([]string{}, selection.Pillars...), selection.ExcludePillars...) {
		if !finding.Pillar(pillar).Valid() {
			return fmt.Errorf("unknown pillar %q", pillar)
		}
	}
	if len(selection.Tiers) > 0 {
		return fmt.Errorf("selection.tiers is not supported by gruff-go")
	}
	return nil
}

// sensitiveExclusionRulePatterns are the glob, selector, and regular-expression
// metacharacters a sensitiveExclusions rule ID may never contain. The dot is
// absent on purpose: every rule ID carries one.
const sensitiveExclusionRulePatterns = "*?[]{}()|^$+\\"

// sensitiveExclusionPathPatterns are the glob metacharacters a
// sensitiveExclusions path may never contain. A path names one file, so a
// pattern would suppress findings across files nobody enumerated.
const sensitiveExclusionPathPatterns = "*?[]{}"

// validateSensitiveExclusions enforces the ratified section 13a entry contract.
// Each failure is fatal and names both the entry index and the offending key, so
// a reviewer can find the entry without counting list items.
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

// validateOneSensitiveExclusion checks the closed key set, the rule, the path,
// and the rationale of a single entry, in that order.
func validateOneSensitiveExclusion(index int, entry SensitiveExclusion, definitions map[string]rule.Definition) error {
	if len(entry.UnsupportedKeys) > 0 {
		return fmt.Errorf("sensitiveExclusions[%d] has unsupported key %q; only rule, path, symbol and reason are allowed", index, entry.UnsupportedKeys[0])
	}
	if err := validateSensitiveExclusionRule(index, entry.Rule, definitions); err != nil {
		return err
	}
	if err := validateSensitiveExclusionPath(index, entry.Path); err != nil {
		return err
	}
	if strings.TrimSpace(entry.Reason) == "" {
		return fmt.Errorf("sensitiveExclusions[%d].reason must be a non-empty rationale", index)
	}
	return nil
}

// validateSensitiveExclusionRule rejects anything that is not one exact
// sensitive-data rule ID: a blank, a pattern, a pillar selector, an unknown ID,
// or a known ID from another pillar.
func validateSensitiveExclusionRule(index int, id string, definitions map[string]rule.Definition) error {
	label := fmt.Sprintf("sensitiveExclusions[%d].rule", index)
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%s must name exactly one rule ID", label)
	}
	if strings.ContainsAny(id, sensitiveExclusionRulePatterns) {
		return fmt.Errorf("%s must name exactly one rule ID, not the pattern %q", label, id)
	}
	if finding.Pillar(id).Valid() {
		return fmt.Errorf("%s must name exactly one rule ID, not the pillar %q", label, id)
	}
	definition, known := definitions[id]
	if !known {
		return fmt.Errorf("%s names unknown rule %q", label, id)
	}
	if definition.Pillar != finding.PillarSensitiveData {
		return fmt.Errorf("%s names %q, which is outside the sensitive-data pillar", label, id)
	}
	return nil
}

// validateSensitiveExclusionPath rejects anything that is not one project-relative
// file: a blank, an absolute path, a parent traversal, or a glob.
func validateSensitiveExclusionPath(index int, path string) error {
	label := fmt.Sprintf("sensitiveExclusions[%d].path", index)
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s must name exactly one project-relative file", label)
	}
	if strings.HasPrefix(path, "/") || filepath.IsAbs(path) {
		return fmt.Errorf("%s must be project-relative, not the absolute path %q", label, path)
	}
	if slices.Contains(strings.Split(path, "/"), "..") {
		return fmt.Errorf("%s must stay inside the project; %q escapes it", label, path)
	}
	if strings.ContainsAny(path, sensitiveExclusionPathPatterns) {
		return fmt.Errorf("%s must name exactly one file, not the pattern %q", label, path)
	}
	return nil
}
