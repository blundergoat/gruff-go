// Package config validation helpers check rule overrides against registry defaults.
// They enforce supported pillar IDs, threshold ranges, and path pattern rules.
package config

import (
	"fmt"
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

// validateAbbreviations rejects non-uppercase accepted-abbreviation entries.
func validateAbbreviations(values []string) error {
	for index, abbreviation := range values {
		if abbreviation == "" || abbreviation != strings.ToUpper(abbreviation) {
			return fmt.Errorf("acceptedAbbreviations[%d] must be uppercase", index)
		}
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
