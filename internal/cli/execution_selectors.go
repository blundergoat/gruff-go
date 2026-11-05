// Package cli resolves the family's execution selectors: the flags that choose what runs, not what is shown.
//
// Execution selectors and display selectors affect different parts of the run.
// The --show-rule and --hide-rule flags filter a finished report, so the score and the exit code are the same with or without them.
// The --include-rule and --exclude-rule flags change which rules execute, so they can move the score and what a baseline records.
//
// Keeping them apart is what lets a user tell "I hid this" from "I never checked for this".
package cli

import (
	"fmt"

	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// executionSelectors carries the four selectors that decide which rules run for this invocation.
//
// Each field holds a comma-separated list; applyExecutionSelectors validates it and folds it into the loaded configuration.
// When all four are empty, no selector was given and the configured registry runs unchanged.
type executionSelectors struct {
	// includeRules adds rule IDs to the configured allowlist; empty adds none and leaves the configured selection as it is.
	includeRules string
	// excludeRules names rules not to run, applied after any inclusion.
	excludeRules string
	// includePillars adds pillar names to the configured pillar allowlist, in the same additive sense as includeRules.
	includePillars string
	// excludePillars names pillars not to run.
	excludePillars string
}

// requested reports whether the user asked for any restriction at all.
// It reports false when all four selectors are empty, and applyExecutionSelectors then keeps the configured registry.
func (selectors executionSelectors) requested() bool {
	return selectors.includeRules != "" || selectors.excludeRules != "" ||
		selectors.includePillars != "" || selectors.excludePillars != ""
}

// applyExecutionSelectors rebuilds the rule registry so only the rules the user asked for actually run.
//
// The selectors are folded into the loaded configuration rather than filtered afterwards, so a command line and a
// configuration file that name the same rules produce one registry and one score.
//
// Rule ids in selectors must appear in definitions, and pillar names must belong to the ratified vocabulary.
// The validated values are appended to copies of the rule and pillar selection and exclusion lists taken from cfg.
//
// With no selector requested it returns a zero Registry, cfg unchanged and a nil error, since the configured registry already applies.
// Otherwise it returns the registry rule.DefaultsConfigured builds from the merged configuration, together with that merged configuration.
// It fails, with a zero Registry and the original cfg, when either validator refuses a value or rule.DefaultsConfigured cannot build the registry.
func applyExecutionSelectors(cfg cfgpkg.Config, selectors executionSelectors, definitions []rule.Definition) (rule.Registry, cfgpkg.Config, error) {
	// Without a selector the configured registry already answers the question, and rebuilding it would only risk drift.
	if !selectors.requested() {
		return rule.Registry{}, cfg, nil
	}

	includeRules, err := validatedRuleIDs(selectors.includeRules, definitions)
	// A misspelt rule ID in --include-rule returns an unknown rule error here, so the user never gets a quietly different run.
	if err != nil {
		return rule.Registry{}, cfg, err
	}

	excludeRules, err := validatedRuleIDs(selectors.excludeRules, definitions)
	if err != nil {
		return rule.Registry{}, cfg, err
	}

	includePillars, err := validatedPillarNames(selectors.includePillars)
	if err != nil {
		return rule.Registry{}, cfg, err
	}

	excludePillars, err := validatedPillarNames(selectors.excludePillars)
	if err != nil {
		return rule.Registry{}, cfg, err
	}

	// Selectors extend the configured lists rather than replace them, so the configured entries stay in the merged selection.
	selected := cfg
	selected.Select = append(append([]string{}, cfg.Select...), includeRules...)
	selected.ExcludeRules = append(append([]string{}, cfg.ExcludeRules...), excludeRules...)
	selected.Selection.Pillars = append(append([]string{}, cfg.Selection.Pillars...), includePillars...)
	selected.Selection.ExcludePillars = append(append([]string{}, cfg.Selection.ExcludePillars...), excludePillars...)

	registry, err := rule.DefaultsConfigured(selected.RuleOptions())
	// Only registry construction errors land here; a merged selection that leaves no rule active is not refused.
	if err != nil {
		return rule.Registry{}, cfg, err
	}

	return registry, selected, nil
}

// validatedRuleIDs splits a comma-separated rule list and refuses a name no rule answers to.
//
// Without this check a mistyped id would silently change what runs: an unknown include matches no rule, and an unknown exclude disables nothing.
// Refusing it keeps the user from believing they chose the rules when they did not.
//
// Each id that splitCSV takes from input must equal the ID of an entry in definitions.
// It returns the ids as splitCSV yields them, each known to definitions, and no ids when splitCSV finds none in input.
// It fails with a nil slice and an unknown rule error naming the first id that matches no definition.
func validatedRuleIDs(input string, definitions []rule.Definition) ([]string, error) {
	requestedIDs := splitCSV(input)
	known := map[string]struct{}{}

	for _, definition := range definitions {
		known[definition.ID] = struct{}{}
	}

	for _, id := range requestedIDs {
		if _, recognised := known[id]; !recognised {
			return nil, fmt.Errorf("unknown rule %q", id)
		}
	}

	return requestedIDs, nil
}

// validatedPillarNames splits a comma-separated pillar list and refuses a name outside the ratified vocabulary.
//
// It returns the string name of each pillar parsePillars reads from input, and an empty non-nil slice when it reads none.
// It fails with a nil slice and the parsePillars error when input holds a value parsePillars rejects, such as a misspelt pillar name.
func validatedPillarNames(input string) ([]string, error) {
	pillars, err := parsePillars(input)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(pillars))

	for _, pillar := range pillars {
		names = append(names, string(pillar))
	}

	return names, nil
}
