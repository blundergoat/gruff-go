// Package cli resolves the family's execution selectors: the flags that choose what runs, not what is shown.
//
// The family contract splits one idea gruff-go had merged. --show-rule and --hide-rule filter a finished report, so the
// score and the exit code are the same with or without them. --include-rule and --exclude-rule choose which rules
// execute, so the score moves and a baseline written under them records a smaller run. Keeping them apart is what lets
// a user tell "I hid this" from "I never checked for this".
package cli

import (
	"fmt"

	cfgpkg "github.com/blundergoat/gruff-go/internal/config"
	"github.com/blundergoat/gruff-go/internal/rule"
)

// executionSelectors carries the four selectors that decide which rules run for this invocation.
type executionSelectors struct {
	// includeRules names the only rules to run; empty means run everything the configuration enables.
	includeRules string
	// excludeRules names rules not to run, applied after any inclusion.
	excludeRules string
	// includePillars names the only pillars to run, in the same allowlist sense as includeRules.
	includePillars string
	// excludePillars names pillars not to run.
	excludePillars string
}

// requested reports whether the user asked for any restriction at all.
func (selectors executionSelectors) requested() bool {
	return selectors.includeRules != "" || selectors.excludeRules != "" ||
		selectors.includePillars != "" || selectors.excludePillars != ""
}

// applyExecutionSelectors rebuilds the rule registry so only the rules the user asked for actually run.
//
// The selectors are folded into the loaded configuration rather than filtered afterwards, so a command line and a
// configuration file that name the same rules produce one registry and one score.
func applyExecutionSelectors(cfg cfgpkg.Config, selectors executionSelectors, definitions []rule.Definition) (rule.Registry, cfgpkg.Config, error) {
	// Without a selector the configured registry already answers the question, and rebuilding it would only risk drift.
	if !selectors.requested() {
		return rule.Registry{}, cfg, nil
	}

	includeRules, err := validatedRuleIDs(selectors.includeRules, definitions)
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

	selected := cfg
	selected.Select = append(append([]string{}, cfg.Select...), includeRules...)
	selected.ExcludeRules = append(append([]string{}, cfg.ExcludeRules...), excludeRules...)
	selected.Selection.Pillars = append(append([]string{}, cfg.Selection.Pillars...), includePillars...)
	selected.Selection.ExcludePillars = append(append([]string{}, cfg.Selection.ExcludePillars...), excludePillars...)

	registry, err := rule.DefaultsConfigured(selected.RuleOptions())
	// A registry the selectors emptied or contradicted is a usage error, not a scan that quietly checks nothing.
	if err != nil {
		return rule.Registry{}, cfg, err
	}

	return registry, selected, nil
}

// validatedRuleIDs splits a comma-separated rule list and refuses a name no rule answers to.
//
// A mistyped rule id would otherwise silently run everything, which is the failure mode an execution selector exists to
// prevent: the user believes they narrowed the scan and they did not.
func validatedRuleIDs(input string, definitions []rule.Definition) ([]string, error) {
	values := splitCSV(input)
	known := map[string]struct{}{}

	for _, definition := range definitions {
		known[definition.ID] = struct{}{}
	}

	for _, id := range values {
		if _, recognised := known[id]; !recognised {
			return nil, fmt.Errorf("unknown rule %q", id)
		}
	}

	return values, nil
}

// validatedPillarNames splits a comma-separated pillar list and refuses a name outside the ratified vocabulary.
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
