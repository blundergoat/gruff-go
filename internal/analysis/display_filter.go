// Package analysis orchestrates discovery, parsing, rule execution, and report assembly.
// It also applies display-only filters that hide findings without affecting exit codes.
package analysis

import (
	"slices"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// DisplayFilter selects which findings are rendered without changing scoring.
type DisplayFilter struct {
	// IncludeRules limits rendering to findings whose RuleID is in this allow list; empty means no allow list.
	IncludeRules []string
	// ExcludeRules hides findings whose RuleID is in this deny list.
	ExcludeRules []string
	// IncludePillars limits rendering to findings whose Pillar is in this allow list; empty means no allow list.
	IncludePillars []finding.Pillar
	// ExcludePillars hides findings whose Pillar is in this deny list.
	ExcludePillars []finding.Pillar
}

// Empty reports whether the filter has no include or exclude selections.
func (filter DisplayFilter) Empty() bool {
	return len(filter.IncludeRules) == 0 &&
		len(filter.ExcludeRules) == 0 &&
		len(filter.IncludePillars) == 0 &&
		len(filter.ExcludePillars) == 0
}

// ApplyDisplayFilter hides findings that do not match the supplied filter.
func ApplyDisplayFilter(report *Report, filter DisplayFilter) {
	if filter.Empty() {
		report.DisplayFilter = DisplayFilterSummary{
			IncludeRules:   []string{},
			ExcludeRules:   []string{},
			IncludePillars: []string{},
			ExcludePillars: []string{},
		}
		return
	}
	kept := report.Findings[:0]
	hidden := 0
	for _, item := range report.Findings {
		if displayFilterKeeps(item, filter) {
			kept = append(kept, item)
			continue
		}
		hidden++
	}
	report.Findings = kept
	report.DisplayFilter = DisplayFilterSummary{
		Applied:        true,
		IncludeRules:   sortedStrings(filter.IncludeRules),
		ExcludeRules:   sortedStrings(filter.ExcludeRules),
		IncludePillars: sortedPillars(filter.IncludePillars),
		ExcludePillars: sortedPillars(filter.ExcludePillars),
		HiddenFindings: hidden,
		Caveat:         "display filters do not change summary counts, score, or exit code",
	}
}

// displayFilterKeeps reports whether the finding passes the filter's selections.
func displayFilterKeeps(item finding.Finding, filter DisplayFilter) bool {
	if len(filter.IncludeRules) > 0 && !slices.Contains(filter.IncludeRules, item.RuleID) {
		return false
	}
	if slices.Contains(filter.ExcludeRules, item.RuleID) {
		return false
	}
	if len(filter.IncludePillars) > 0 && !slices.Contains(filter.IncludePillars, item.Pillar) {
		return false
	}
	if slices.Contains(filter.ExcludePillars, item.Pillar) {
		return false
	}
	return true
}

// sortedStrings returns a copy of values sorted lexicographically.
func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	slices.Sort(out)
	return out
}

// sortedPillars converts pillar values to sorted string identifiers.
func sortedPillars(values []finding.Pillar) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	slices.Sort(out)
	return out
}
