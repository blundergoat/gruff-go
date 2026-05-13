package analysis

import (
	"slices"

	"github.com/blundergoat/gruff-go/internal/finding"
)

type DisplayFilter struct {
	IncludeRules   []string
	ExcludeRules   []string
	IncludePillars []finding.Pillar
	ExcludePillars []finding.Pillar
}

func (filter DisplayFilter) Empty() bool {
	return len(filter.IncludeRules) == 0 &&
		len(filter.ExcludeRules) == 0 &&
		len(filter.IncludePillars) == 0 &&
		len(filter.ExcludePillars) == 0
}

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

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	slices.Sort(out)
	return out
}

func sortedPillars(values []finding.Pillar) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	slices.Sort(out)
	return out
}
