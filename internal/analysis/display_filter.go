// Package analysis orchestrates discovery, parsing, rule execution, and report assembly.
//
// It also applies display-only filters that hide findings without affecting exit codes.
// The report's display filter summary says how many findings were hidden and that summary counts and score are unchanged.
package analysis

import (
	"slices"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// DisplayFilter selects which findings are rendered without changing scoring.
//
// Rule and pillar lists act as allow and deny lists, and MinimumSeverity hides findings below a severity floor.
// The zero value is Empty and keeps every finding; summary counts, score and exit code ignore the filter either way.
type DisplayFilter struct {
	// IncludeRules limits rendering to findings whose RuleID is in this allow list; empty means no allow list.
	IncludeRules []string
	// ExcludeRules hides findings whose RuleID is in this deny list.
	ExcludeRules []string
	// IncludePillars limits rendering to findings whose Pillar is in this allow list; empty means no allow list.
	IncludePillars []finding.Pillar
	// ExcludePillars hides findings whose Pillar is in this deny list.
	ExcludePillars []finding.Pillar
	// MinimumSeverity hides findings below this severity. Empty means the report shows every severity it found.
	MinimumSeverity finding.Severity
}

// Empty reports whether no rule, pillar or minimum-severity filter is set.
// A true result makes ApplyDisplayFilter keep every finding and record the display filter as not applied.
func (filter DisplayFilter) Empty() bool {
	return len(filter.IncludeRules) == 0 &&
		len(filter.ExcludeRules) == 0 &&
		len(filter.IncludePillars) == 0 &&
		len(filter.ExcludePillars) == 0 &&
		filter.MinimumSeverity == ""
}

// ApplyDisplayFilter hides findings that do not match the supplied filter.
//
// report is changed in place: Findings keeps only matching findings, and DisplayFilter records the sorted rule and pillar lists and hidden count.
// filter holds the rule, pillar and severity selections; an empty filter keeps every finding and records an unapplied summary with empty lists.
//
// A non-empty filter also records a caveat that summary counts, score and exit code are unchanged by the filter.
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

// displayFilterKeeps reports whether the finding passes the filter's selections; false hides it from the report.
//
// item passes when its RuleID and Pillar each appear in the matching non-empty allow list of filter and in neither deny list.
// When filter.MinimumSeverity is set, an item whose severity ranks below it by displaySeverityRank is also hidden.
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
	// The display floor hides quieter findings from the report; the exit code was already decided without it.
	if filter.MinimumSeverity != "" && displaySeverityRank(item.Severity) < displaySeverityRank(filter.MinimumSeverity) {
		return false
	}
	return true
}

// displaySeverityRank orders the three severities so a floor can be compared against a finding.
//
// An unrecognised severity ranks highest, so a finding this port cannot rank is shown rather than quietly hidden.
// It returns 0 for SeverityAdvisory, 1 for SeverityWarning, and 2 for any other value, including the empty severity.
func displaySeverityRank(severity finding.Severity) int {
	switch severity {
	case finding.SeverityAdvisory:
		return 0
	case finding.SeverityWarning:
		return 1
	default:
		return 2
	}
}

// sortedStrings returns a copy of values sorted lexicographically.
// An empty values gives nil, unlike sortedPillars, so an applied filter with no rule selections records nil rule lists.
func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	slices.Sort(out)
	return out
}

// sortedPillars converts pillar values to sorted string identifiers.
// It returns a new slice of the pillar names in ascending order, empty but non-nil when values is empty; values itself is not modified.
func sortedPillars(values []finding.Pillar) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	slices.Sort(out)
	return out
}
