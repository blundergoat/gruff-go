// Package report renders gruff-go analysis results into output formats.
//
// This file generates the interactive findings filter UI inlined into the HTML report.
// Readers of the HTML report use it to narrow the findings by severity, pillar, path or search text, and to group them by file or rule.
package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// findingFilters renders the severity, pillar, path, and search controls above the findings list.
//
// It returns the whole filter form as HTML, never an empty string, with severity options ordered error, warning, advisory and pillars sorted.
// Pillar options cover only the distinct pillars present in the report's findings, so that list is empty when there are no findings.
func (r htmlRenderer) findingFilters() string {
	pillars := map[string]struct{}{}
	for _, item := range r.report.Findings {
		pillars[string(item.Pillar)] = struct{}{}
	}
	pillarKeys := make([]string, 0, len(pillars))
	for key := range pillars {
		pillarKeys = append(pillarKeys, key)
	}
	slices.Sort(pillarKeys)

	// Severity options are fixed, so all three tiers appear even when the report has no finding at that tier.
	severityOrder := []string{
		string(finding.SeverityError),
		string(finding.SeverityWarning),
		string(finding.SeverityAdvisory),
	}

	var builder strings.Builder
	builder.WriteString(`<form class="finding-filters" data-finding-filters aria-label="Filter flagged findings">`)
	builder.WriteString(`<div class="filter-grid">`)
	builder.WriteString(`<label>Severity<select name="severity" multiple size="5">`)
	for _, value := range severityOrder {
		fmt.Fprintf(&builder, `<option value="%s">%s</option>`, esc(value), esc(value))
	}
	builder.WriteString(`</select></label>`)
	// The pillar list box shows 2 to 6 rows; with more pillars than that, the box scrolls.
	pillarRows := max(2, min(6, len(pillarKeys)))
	fmt.Fprintf(&builder, `<label>Pillar<select name="pillar" multiple size="%d">`, pillarRows)
	for _, value := range pillarKeys {
		fmt.Fprintf(&builder, `<option value="%s">%s</option>`, esc(value), esc(value))
	}
	builder.WriteString(`</select></label>`)
	builder.WriteString(`<label>Path<input name="path" type="search" autocomplete="off"></label>`)
	builder.WriteString(`<label>Search<input name="q" type="search" autocomplete="off"></label>`)
	builder.WriteString(`</div>`)
	// Group-by radios offer none, file and rule with none checked; on load the script applies any group named in the URL fragment.
	builder.WriteString(`<fieldset class="filter-group"><legend>Group by</legend>`)
	builder.WriteString(`<label class="radio"><input type="radio" name="group" value="none" checked> none</label>`)
	builder.WriteString(`<label class="radio"><input type="radio" name="group" value="file"> file</label>`)
	builder.WriteString(`<label class="radio"><input type="radio" name="group" value="rule"> rule</label>`)
	builder.WriteString(`</fieldset>`)
	// Clear all and the live count end the form; the generated count includes every finding.
	// On load the script restores filters from the URL fragment and recounts, so a deep link can open already filtered.
	builder.WriteString(`<div class="filter-actions"><button type="button" data-clear-filters>Clear all</button>`)
	fmt.Fprintf(&builder, `<output class="filter-count" data-filter-count aria-live="polite">%d of %d findings shown.</output></div>`, len(r.report.Findings), len(r.report.Findings))
	builder.WriteString(`</form>`)
	return builder.String()
}
