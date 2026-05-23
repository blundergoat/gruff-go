// Package report renders gruff-go analysis results into output formats.
// This file generates the interactive findings filter UI inlined into the HTML report.
package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/blundergoat/gruff-go/internal/finding"
)

// findingFilters renders the severity, pillar, path, and search controls above the findings list.
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

	severityOrder := []string{
		string(finding.SeverityCritical),
		string(finding.SeverityHigh),
		string(finding.SeverityMedium),
		string(finding.SeverityLow),
		string(finding.SeverityInfo),
	}

	var builder strings.Builder
	builder.WriteString(`<form class="finding-filters" data-finding-filters aria-label="Filter flagged findings">`)
	builder.WriteString(`<div class="filter-grid">`)
	builder.WriteString(`<label>Severity<select name="severity" multiple size="5">`)
	for _, value := range severityOrder {
		fmt.Fprintf(&builder, `<option value="%s">%s</option>`, esc(value), esc(value))
	}
	builder.WriteString(`</select></label>`)
	pillarSize := max(2, min(6, len(pillarKeys)))
	fmt.Fprintf(&builder, `<label>Pillar<select name="pillar" multiple size="%d">`, pillarSize)
	for _, value := range pillarKeys {
		fmt.Fprintf(&builder, `<option value="%s">%s</option>`, esc(value), esc(value))
	}
	builder.WriteString(`</select></label>`)
	builder.WriteString(`<label>Path<input name="path" type="search" autocomplete="off"></label>`)
	builder.WriteString(`<label>Search<input name="q" type="search" autocomplete="off"></label>`)
	builder.WriteString(`</div>`)
	builder.WriteString(`<fieldset class="filter-group"><legend>Group by</legend>`)
	builder.WriteString(`<label class="radio"><input type="radio" name="group" value="none" checked> none</label>`)
	builder.WriteString(`<label class="radio"><input type="radio" name="group" value="file"> file</label>`)
	builder.WriteString(`<label class="radio"><input type="radio" name="group" value="rule"> rule</label>`)
	builder.WriteString(`</fieldset>`)
	builder.WriteString(`<div class="filter-actions"><button type="button" data-clear-filters>Clear all</button>`)
	fmt.Fprintf(&builder, `<output class="filter-count" data-filter-count aria-live="polite">%d of %d findings shown.</output></div>`, len(r.report.Findings), len(r.report.Findings))
	builder.WriteString(`</form>`)
	return builder.String()
}
