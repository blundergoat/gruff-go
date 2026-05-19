// Package report renders gruff-go analysis results into output formats.
// This file collects shared helpers used by the HTML reporter.
package report

import (
	"fmt"
	"html"
	"net/url"
	"sort"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
)

// severityTotals aggregates finding counts by severity for headline summaries.
type severityTotals struct {
	total    int
	critical int
	high     int
	medium   int
	low      int
	info     int
}

// severityCounts tallies findings across the report by severity.
func severityCounts(report analysis.Report) severityTotals {
	counts := severityTotals{total: len(report.Findings)}
	for _, item := range report.Findings {
		switch item.Severity {
		case finding.SeverityCritical:
			counts.critical++
		case finding.SeverityHigh:
			counts.high++
		case finding.SeverityMedium:
			counts.medium++
		case finding.SeverityLow:
			counts.low++
		case finding.SeverityInfo:
			counts.info++
		}
	}
	return counts
}

// verdictSubtitle returns the human-readable subtitle shown beneath the grade stamp.
func (r htmlRenderer) verdictSubtitle(counts severityTotals) string {
	thresholdFindings := counts.critical + counts.high + counts.medium
	if thresholdFindings == 0 {
		return "No medium or higher severity findings flagged."
	}
	pillarSet := map[string]struct{}{}
	for _, item := range r.report.Findings {
		switch item.Severity {
		case finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium:
			pillarSet[string(item.Pillar)] = struct{}{}
		}
	}
	pillarCount := len(pillarSet)
	return fmt.Sprintf(
		"%d %s at medium or higher severity across %d %s.",
		thresholdFindings,
		pluralise(thresholdFindings, "finding", "findings"),
		pillarCount,
		pluralise(pillarCount, "pillar", "pillars"),
	)
}

// cyclomaticSummary formats a one-line caption describing the over-threshold complexity bins.
func cyclomaticSummary(distribution map[string]int, scope string) string {
	moderate := distribution["11-15"]
	high := distribution["16-20"]
	severe := distribution["21+"]
	total := moderate + high + severe
	scopeSuffix := ""
	if scope != "" {
		scopeSuffix = " in the finding-only distribution"
	}
	if total == 0 {
		return "0 methods exceed CC 10" + scopeSuffix + "; zero bins mean no over-threshold complexity findings were reported."
	}
	return fmt.Sprintf(
		"%d %s %s CC 10%s (%d in 11-15, %d in 16-20, %d at 21+).",
		total,
		pluralise(total, "method", "methods"),
		pluralise(total, "exceeds", "exceed"),
		scopeSuffix,
		moderate,
		high,
		severe,
	)
}

// histogramTier maps a complexity bin label to the CSS tier suffix used for the histogram bar.
func histogramTier(bin string) string {
	switch bin {
	case "11-15":
		return " warn"
	case "16-20", "21+":
		return " fail"
	default:
		return ""
	}
}

// severityTierClass maps a severity to the CSS class used to colour severity badges.
func severityTierClass(severity finding.Severity) string {
	switch severity {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "fail"
	case finding.SeverityMedium:
		return "warn"
	default:
		return "note"
	}
}

// tierClass derives the CSS tier class from a single-letter grade.
func tierClass(grade string) string {
	if grade == "" {
		return "n"
	}
	return strings.ToLower(string(grade[0]))
}

// metaRow renders a labelled metadata row in the masthead.
func metaRow(label, value string) string {
	return fmt.Sprintf(
		`<div><span class="label">%s</span><span class="val">%s</span></div>`,
		esc(label),
		esc(value),
	)
}

// stat renders a single statistic block with a number, label, and optional tier class.
func stat(number, label, class string) string {
	return fmt.Sprintf(
		`<div class="stat"><div class="num %s">%s</div><div class="lbl">%s</div></div>`,
		esc(class),
		esc(number),
		esc(label),
	)
}

// breakdownRow renders a key/value row inside a pillar breakdown block.
func breakdownRow(key, value string) string {
	return fmt.Sprintf(
		`<div class="row"><span class="key">%s</span><span class="val">%s</span></div>`,
		esc(key),
		esc(value),
	)
}

// optionalInt formats an optional integer, returning "n/a" when it is nil.
func optionalInt(value *int) string {
	if value == nil {
		return "n/a"
	}
	return fmt.Sprintf("%d", *value)
}

// pluralise returns singular or plural depending on the count.
func pluralise(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

// displayInputs returns a sorted copy of the scan inputs, defaulting to "." when empty.
func displayInputs(inputs []string) []string {
	if len(inputs) == 0 {
		return []string{"."}
	}
	sorted := append([]string(nil), inputs...)
	sort.Strings(sorted)
	return sorted
}

// scopeLabel returns the human-readable scan scope label for the masthead.
func scopeLabel(summary analysis.DiffSummary) string {
	if summary.Enabled {
		return fmt.Sprintf("diff · %d changed files", len(summary.ChangedFiles))
	}
	return "full project"
}

// encodePathSegments percent-encodes each segment of a slash-separated path.
func encodePathSegments(absolutePath string) string {
	segments := strings.Split(absolutePath, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

// esc HTML-escapes a value for safe inclusion in the rendered document.
func esc(value string) string {
	return html.EscapeString(value)
}
