// Package report renders gruff-go analysis results into output formats.
//
// Shared HTML helpers centralize escaping and formatting so renderer methods stay structural.
// They build the headline severity counts, verdict subtitle, complexity caption, table cells and masthead rows of the HTML report.
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
	error    int
	warning  int
	advisory int
}

// severityCounts tallies findings across the report by severity for the headline summaries.
//
// Returns a severityTotals whose total is len(report.Findings) and whose error, warning and advisory fields count findings of that severity.
// A finding of any other severity adds to total only, and every count is zero when report has no findings.
func severityCounts(report analysis.Report) severityTotals {
	counts := severityTotals{total: len(report.Findings)}
	for _, item := range report.Findings {
		switch item.Severity {
		case finding.SeverityError:
			counts.error++
		case finding.SeverityWarning:
			counts.warning++
		case finding.SeverityAdvisory:
			counts.advisory++
		}
	}
	return counts
}

// verdictSubtitle returns the human-readable verdict subtitle that sums up warning-or-higher findings in the HTML report.
//
// counts supplies the error and warning totals; when their sum is zero the subtitle says no warning or higher severity findings were flagged.
// Otherwise it states that sum and the number of distinct pillars holding an error or warning finding in r.report.
func (r htmlRenderer) verdictSubtitle(counts severityTotals) string {
	thresholdFindings := counts.error + counts.warning
	// A report holding only advisory findings lands here too, so the subtitle mentions none of them.
	if thresholdFindings == 0 {
		return "No warning or higher severity findings flagged."
	}
	pillarSet := map[string]struct{}{}
	for _, item := range r.report.Findings {
		switch item.Severity {
		case finding.SeverityError, finding.SeverityWarning:
			pillarSet[string(item.Pillar)] = struct{}{}
		}
	}
	pillarCount := len(pillarSet)
	return fmt.Sprintf(
		"%d %s at warning or higher severity across %d %s.",
		thresholdFindings,
		pluralise(thresholdFindings, "finding", "findings"),
		pillarCount,
		pluralise(pillarCount, "pillar", "pillars"),
	)
}

// cyclomaticSummary formats a one-line caption describing the over-threshold complexity bins.
//
// distribution maps complexity bin labels to method counts, and only the 11-15, 16-20 and 21+ bins are read.
// A non-empty scope appends a note that the counts come from the finding-only distribution.
// Returns a sentence with the over-threshold method total and each bin's count, or a zero-methods sentence when the three bins total zero.
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
// Returns the suffix " warn" for the 11-15 bin, " fail" for the 16-20 and 21+ bins, and an empty string for any other bin label.
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
// Returns the class "fail" for SeverityError, "warn" for SeverityWarning, and "note" for SeverityAdvisory or any other severity.
func severityTierClass(severity finding.Severity) string {
	switch severity {
	case finding.SeverityError:
		return "fail"
	case finding.SeverityWarning:
		return "warn"
	default:
		return "note"
	}
}

// severityCountCell renders a numeric per-severity table cell.
//
// Zero and negative counts stay neutral so a clean pillar reads as quiet; positive counts take the supplied tier class for colour emphasis.
//
// count is the number printed in the cell, and tier is the HTML-escaped class added beside num only when count is above zero.
// Returns the td cell markup; a zero or negative count renders with the num class alone.
func severityCountCell(count int, tier string) string {
	if count <= 0 {
		return fmt.Sprintf(`<td class="num">%d</td>`, count)
	}
	return fmt.Sprintf(`<td class="num %s">%d</td>`, esc(tier), count)
}

// tierClass derives the CSS tier class from a single-letter grade.
// Returns the lower-cased first byte of grade, or "n" when grade is empty.
func tierClass(grade string) string {
	if grade == "" {
		return "n"
	}
	return strings.ToLower(string(grade[0]))
}

// metaRow renders a labelled metadata row in the masthead.
// Returns a div markup string holding a label span with label and a val span with value, both HTML-escaped.
func metaRow(label, value string) string {
	return fmt.Sprintf(
		`<div><span class="label">%s</span><span class="val">%s</span></div>`,
		esc(label),
		esc(value),
	)
}

// stat renders a single statistic block with a number, label, and optional tier class.
//
// Returns a stat div markup string with number, label and class all HTML-escaped, and class placed beside num on the number div.
// An empty class leaves the number div with the num class alone.
func stat(number, label, class string) string {
	return fmt.Sprintf(
		`<div class="stat"><div class="num %s">%s</div><div class="lbl">%s</div></div>`,
		esc(class),
		esc(number),
		esc(label),
	)
}

// optionalInt formats an optional integer, returning "n/a" when it is nil.
//
// value is the optional integer to format; a non-nil value renders as its base-10 digits.
// Returns "n/a" when value is nil, so a missing number never reads as 0.
func optionalInt(value *int) string {
	if value == nil {
		return "n/a"
	}
	return fmt.Sprintf("%d", *value)
}

// pluralise returns singular or plural depending on the count.
// Returns singular only when count is exactly 1, so zero and negative counts read as plural, as in 0 findings.
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
// summary is the diff summary; when Enabled is set the label names diff mode and the count of ChangedFiles, otherwise it is "full project".
func scopeLabel(summary analysis.DiffSummary) string {
	if summary.Enabled {
		return fmt.Sprintf("diff · %d changed files", len(summary.ChangedFiles))
	}
	return "full project"
}

// encodePathSegments percent-encodes each segment of a slash-separated path.
//
// absolutePath is split on forward slashes and each segment is escaped with url.PathEscape, so the separators survive.
// Returns the rejoined path, keeping any leading slash; an empty absolutePath gives an empty string.
func encodePathSegments(absolutePath string) string {
	segments := strings.Split(absolutePath, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

// esc HTML-escapes a value for safe inclusion in the rendered document.
// Returns value with html.EscapeString applied, so less-than, greater-than, ampersand, and single and double quotes become entities.
func esc(value string) string {
	return html.EscapeString(value)
}
