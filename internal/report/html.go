// Package report renders gruff-go analysis results into output formats.
//
// The HTML renderer emits a self-contained report so CI artifacts can be opened without external assets.
// Styles and the optional filter script are inlined into the page rather than linked.
package report

import (
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/blundergoat/gruff-go/internal/analysis"
	"github.com/blundergoat/gruff-go/internal/finding"
	"github.com/blundergoat/gruff-go/internal/scoring"
)

// HTMLOptions controls optional behaviour of the HTML reporter.
//
// The zero value gives plain text locations with no editor links and no filter UI.
// WriteHTML treats an empty EditorLink as none, so callers set only the fields they need.
type HTMLOptions struct {
	// EditorLink selects the href scheme used for file:line links.
	// Valid values: "none" (default), "vscode", "phpstorm"; any other value renders plain text, as none does.
	EditorLink string
	// ProjectRoot is the absolute project root joined to relative report paths in editor links.
	// When empty, the reporter uses the report's recorded WorkingDirectory; if that is also empty, relative file paths stay relative.
	ProjectRoot string
	// Interactive toggles the inline filter UI and the supporting script
	// inside the rendered report.
	Interactive bool
}

// Known values for HTMLOptions.EditorLink controlling the href scheme used for file location links.
//
// vscode gives vscode://file links and phpstorm gives phpstorm://open links; none, empty, or any other value gives plain text locations.
const (
	editorLinkNone     = "none"
	editorLinkVSCode   = "vscode"
	editorLinkPhpStorm = "phpstorm"
)

// WriteHTML renders the analysis report as a self-contained HTML document.
//
// The whole document goes to writer in one write. opts chooses the editor-link scheme, with empty meaning none,
// the root used to resolve relative paths in those links, and whether the interactive filter UI is embedded.
// It returns the error from writing to writer, or nil when the write succeeds.
func WriteHTML(writer io.Writer, report analysis.Report, opts HTMLOptions) error {
	if opts.EditorLink == "" {
		opts.EditorLink = editorLinkNone
	}
	renderer := htmlRenderer{report: report, opts: opts}
	_, err := io.WriteString(writer, renderer.render())
	return err
}

// htmlRenderer carries the report and options needed to render the HTML document.
type htmlRenderer struct {
	report analysis.Report
	opts   HTMLOptions
}

// render returns the full HTML document as a string, never empty.
// Diagnostics styles are inlined only when the run recorded diagnostics, and the filter styles and script only when Interactive is set.
func (r htmlRenderer) render() string {
	var builder strings.Builder
	builder.WriteString(`<!DOCTYPE html>` + "\n")
	builder.WriteString(`<html lang="en-NZ">` + "\n")
	builder.WriteString(`<head>` + "\n")
	builder.WriteString(`<meta charset="UTF-8">` + "\n")
	builder.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1.0">` + "\n")
	fmt.Fprintf(&builder, "<title>%s</title>\n", esc(fmt.Sprintf("gruff-go inspection report - %s", gradeOrNA(r.report.Score.Grade))))
	builder.WriteString(`<style>`)
	builder.WriteString(reportCSS)
	if len(r.report.Diagnostics) > 0 {
		builder.WriteString(reportDiagnosticsCSS)
	}
	if r.opts.Interactive {
		builder.WriteString(reportInteractiveCSS)
	}
	builder.WriteString(`</style>` + "\n")
	builder.WriteString(`</head>` + "\n")
	builder.WriteString(`<body>` + "\n")
	builder.WriteString(`<div class="paper">`)
	builder.WriteString(`<span class="corner-tr"></span><span class="corner-bl"></span>`)
	builder.WriteString(r.masthead())
	builder.WriteString(r.diagnostics())
	builder.WriteString(r.verdict())
	builder.WriteString(r.pillars())
	builder.WriteString(r.offenders())
	builder.WriteString(r.distribution())
	builder.WriteString(r.findings())
	builder.WriteString(r.footer())
	builder.WriteString(`</div>` + "\n")
	if r.opts.Interactive {
		builder.WriteString(`<script type="module">`)
		builder.WriteString(reportInteractiveJS)
		builder.WriteString(`</script>` + "\n")
	}
	builder.WriteString(`</body>` + "\n")
	builder.WriteString(`</html>` + "\n")
	return builder.String()
}

// masthead renders the report header with brand wordmark and run metadata.
// It returns the header element markup holding the input paths, diff scope, output format, fail-on threshold, and tool version; it is never empty.
func (r htmlRenderer) masthead() string {
	var builder strings.Builder
	builder.WriteString(`<header class="masthead">`)
	builder.WriteString(`<div class="brand">`)
	builder.WriteString(`<div class="wordmark">gruff</div>`)
	builder.WriteString(`<div class="tagline">go code quality &middot; inspection report</div>`)
	builder.WriteString(`</div>`)
	builder.WriteString(`<div class="meta">`)
	builder.WriteString(metaRow("paths", strings.Join(displayInputs(r.report.Run.Inputs), ", ")))
	builder.WriteString(metaRow("scope", scopeLabel(r.report.Diff)))
	builder.WriteString(metaRow("format", r.report.Run.Format))
	builder.WriteString(metaRow("fail", r.report.Run.FailOn))
	fmt.Fprintf(&builder, `<div class="inspection-id">%s</div>`, esc("gruff "+r.report.Tool.Version))
	builder.WriteString(`</div>`)
	builder.WriteString(`</header>`)
	return builder.String()
}

// diagnostics renders the diagnostics section, or an empty string when none are present.
// Otherwise it returns a section listing each diagnostic's type label and message, plus its file and line when those are recorded.
func (r htmlRenderer) diagnostics() string {
	if len(r.report.Diagnostics) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(`<section class="diagnostics">`)
	builder.WriteString(`<h2 class="section-head">diagnostics <span class="aside">run messages</span></h2>`)
	builder.WriteString(`<div class="diagnostic-list">`)
	for _, diagnostic := range r.report.Diagnostics {
		builder.WriteString(`<div class="diagnostic">`)
		fmt.Fprintf(&builder, `<span class="diagnostic-type">%s</span>`, esc(diagnosticLabel(diagnostic)))
		fmt.Fprintf(&builder, `<span class="diagnostic-message">%s</span>`, esc(diagnostic.Message))
		if diagnostic.File != "" {
			location := diagnostic.File
			if diagnostic.Location != nil && diagnostic.Location.Line > 0 {
				location = fmt.Sprintf("%s:%d", diagnostic.File, diagnostic.Location.Line)
			}
			fmt.Fprintf(&builder, `<span class="diagnostic-location">%s</span>`, esc(location))
		}
		builder.WriteString(`</div>`)
	}
	builder.WriteString(`</div></section>`)
	return builder.String()
}

// verdict renders the headline grade stamp and severity counts.
//
// It returns the verdict section markup; the stamp shows the composite score to two decimals, or "not evaluated" when the composite is nil.
// The coverage caveat paragraph appears only when the report carries one, and the counts cover total, error, warning, and advisory findings.
func (r htmlRenderer) verdict() string {
	gradeLetter := gradeOrNA(r.report.Score.Grade)
	// A run that evaluated nothing shows no number in the stamp, so an empty scan cannot read as perfect.
	scoreText := "not evaluated"
	if r.report.Score.Composite != nil {
		scoreText = fmt.Sprintf("%.2f / 100", *r.report.Score.Composite)
	}
	tier := tierClass(gradeLetter)

	counts := severityCounts(r.report)

	var builder strings.Builder
	builder.WriteString(`<section class="verdict">`)
	builder.WriteString(`<div class="grade-stamp ` + tier + `">`)
	fmt.Fprintf(&builder, `<div class="grade-letter">%s</div>`, esc(gradeLetter))
	fmt.Fprintf(&builder, `<div class="grade-score">%s</div>`, esc(scoreText))
	builder.WriteString(`</div>`)
	builder.WriteString(`<div class="verdict-body">`)
	fmt.Fprintf(&builder, `<div class="verdict-headline">Inspection complete.<br><em>%s</em></div>`, esc(r.verdictSubtitle(counts)))
	if r.report.Score.Coverage.Caveat != "" {
		fmt.Fprintf(&builder, `<p class="score-caveat">%s</p>`, esc(r.report.Score.Coverage.Caveat))
	}
	builder.WriteString(`<div class="verdict-stats">`)
	builder.WriteString(stat(fmt.Sprintf("%d", counts.total), "findings", ""))
	builder.WriteString(stat(fmt.Sprintf("%d", counts.error), "error", "fail"))
	builder.WriteString(stat(fmt.Sprintf("%d", counts.warning), "warning", "warn"))
	builder.WriteString(stat(fmt.Sprintf("%d", counts.advisory), "advisory", "note"))
	builder.WriteString(`</div>`)
	builder.WriteString(`</div>`)
	builder.WriteString(`</section>`)
	return builder.String()
}

// pillars renders the canonical Pillars table.
//
// Rows mirror the text summary shape produced by BuildPillarSummaryRows.
// Every applicable pillar shows grade, score to two decimals, findings, and per-severity counts, sorted by findings descending then pillar name.
//
// It returns the pillars section markup with one row per pillar in summaryPillarOrder, so a report with no findings still lists every pillar.
// Rows marked not applicable are included and render like any other row, with no applicability column.
func (r htmlRenderer) pillars() string {
	rows := BuildPillarSummaryRows(r.report)
	var builder strings.Builder
	builder.WriteString(`<section class="pillars">`)
	builder.WriteString(`<h2 class="section-head">pillars <span class="aside">weighted composite</span></h2>`)
	builder.WriteString(`<table class="pillar-list"><thead><tr>`)
	builder.WriteString(`<th scope="col">pillar</th>`)
	builder.WriteString(`<th scope="col" class="num">grade</th>`)
	builder.WriteString(`<th scope="col" class="num">score</th>`)
	builder.WriteString(`<th scope="col" class="num">findings</th>`)
	builder.WriteString(`<th scope="col" class="num">advisory</th>`)
	builder.WriteString(`<th scope="col" class="num">warning</th>`)
	builder.WriteString(`<th scope="col" class="num">error</th>`)
	builder.WriteString(`</tr></thead><tbody>`)
	if len(rows) == 0 {
		builder.WriteString(`<tr><td colspan="7">No pillars.</td></tr>`)
	}
	for _, row := range rows {
		builder.WriteString(r.pillarRow(row))
	}
	builder.WriteString(`</tbody></table></section>`)
	return builder.String()
}

// pillarRow renders a single row of the canonical pillars table.
// It returns one table row: pillar name, grade pill, score to two decimals, findings count, and the advisory, warning, and error counts.
func (r htmlRenderer) pillarRow(row PillarSummaryRow) string {
	tier := tierClass(row.Grade)
	var builder strings.Builder
	builder.WriteString(`<tr>`)
	fmt.Fprintf(&builder, `<td class="pillar-name">%s</td>`, esc(row.Pillar))
	fmt.Fprintf(&builder, `<td class="num"><span class="grade-pill %s">%s</span></td>`, esc(tier), esc(row.Grade))
	fmt.Fprintf(&builder, `<td class="num">%s</td>`, esc(fmt.Sprintf("%.2f", row.Score)))
	fmt.Fprintf(&builder, `<td class="num">%d</td>`, row.Findings)
	builder.WriteString(severityCountCell(row.Advisory, "note"))
	builder.WriteString(severityCountCell(row.Warning, "warn"))
	builder.WriteString(severityCountCell(row.Error, "fail"))
	builder.WriteString(`</tr>`)
	return builder.String()
}

// offenders renders the table of files sorted by penalty.
// It returns the section markup with one row per TopOffender entry in scoring's order, or one placeholder row when the list is empty.
func (r htmlRenderer) offenders() string {
	var builder strings.Builder
	builder.WriteString(`<section class="offenders">`)
	builder.WriteString(`<h2 class="section-head">top offenders <span class="aside">sorted by penalty</span></h2>`)
	builder.WriteString(`<table class="offender-list"><thead><tr>`)
	builder.WriteString(`<th scope="col">file</th>`)
	builder.WriteString(`<th scope="col" class="num">cyclo</th>`)
	builder.WriteString(`<th scope="col" class="num">findings</th>`)
	builder.WriteString(`<th scope="col" class="num">penalty</th>`)
	builder.WriteString(`<th scope="col" class="num">grade</th>`)
	builder.WriteString(`</tr></thead><tbody>`)
	offenders := r.report.Score.TopOffender
	if len(offenders) == 0 {
		builder.WriteString(`<tr><td colspan="5">No offenders.</td></tr>`)
	}
	for _, file := range offenders {
		builder.WriteString(r.offenderRow(file))
	}
	builder.WriteString(`</tbody></table></section>`)
	return builder.String()
}

// offenderRow renders a single row of the top-offenders table.
//
// file supplies the cells: its path via locationMarkup with no line, MaxCyclomatic or "n/a" when nil, Findings, Score to two decimals, and Grade.
// It returns the row markup as a string, which is never empty.
func (r htmlRenderer) offenderRow(file scoring.FileScore) string {
	tier := tierClass(file.Grade)
	var builder strings.Builder
	builder.WriteString(`<tr>`)
	fmt.Fprintf(&builder, `<td class="file-path">%s</td>`, r.locationMarkup(file.File, 0))
	fmt.Fprintf(&builder, `<td class="num">%s</td>`, esc(optionalInt(file.MaxCyclomatic)))
	fmt.Fprintf(&builder, `<td class="num">%d</td>`, file.Findings)
	fmt.Fprintf(&builder, `<td class="num">%.2f</td>`, file.Score)
	fmt.Fprintf(&builder, `<td class="num"><span class="grade-pill %s">%s</span></td>`, esc(tier), esc(file.Grade))
	builder.WriteString(`</tr>`)
	return builder.String()
}

// distribution renders the cyclomatic complexity histogram section.
//
// It returns the section markup with a summary line and one bar per fixed bin, 1-5 through 21+, where an absent bin counts as zero.
// Bar heights are percentages of the largest bin count, never below 4 percent.
func (r htmlRenderer) distribution() string {
	distribution := r.report.Score.ComplexityDistribution
	bins := []string{"1-5", "6-10", "11-15", "16-20", "21+"}
	maxValue := 1
	for _, bin := range bins {
		if value := distribution[bin]; value > maxValue {
			maxValue = value
		}
	}
	var builder strings.Builder
	builder.WriteString(`<section class="chart-section">`)
	builder.WriteString(`<h2 class="section-head">distribution <span class="aside">cyclomatic complexity</span></h2>`)
	fmt.Fprintf(&builder, `<p class="chart-summary">%s</p>`, esc(cyclomaticSummary(distribution, r.report.Score.ComplexityDistributionScope)))
	builder.WriteString(`<div class="chart-card">`)
	builder.WriteString(`<div class="title">cyclomatic complexity &middot; finding-only histogram</div>`)
	builder.WriteString(`<div class="histogram">`)
	for _, bin := range bins {
		count := distribution[bin]
		height := 4
		if maxValue > 0 {
			height = max(4, (count*100)/maxValue)
		}
		tier := histogramTier(bin)
		fmt.Fprintf(&builder, `<div class="bar%s" style="height:%d%%;"><span class="count">%d</span></div>`, tier, height, count)
	}
	builder.WriteString(`</div>`)
	builder.WriteString(`<div class="histogram-axis">`)
	for _, bin := range bins {
		fmt.Fprintf(&builder, `<span>%s</span>`, esc(bin))
	}
	builder.WriteString(`</div>`)
	builder.WriteString(`</div></section>`)
	return builder.String()
}

// findings renders the flagged-findings list, with optional filter UI when Interactive is set.
// It returns the section markup with one entry per report finding in report order, or a single placeholder when there are none.
func (r htmlRenderer) findings() string {
	findings := r.report.Findings
	var builder strings.Builder
	builder.WriteString(`<section class="findings">`)
	fmt.Fprintf(&builder, `<h2 class="section-head">flagged findings <span class="aside">%d shown</span></h2>`, len(findings))
	if r.opts.Interactive {
		builder.WriteString(r.findingFilters())
	}
	listAttribute := ""
	if r.opts.Interactive {
		listAttribute = " data-findings-list"
	}
	fmt.Fprintf(&builder, `<div class="findings-list"%s>`, listAttribute)
	if len(findings) == 0 {
		builder.WriteString(`<div class="empty">No findings.</div>`)
	}
	for _, item := range findings {
		builder.WriteString(r.findingRow(item))
	}
	builder.WriteString(`</div></section>`)
	return builder.String()
}

// findingRow renders a single finding entry with the data attributes used by the interactive filter.
//
// item supplies the severity, pillar, file, and rule ID for those attributes, plus a lowercased rule-and-message search value.
// It returns the entry markup; without a positive Location line, the location shows the file alone.
func (r htmlRenderer) findingRow(item finding.Finding) string {
	tier := severityTierClass(item.Severity)
	line := 0
	if item.Location != nil {
		line = item.Location.Line
	}
	searchValue := strings.ToLower(item.RuleID + " " + item.Message)
	var builder strings.Builder
	fmt.Fprintf(
		&builder,
		`<div class="finding" data-severity="%s" data-pillar="%s" data-file="%s" data-rule="%s" data-search="%s">`,
		esc(string(item.Severity)),
		esc(string(item.Pillar)),
		esc(item.File),
		esc(item.RuleID),
		esc(searchValue),
	)
	fmt.Fprintf(&builder, `<div class="severity %s">%s</div>`, esc(tier), esc(string(item.Severity)))
	builder.WriteString(`<div class="finding-body">`)
	fmt.Fprintf(&builder, `<h3 class="rule">%s</h3>`, esc(item.RuleID))
	fmt.Fprintf(&builder, `<div class="msg">%s</div>`, esc(item.Message))
	fmt.Fprintf(&builder, `<div class="loc"><code>%s</code></div>`, r.locationMarkup(item.File, line))
	builder.WriteString(`</div>`)
	fmt.Fprintf(&builder, `<div class="points"><b>%s</b></div>`, esc(string(item.Pillar)))
	builder.WriteString(`</div>`)
	return builder.String()
}

// footer renders the report footer with tool version and schema identifiers.
// It returns the footer markup; the string is never empty, even when the version or schema identifier is blank.
func (r htmlRenderer) footer() string {
	var builder strings.Builder
	builder.WriteString(`<footer class="footer">`)
	fmt.Fprintf(&builder, `<div class="left">gruff-go &middot; v%s</div>`, esc(r.report.Tool.Version))
	builder.WriteString(`<div class="center">strong opinions, opinionated defaults</div>`)
	fmt.Fprintf(&builder, `<div class="right">schema &middot; %s</div>`, esc(r.report.SchemaVersion))
	builder.WriteString(`</footer>`)
	return builder.String()
}

// locationMarkup renders a file:line link or a focusable span depending on the editor-link option.
//
// It returns an anchor to the editorHref URL, or a focusable span when that URL is empty.
// Both show file as the visible text and data-path, with :line appended when line is positive.
func (r htmlRenderer) locationMarkup(file string, line int) string {
	visible := file
	if line > 0 {
		visible = fmt.Sprintf("%s:%d", file, line)
	}
	href := r.editorHref(file, line)
	if href == "" {
		return fmt.Sprintf(
			`<span class="loc-link" tabindex="0" data-path="%s">%s</span>`,
			esc(visible),
			esc(visible),
		)
	}
	return fmt.Sprintf(
		`<a class="loc-link" href="%s" data-path="%s">%s</a>`,
		esc(href),
		esc(visible),
		esc(visible),
	)
}

// editorHref builds the editor-specific URL scheme for opening file:line in the user's editor.
//
// For vscode or phpstorm it returns that editor's URL for absolutePath of file, which stays relative when no root is set.
// The URL carries line only when line is positive; the result is an empty string when EditorLink is empty, none, or unknown.
func (r htmlRenderer) editorHref(file string, line int) string {
	if r.opts.EditorLink == "" || r.opts.EditorLink == editorLinkNone {
		return ""
	}
	absolutePath := r.absolutePath(file)
	switch r.opts.EditorLink {
	case editorLinkVSCode:
		encoded := encodePathSegments(absolutePath)
		if line > 0 {
			return fmt.Sprintf("vscode://file%s:%d", encoded, line)
		}
		return "vscode://file" + encoded
	case editorLinkPhpStorm:
		base := "phpstorm://open?file=" + url.QueryEscape(absolutePath)
		if line > 0 {
			return fmt.Sprintf("%s&line=%d", base, line)
		}
		return base
	default:
		return ""
	}
}

// absolutePath resolves a possibly-relative report path against the project root for editor links.
//
// It returns file unchanged when it is already absolute or when neither ProjectRoot nor the run's WorkingDirectory is set.
// Otherwise it joins ProjectRoot, or WorkingDirectory when ProjectRoot is empty, to file with one forward slash between them.
func (r htmlRenderer) absolutePath(file string) string {
	if filepath.IsAbs(file) {
		return file
	}
	root := r.opts.ProjectRoot
	if root == "" {
		root = r.report.Run.WorkingDirectory
	}
	if root == "" {
		return file
	}
	return strings.TrimRight(root, "/") + "/" + strings.TrimLeft(file, "/")
}
