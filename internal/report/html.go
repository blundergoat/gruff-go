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
type HTMLOptions struct {
	// EditorLink selects the href scheme used for file:line links.
	// Valid values: "none" (default), "vscode", "phpstorm".
	EditorLink string
	// ProjectRoot is the absolute project root used to build editor links.
	// When empty, the reporter falls back to the working directory at render time.
	ProjectRoot string
	// Interactive toggles the inline filter UI and the supporting script
	// inside the rendered report.
	Interactive bool
}

const (
	editorLinkNone     = "none"
	editorLinkVSCode   = "vscode"
	editorLinkPhpStorm = "phpstorm"
)

// WriteHTML renders the analysis report as a self-contained HTML document.
func WriteHTML(writer io.Writer, report analysis.Report, opts HTMLOptions) error {
	if opts.EditorLink == "" {
		opts.EditorLink = editorLinkNone
	}
	renderer := htmlRenderer{report: report, opts: opts}
	_, err := io.WriteString(writer, renderer.render())
	return err
}

type htmlRenderer struct {
	report analysis.Report
	opts   HTMLOptions
}

func (r htmlRenderer) render() string {
	var builder strings.Builder
	builder.WriteString(`<!DOCTYPE html>` + "\n")
	builder.WriteString(`<html lang="en-NZ">` + "\n")
	builder.WriteString(`<head>` + "\n")
	builder.WriteString(`<meta charset="UTF-8">` + "\n")
	builder.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1.0">` + "\n")
	fmt.Fprintf(&builder, "<title>%s</title>\n", esc(fmt.Sprintf("gruff-go inspection report - %s", r.report.Score.Grade)))
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
		fmt.Fprintf(&builder, `<span class="diagnostic-type">%s</span>`, esc(diagnostic.Stage))
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

func (r htmlRenderer) verdict() string {
	composite := r.report.Score.Composite
	gradeLetter := r.report.Score.Grade
	if gradeLetter == "" {
		gradeLetter = "n/a"
	}
	scoreText := fmt.Sprintf("%d / 100", composite)
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
	builder.WriteString(`<div class="verdict-stats">`)
	builder.WriteString(stat(fmt.Sprintf("%d", counts.total), "findings", ""))
	builder.WriteString(stat(fmt.Sprintf("%d", counts.critical), "critical", "fail"))
	builder.WriteString(stat(fmt.Sprintf("%d", counts.high), "high", "fail"))
	builder.WriteString(stat(fmt.Sprintf("%d", counts.medium), "medium", "warn"))
	builder.WriteString(`</div>`)
	builder.WriteString(`</div>`)
	builder.WriteString(`</section>`)
	return builder.String()
}

func (r htmlRenderer) pillars() string {
	var builder strings.Builder
	builder.WriteString(`<section class="pillars">`)
	builder.WriteString(`<h2 class="section-head">pillar grades <span class="aside">weighted composite</span></h2>`)
	builder.WriteString(`<div class="pillar-grid">`)
	details := r.report.Score.PillarDetails
	if len(details) == 0 {
		builder.WriteString(`<div class="pillar pillar-empty">`)
		builder.WriteString(`<div class="name">no pillar findings</div>`)
		builder.WriteString(`<div class="grade a">A</div>`)
		builder.WriteString(`<div class="breakdown"><div class="row"><span class="key">score</span><span class="val">100.00</span></div></div>`)
		builder.WriteString(`</div>`)
	}
	for _, detail := range details {
		builder.WriteString(r.pillarCard(detail))
	}
	builder.WriteString(`</div></section>`)
	return builder.String()
}

func (r htmlRenderer) pillarCard(detail scoring.PillarDetail) string {
	tier := tierClass(detail.Grade)
	var builder strings.Builder
	builder.WriteString(`<div class="pillar">`)
	fmt.Fprintf(&builder, `<div class="name">%s</div>`, esc(detail.Pillar))
	fmt.Fprintf(&builder, `<div class="grade %s">%s</div>`, esc(tier), esc(detail.Grade))
	builder.WriteString(`<div class="breakdown">`)
	builder.WriteString(breakdownRow("score", fmt.Sprintf("%d", detail.Score)))
	builder.WriteString(breakdownRow("findings", fmt.Sprintf("%d", detail.Findings)))
	builder.WriteString(breakdownRow("critical", fmt.Sprintf("%d", detail.Critical)))
	builder.WriteString(breakdownRow("high", fmt.Sprintf("%d", detail.High)))
	builder.WriteString(breakdownRow("medium", fmt.Sprintf("%d", detail.Medium)))
	builder.WriteString(breakdownRow("low", fmt.Sprintf("%d", detail.Low)))
	builder.WriteString(breakdownRow("info", fmt.Sprintf("%d", detail.Info)))
	builder.WriteString(`</div></div>`)
	return builder.String()
}

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

func (r htmlRenderer) offenderRow(file scoring.FileScore) string {
	tier := tierClass(file.Grade)
	var builder strings.Builder
	builder.WriteString(`<tr>`)
	fmt.Fprintf(&builder, `<td class="file-path">%s</td>`, r.locationMarkup(file.File, 0))
	fmt.Fprintf(&builder, `<td class="num">%s</td>`, esc(optionalInt(file.MaxCyclomatic)))
	fmt.Fprintf(&builder, `<td class="num">%d</td>`, file.Findings)
	fmt.Fprintf(&builder, `<td class="num">%d</td>`, file.Penalty)
	fmt.Fprintf(&builder, `<td class="num"><span class="grade-pill %s">%s</span></td>`, esc(tier), esc(file.Grade))
	builder.WriteString(`</tr>`)
	return builder.String()
}

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
	fmt.Fprintf(&builder, `<p class="chart-summary">%s</p>`, esc(cyclomaticSummary(distribution)))
	builder.WriteString(`<div class="chart-card">`)
	builder.WriteString(`<div class="title">cyclomatic complexity &middot; flagged methods</div>`)
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

func (r htmlRenderer) footer() string {
	var builder strings.Builder
	builder.WriteString(`<footer class="footer">`)
	fmt.Fprintf(&builder, `<div class="left">gruff-go &middot; v%s</div>`, esc(r.report.Tool.Version))
	builder.WriteString(`<div class="center">strong opinions, opinionated defaults</div>`)
	fmt.Fprintf(&builder, `<div class="right">schema &middot; %s</div>`, esc(r.report.SchemaVersion))
	builder.WriteString(`</footer>`)
	return builder.String()
}

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
