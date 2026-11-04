// Package report renders gruff-go analysis results into output formats.
//
// It supports text, JSON, HTML, SARIF, GitHub annotations, and the dashboard shell.
// This file builds the dashboard shell page and its error page.
// It also adds the script that reports a finished scan from the report iframe back to the shell.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// DashboardState describes the form state rendered into the dashboard shell.
//
// Each field prefills one control in the dashboard controls panel; an empty text field renders as an empty input.
// An empty ScanScope or FailOn selects no option, so the browser shows the first one, full or advisory.
// DashboardScanQuery turns the same state into the /scan URL that dashboardHTML stores on the report iframe.
type DashboardState struct {
	// Project is the currently selected project root path.
	Project string
	// Paths is the comma-separated list of scan targets; relative paths resolve against Project, and absolute paths can lie outside it.
	Paths string
	// ScanScope selects "full" or "diff" scan mode for the next run.
	ScanScope string
	// FailOn is the failure threshold for the scan exit code: advisory, warning or error, or none, which never fails on findings.
	FailOn string
	// Config is the configured .gruff-go.yaml path.
	Config string
	// Baseline is the configured baseline file path.
	Baseline string
	// SkipBaseline is "1" when baseline application is disabled, empty otherwise.
	SkipBaseline string
	// SkipConfig is "1" when config loading is disabled, empty otherwise.
	SkipConfig string
	// IncludeIgnored is "1" when gitignore filtering is disabled, empty otherwise.
	IncludeIgnored string
	// ReportInteractive is "1" when interactive findings rendering is enabled, empty otherwise.
	ReportInteractive string
}

// WriteDashboard renders the dashboard shell HTML to the writer.
//
// The state prefills the controls form and supplies the /scan URL stored on the report iframe.
// It returns the error from writing the page to writer, or nil when the write succeeds.
func WriteDashboard(writer io.Writer, state DashboardState) error {
	_, err := io.WriteString(writer, dashboardHTML(state))
	return err
}

// WriteDashboardError renders a self-contained dashboard error document.
//
// The page shows message as its lead paragraph, exitCode and durationMs, in milliseconds, on one line, and detail in a preformatted block.
// Both message and detail are HTML-escaped; the page goes to writer, and it returns the error from that write, or nil when the write succeeds.
func WriteDashboardError(writer io.Writer, message, detail string, exitCode, durationMs int) error {
	_, err := io.WriteString(writer, dashboardErrorHTML(message, detail, exitCode, durationMs))
	return err
}

// ScanMetadata is the payload posted from the iframe back to the dashboard shell.
//
// InjectScanMetadata embeds it as JSON in the report page, with a script that posts it to the parent window as type gruff-scan-complete.
type ScanMetadata struct {
	// ExitCode is the process exit code the scan would have produced on the CLI.
	ExitCode int `json:"exitCode"`
	// DurationMs is the wall-clock duration of the scan in milliseconds.
	DurationMs int `json:"durationMs"`
	// ProjectRoot is the scan root as requested, so it may be relative to the dashboard server's working directory.
	ProjectRoot string `json:"projectRoot"`
	// Command is a display string of the scan's CLI flags and paths, with no shell quoting or directory change, so it may not rerun the same scan.
	Command string `json:"command"`
}

// InjectScanMetadata adds the postMessage hand-off script to the rendered report HTML.
//
// The metadata is JSON-encoded and dispatched to window.parent on the matching origin.
// It returns reportHTML with both script tags inserted right after its first literal <body> tag, or prepended when it has no such tag.
func InjectScanMetadata(reportHTML string, metadata ScanMetadata) string {
	payload := struct {
		Type        string `json:"type"`
		ExitCode    int    `json:"exitCode"`
		DurationMs  int    `json:"durationMs"`
		ProjectRoot string `json:"projectRoot"`
		Command     string `json:"command"`
	}{
		Type:        "gruff-scan-complete",
		ExitCode:    metadata.ExitCode,
		DurationMs:  metadata.DurationMs,
		ProjectRoot: metadata.ProjectRoot,
		Command:     metadata.Command,
	}
	encoded, err := json.Marshal(payload)
	// If encoding ever failed, the shell would still learn the scan finished, but without its exit code, duration, root or command.
	if err != nil {
		encoded = []byte(`{"type":"gruff-scan-complete"}`)
	}
	injection := `<script id="gruff-dashboard-meta" type="application/json">` + string(encoded) + `</script>` +
		`<script>(()=>{const el=document.getElementById("gruff-dashboard-meta");if(window.parent&&el){window.parent.postMessage(JSON.parse(el.textContent),window.location.origin);}})();</script>`
	if strings.Contains(reportHTML, "<body>") {
		return strings.Replace(reportHTML, "<body>", "<body>"+injection, 1)
	}
	return injection + reportHTML
}

// DashboardScanQuery encodes the form state for a /scan request.
//
// It returns a URL-encoded query string with sorted keys and no leading question mark; the non-flag fields appear even when empty.
// The flags noBaseline, noConfig, includeIgnored and reportInteractive appear, set to 1, only when the matching state field is 1.
func DashboardScanQuery(state DashboardState) string {
	values := url.Values{}
	values.Set("project", state.Project)
	values.Set("paths", state.Paths)
	values.Set("scanScope", state.ScanScope)
	values.Set("failOn", state.FailOn)
	values.Set("config", state.Config)
	values.Set("baseline", state.Baseline)
	if state.SkipBaseline == "1" {
		values.Set("noBaseline", "1")
	}
	if state.SkipConfig == "1" {
		values.Set("noConfig", "1")
	}
	if state.IncludeIgnored == "1" {
		values.Set("includeIgnored", "1")
	}
	if state.ReportInteractive == "1" {
		values.Set("reportInteractive", "1")
	}
	return values.Encode()
}

// dashboardHTML composes the dashboard shell document from the current form state.
//
// It returns a complete HTML page whose controls form is prefilled from state.
// Its report iframe shows a loading placeholder and carries the /scan URL for state in its data-initial-src attribute.
func dashboardHTML(state DashboardState) string {
	var builder strings.Builder
	builder.WriteString(`<!DOCTYPE html><html lang="en-NZ"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>gruff-go dashboard</title><style>`)
	builder.WriteString(dashboardCSS)
	builder.WriteString(`</style></head><body>`)
	builder.WriteString(`<button type="button" id="controls-toggle" class="controls-toggle" aria-haspopup="dialog" aria-expanded="false" aria-controls="controls-panel" title="Dashboard controls">&#9881;</button>`)
	builder.WriteString(`<section id="controls-panel" class="controls-panel" role="dialog" aria-label="Dashboard controls" hidden>`)
	builder.WriteString(`<div class="panel-head"><div><strong>Dashboard controls</strong><span>local scan settings</span></div><button type="button" id="controls-close" aria-label="Close dashboard controls">&times;</button></div>`)
	builder.WriteString(`<div class="scan-summary" aria-label="Scan status">`)
	builder.WriteString(`<div class="scan-status"><span>Status</span><strong id="scan-status" aria-live="polite">Ready</strong></div>`)
	builder.WriteString(`<div class="scan-command"><span>Last scan</span><div class="scan-meta-line"><code id="scan-meta">Not run</code><button type="button" id="copy-scan-meta">Copy</button></div></div>`)
	builder.WriteString(`</div>`)
	builder.WriteString(`<form id="scan-form" method="get" action="/">`)
	builder.WriteString(`<div class="field-stack">`)
	builder.WriteString(dashboardField("Project root", "project", state.Project, ""))
	builder.WriteString(dashboardField("Paths", "paths", state.Paths, ""))
	builder.WriteString(`</div>`)
	builder.WriteString(`<div class="field-grid">`)
	builder.WriteString(dashboardField("Config path", "config", state.Config, ".gruff-go.yaml"))
	builder.WriteString(dashboardField("Baseline", "baseline", state.Baseline, "gruff-baseline.json"))
	builder.WriteString(`</div>`)
	builder.WriteString(`<div class="field-grid">`)
	builder.WriteString(`<label>Scan scope<select name="scanScope">`)
	builder.WriteString(dashboardOption("full", state.ScanScope, "whole branch"))
	builder.WriteString(dashboardOption("diff", state.ScanScope, "diff only"))
	builder.WriteString(`</select></label>`)
	builder.WriteString(`<label>Fail on<select name="failOn">`)
	// Besides the three severities, none is offered because it is the dashboard's default from DefaultFailThresholdFor("dashboard").
	// Options run strictest first, advisory failing on the most findings, with none, which never fails on findings, last.
	for _, value := range []string{"advisory", "warning", "error", "none"} {
		builder.WriteString(dashboardOption(value, state.FailOn, value))
	}
	builder.WriteString(`</select></label>`)
	builder.WriteString(`</div>`)
	builder.WriteString(`<div class="option-grid">`)
	builder.WriteString(dashboardCheck("noBaseline", "skip baseline", state.SkipBaseline))
	builder.WriteString(dashboardCheck("noConfig", "skip config", state.SkipConfig))
	builder.WriteString(dashboardCheck("includeIgnored", "include ignored", state.IncludeIgnored))
	builder.WriteString(dashboardCheck("reportInteractive", "interactive findings", state.ReportInteractive))
	builder.WriteString(`</div>`)
	builder.WriteString(`<div class="panel-actions"><button type="button" id="refresh">Refresh</button><button type="submit" id="run-scan">Run scan</button></div></form></section>`)
	scanURL := "/scan?" + DashboardScanQuery(state)
	fmt.Fprintf(&builder, `<iframe id="report-frame" title="gruff report" data-initial-src="%s" srcdoc="%s"></iframe>`, esc(scanURL), esc(dashboardLoadingFrame()))
	builder.WriteString(`<script>`)
	builder.WriteString(dashboardJS)
	builder.WriteString(`</script></body></html>`)
	return builder.String()
}

// dashboardErrorHTML produces a self-contained error document for the dashboard.
//
// It returns a full HTML page that shows message as the lead paragraph, exitCode and durationMs, in milliseconds, on one line, and detail below.
// Both message and detail are HTML-escaped, and detail sits in a preformatted block that keeps its line breaks.
func dashboardErrorHTML(message, detail string, exitCode, durationMs int) string {
	return `<!DOCTYPE html><html lang="en-NZ"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>gruff-go dashboard error</title>` +
		`<style>body{font:14px ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;background:#161412;color:#f3e9d2;padding:32px}main{max-width:920px;margin:0 auto}pre{white-space:pre-wrap;background:#0d0c0a;border:1px solid #2a2622;padding:16px;overflow:auto}</style></head><body><main>` +
		`<h1>gruff-go dashboard</h1>` +
		fmt.Sprintf(`<p>%s</p>`, esc(message)) +
		fmt.Sprintf(`<p>Exit code: %d &middot; Duration: %dms</p>`, exitCode, durationMs) +
		fmt.Sprintf(`<pre>%s</pre>`, esc(detail)) +
		`</main></body></html>`
}

// dashboardLoadingFrame returns the placeholder HTML used inside the iframe before a scan completes.
// The user sees the words Ready to scan centred on a dark page.
func dashboardLoadingFrame() string {
	return `<!DOCTYPE html><html lang="en-NZ"><head><meta charset="UTF-8"><style>body{margin:0;background:#0d0c0a;color:#f3e9d2;font:14px ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;display:grid;place-items:center;min-height:100vh}</style></head><body>Ready to scan.</body></html>`
}

// dashboardField renders a labelled text input for the dashboard form.
//
// It returns a label element whose text is label and whose input carries name, value and placeholder as attributes, all four HTML-escaped.
// An empty value or placeholder still renders as an empty attribute.
func dashboardField(label, name, value, placeholder string) string {
	return fmt.Sprintf(
		`<label>%s<input name="%s" value="%s" placeholder="%s"></label>`,
		esc(label),
		esc(name),
		esc(value),
		esc(placeholder),
	)
}

// dashboardOption renders a single select option, marking it selected when the value matches.
//
// It returns an option element whose value attribute is value and whose text is label, both HTML-escaped.
// The selected attribute is added only when value equals selected exactly.
func dashboardOption(value, selected, label string) string {
	selectedAttr := ""
	if value == selected {
		selectedAttr = " selected"
	}
	return fmt.Sprintf(
		`<option value="%s"%s>%s</option>`,
		esc(value),
		selectedAttr,
		esc(label),
	)
}

// dashboardCheck renders a labelled checkbox for the dashboard form.
//
// It returns a checkbox input named name with value 1, wrapped in a label whose text is label; name and label are HTML-escaped.
// The box is checked only when value is exactly 1, the value DashboardState flag fields hold when set.
func dashboardCheck(name, label, value string) string {
	checked := ""
	if value == "1" {
		checked = " checked"
	}
	return fmt.Sprintf(
		`<label class="check"><input type="checkbox" name="%s" value="1"%s><span>%s</span></label>`,
		esc(name),
		checked,
		esc(label),
	)
}
