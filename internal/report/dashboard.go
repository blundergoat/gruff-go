package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// DashboardState describes the form state rendered into the dashboard shell.
type DashboardState struct {
	Project           string
	Paths             string
	ScanScope         string
	FailOn            string
	Config            string
	Baseline          string
	NoBaseline        string
	NoConfig          string
	IncludeIgnored    string
	ReportInteractive string
}

// WriteDashboard renders the dashboard shell HTML to the writer.
func WriteDashboard(writer io.Writer, state DashboardState) error {
	_, err := io.WriteString(writer, dashboardHTML(state))
	return err
}

// WriteDashboardError renders a self-contained dashboard error document.
func WriteDashboardError(writer io.Writer, message, detail string, exitCode, durationMs int) error {
	_, err := io.WriteString(writer, dashboardErrorHTML(message, detail, exitCode, durationMs))
	return err
}

// ScanMetadata is the payload posted from the iframe back to the dashboard shell.
type ScanMetadata struct {
	ExitCode    int    `json:"exitCode"`
	DurationMs  int    `json:"durationMs"`
	ProjectRoot string `json:"projectRoot"`
	Command     string `json:"command"`
}

// InjectScanMetadata adds the postMessage hand-off script to the rendered report HTML.
// The metadata is JSON-encoded and dispatched to window.parent on the matching origin.
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
func DashboardScanQuery(state DashboardState) string {
	values := url.Values{}
	values.Set("project", state.Project)
	values.Set("paths", state.Paths)
	values.Set("scanScope", state.ScanScope)
	values.Set("failOn", state.FailOn)
	values.Set("config", state.Config)
	values.Set("baseline", state.Baseline)
	if state.NoBaseline == "1" {
		values.Set("noBaseline", "1")
	}
	if state.NoConfig == "1" {
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
	for _, value := range []string{"info", "low", "medium", "high", "critical"} {
		builder.WriteString(dashboardOption(value, state.FailOn, value))
	}
	builder.WriteString(`</select></label>`)
	builder.WriteString(`</div>`)
	builder.WriteString(`<div class="option-grid">`)
	builder.WriteString(dashboardCheck("noBaseline", "skip baseline", state.NoBaseline))
	builder.WriteString(dashboardCheck("noConfig", "skip config", state.NoConfig))
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

func dashboardErrorHTML(message, detail string, exitCode, durationMs int) string {
	return `<!DOCTYPE html><html lang="en-NZ"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>gruff-go dashboard error</title>` +
		`<style>body{font:14px ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;background:#161412;color:#f3e9d2;padding:32px}main{max-width:920px;margin:0 auto}pre{white-space:pre-wrap;background:#0d0c0a;border:1px solid #2a2622;padding:16px;overflow:auto}</style></head><body><main>` +
		`<h1>gruff-go dashboard</h1>` +
		fmt.Sprintf(`<p>%s</p>`, esc(message)) +
		fmt.Sprintf(`<p>Exit code: %d &middot; Duration: %dms</p>`, exitCode, durationMs) +
		fmt.Sprintf(`<pre>%s</pre>`, esc(detail)) +
		`</main></body></html>`
}

func dashboardLoadingFrame() string {
	return `<!DOCTYPE html><html lang="en-NZ"><head><meta charset="UTF-8"><style>body{margin:0;background:#0d0c0a;color:#f3e9d2;font:14px ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;display:grid;place-items:center;min-height:100vh}</style></head><body>Ready to scan.</body></html>`
}

func dashboardField(label, name, value, placeholder string) string {
	return fmt.Sprintf(
		`<label>%s<input name="%s" value="%s" placeholder="%s"></label>`,
		esc(label),
		esc(name),
		esc(value),
		esc(placeholder),
	)
}

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
