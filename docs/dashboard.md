# Dashboard

`gruff-go dashboard` serves a local browser dashboard that wraps the HTML inspection report in an interactive shell. You point it at a project root, click `Run scan`, and the report renders in an iframe with the current findings - no terminal output to parse, no rebuild loop. The same report is what `gruff-go analyse --format html` emits, so what you see in the dashboard is what you'd commit to a static report artefact.

## Quick start

```bash
# Bind to the default loopback host:port.
gruff-go dashboard --project .

# Open this URL in any browser:
# http://127.0.0.1:8765/
```

The terminal prints the launch URL and a one-liner controls hint. The dashboard stays in the foreground until you press `Ctrl+C` (clean shutdown via SIGINT) or send `SIGTERM`.

## All flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--host` | `127.0.0.1` | Bind host. Non-loopback hosts require `--allow-public`. |
| `--port` | `8765` | Bind port (1–65535). |
| `--scan-timeout` | `120` | Per-scan deadline in seconds. `0` disables. |
| `--project` | *current dir* | Initial project root the controls panel pre-fills. |
| `--paths` | *empty* | Comma-separated initial paths to scan. |
| `--config` | *auto-discover* | Initial `.gruff-go.yaml` path. |
| `--no-config` | *off* | Skip auto-loading any config file. |
| `--baseline` | *empty* | Initial baseline JSON path. |
| `--no-baseline` | *off* | Refuse to apply any baseline. |
| `--diff` | *off* | Start in diff-only scan mode (against `HEAD`). |
| `--include-ignored` | *off* | Include gitignored and default-ignored files; `paths.ignore` still applies. |
| `--fail-on` | `medium` | Minimum severity that fails the scan. |
| `--report-interactive` | *off* | Enable the inline finding filter UI inside the iframe. |
| `--report-editor-link` | `none` | File:line link mode: `none`, `vscode`, `phpstorm`. |
| `--allow-public` | *off* | Permit non-loopback `--host`. Required for `0.0.0.0` etc. |

The scan-shaping flags from `--project` through `--report-interactive` map to controls-panel fields, so you can adjust those knobs from the browser without restarting the server. Listener and startup-only settings (`--host`, `--port`, `--scan-timeout`, `--report-editor-link`, and `--allow-public`) stay fixed for the running dashboard process.

## Security model

The dashboard is **local-only** by design:

- The listener binds to `127.0.0.1` unless `--host` says otherwise.
- If `--host` resolves to a non-loopback address, the server **refuses to start** without `--allow-public`. The refusal includes the host name in the error so it's obvious in scripts.
- When `--allow-public` is set with a non-loopback host, the server prints a `WARNING: binding dashboard to non-loopback host …` line at start-up.
- The dashboard accepts only `GET` requests. `POST` returns `405 Method Not Allowed`; unknown paths return `404 Not Found`.
- Every query-string value (project root, paths, config path, baseline path, fail-on, scope, include-ignored, and interactive-report state) is HTML-escaped before it reaches the rendered shell or report. The same escaping path the static HTML reporter uses is reused here.
- `/scan` runs the analyser **in-process** - there is no `exec`, no template substitution into a shell command, no eval. The "command" string shown in the controls panel is a human-readable rendering of what the analyser would be invoked with, not a string passed to a shell.
- The iframe `postMessage` listener accepts events only from `window.location.origin`. Cross-origin or sandboxed iframes attempting to spoof scan-complete metadata are ignored.

If you need remote access, run the dashboard inside an SSH tunnel rather than enabling `--allow-public`:

```bash
ssh -L 8765:127.0.0.1:8765 user@host
# On the remote machine:
gruff-go dashboard --project /path/to/repo
# On your laptop, browse to http://127.0.0.1:8765/
```

## Page anatomy

```
┌─────────────────────────────────────────────────────────────────┐
│                                                          ⚙       │ <- cog button (top-right)
│                                                                   │
│                  ┌─ controls panel ─────────────┐                 │
│                  │ Status  Ready                │                 │
│                  │ Last scan  exit 0 · 245ms …  │                 │
│                  │ Project root [_______________]│                │
│                  │ Paths        [_______________]│                │
│                  │ Config / Baseline grid       │                 │
│                  │ Scope / Fail-on selects      │                 │
│                  │ ☐ skip baseline  ☐ skip cfg │                 │
│                  │ ☐ include ignored ☐ interactive │              │
│                  │ [Refresh] [Run scan]         │                 │
│                  └──────────────────────────────┘                 │
│                                                                   │
│   ┌────────── iframe (full viewport) ──────────┐                  │
│   │  gruff-go HTML report                       │                 │
│   │  (paper frame · grade stamp · findings)     │                 │
│   └─────────────────────────────────────────────┘                 │
└─────────────────────────────────────────────────────────────────┘
```

- **Cog button** (top-right). Opens the controls panel. Keyboard: focusable, opens with `Enter` / `Space`, closes with `Escape`. ARIA: `aria-haspopup="dialog"`, `aria-controls="controls-panel"`, `aria-expanded` mirrors the panel state.
- **Controls panel**. The form fields above plus a live `Status` indicator (`Ready` / `Scanning… Ns` / `Scan loaded`) and a copy-the-last-command affordance. The status field is `aria-live="polite"` so screen readers announce updates.
- **Iframe**. Hosts the actual report. The first iframe document is a minimal `Ready to scan.` placeholder; subsequent scans replace it with a fresh report from `/scan?…`.

## Scan lifecycle

1. Click **Run scan** (or press `Enter` in any form field).
2. The dashboard JS:
   - Marks the cog and run buttons busy.
   - Sets `Status` to `Scanning… 0s` and increments every second.
   - Sets the iframe `src` to `/scan?…` with the current form state plus a cache-busting `_run` parameter.
   - Mirrors the same state into the URL hash via `history.replaceState`, so reloading the dashboard preserves the form.
3. The server handler:
   - Parses the query string into an `analysis.Options` struct (no shell exec).
   - Runs the scan with the configured project root and `--scan-timeout` deadline. Project config and baseline paths are resolved relative to that project root.
   - Renders the result via `report.WriteHTML` and injects the `postMessage` metadata `<script>`.
   - Returns `text/html; charset=utf-8`.
4. When the iframe `load` event fires, the dashboard JS:
   - Stops the busy timer and sets `Status` to `Scan loaded`.
   - Reads the injected metadata or accepts the same payload via `postMessage` and renders it into the `Last scan` chip as `exit N · Mms · gruff-go analyse --format html …`.

## postMessage protocol

After every scan, the report HTML carries:

```html
<script id="gruff-dashboard-meta" type="application/json">
  {"type":"gruff-scan-complete","exitCode":0,"durationMs":245,"projectRoot":"/repo","command":"gruff-go analyse --format html --min-severity medium ."}
</script>
<script>(()=>{const el=document.getElementById("gruff-dashboard-meta");if(window.parent&&el){window.parent.postMessage(JSON.parse(el.textContent),window.location.origin);}})();</script>
```

The dashboard shell ignores any message whose `origin` does not match `window.location.origin` and any payload whose `type` is not `gruff-scan-complete`. If you embed the dashboard inside your own page, listen for the same event shape on the matching origin.

When the scan includes ignored files or enables the interactive report UI, the metadata command includes `--include-ignored` and `--report-interactive` so the scan can be reproduced from `gruff-go analyse --format html`.

## Scan-timeout behaviour

`--scan-timeout` (default `120` seconds) enforces a wall-clock deadline per scan. On expiry, the handler:

- Cancels the analysis context so discovery stops early and later analysis phases abort before rendering partial results.
- Returns a `dashboardErrorHTML` document with HTTP status `200` (so the iframe still loads parseable HTML).
- Sets the metadata `exitCode` to `124` and includes a `Scan exceeded Ns timeout.` headline.

Set `--scan-timeout 0` to disable the deadline entirely - useful when bisecting a slow-rule issue.

## Interactive findings inside the iframe

Check the **interactive findings** checkbox in the controls panel (or pass `--report-interactive` at start-up) to enable the filter form inside the iframe report. The filter is a self-contained client-side widget - severity multi-select, pillar multi-select, path / search text, group-by file/rule, clear-all. Filter state lives in the iframe's URL hash so deep-links and reload survive.

See [`output-formats.md`](output-formats.md) for the standalone behaviour of the same flag in `gruff-go analyse --format html --report-interactive`.

## Concurrency model

Each `/scan` request passes an explicit project root and context into `analysis.Analyze`; the dashboard does not change the process working directory. This keeps concurrent requests isolated at the scan-root/config layer. The server still handles scans inline per request and does not provide a queued multi-scan workflow.
