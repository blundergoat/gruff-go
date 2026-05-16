# Output Formats

`gruff-go analyse --format <fmt>` accepts six formats. Pick the one that matches the consumer — terminals get `text`, CI annotators get `github` or `sarif`, dashboards and report archives get `html`, automation gets `json` or `summary-json`. All formats share the same underlying `analysis.Report` data, so a JSON pipeline and a SARIF pipeline see the same findings, scores, and metadata.

The default is `text` if you omit `--format`.

## `text` (default)

Compact terminal-friendly output:

```text
gruff-go analysis
schema: gruff-go.analysis.v0.1
files: 65 scanned, 6 skipped
findings:
  [medium] internal/foo/bar.go:42 complexity.cyclomatic: function cyclomatic complexity is 23, above threshold 20
exit: 1
```

The text format is intentionally terse. For human review of a full run, prefer `--format html` and open it in a browser.

## `json`

Full structured report. Schema: `gruff-go.analysis.v0.1`.

```bash
gruff-go analyse --format json . > analysis.json
```

Top-level shape:

```jsonc
{
  "schemaVersion": "gruff-go.analysis.v0.1",
  "tool":          { "name": "gruff-go", "version": "0.1.0-dev" },
  "run":           { "workingDirectory": "/repo", "inputs": ["."], "format": "json", "failOn": "medium" },
  "summary":       { "filesScanned": 65, "filesSkipped": 6, "findingsCount": 3,
                     "countsBySeverity": {...}, "countsByPillar": {...}, "exitCode": 1 },
  "baseline":      { "applied": false, "entries": 0, "suppressedFindings": 0, "staleEntries": 0 },
  "diff":          { "enabled": false, "changedFiles": [], "filteredFindings": 0 },
  "displayFilter": { "applied": false, "...": "..." },
  "score":         { "composite": 92, "grade": "A",
                     "pillars": {...}, "pillarDetails": [...],
                     "topOffenders": [...], "complexityDistribution": {...} },
  "rules":         [ /* every rule definition active for this run */ ],
  "paths":         { "scanned": [...], "skipped": [...], "missing": [] },
  "diagnostics":   [ /* parse errors, missing paths, config errors, etc. */ ],
  "findings":      [ /* one entry per finding */ ]
}
```

Every finding looks like:

```jsonc
{
  "ruleId":      "complexity.cyclomatic",
  "message":     "function cyclomatic complexity is 23, above threshold 20",
  "file":        "internal/foo/bar.go",
  "location":    { "line": 42, "endLine": 78 },
  "symbol":      "DoTheThing",
  "severity":    "medium",
  "confidence":  "high",
  "pillar":      "complexity",
  "remediation": "Split independent decisions or move branches into named helpers.",
  "metadata":    { "complexity": 23, "threshold": 20 },
  "fingerprint": "a3b1c2d4e5f6a7b8"
}
```

The 16-character fingerprint is stable across runs as long as the rule ID, file, line, column, end-line, symbol, and message stay the same — that's what baselines key on. Score-neutral `design.*` composite findings intentionally omit line data so their fingerprints survive body-only line shifts when the file and symbol identity stay the same.

## `summary-json`

Same shape as `json` minus the per-finding `findings` array. Useful for CI dashboards that want the counts, score, and diagnostics without parsing thousands of finding records.

```bash
gruff-go analyse --format summary-json .
```

Schema is still `gruff-go.analysis.v0.1` — the missing `findings` field is the only difference.

## `sarif`

SARIF 2.1.0. Compatible with [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning), [GitLab SAST integration](https://docs.gitlab.com/ee/user/application_security/sast/), and any other SARIF consumer.

```bash
gruff-go analyse --format sarif . > gruff-go.sarif
```

The output includes:

- `runs[].tool.driver` with the resolved rule registry (one `rules[]` entry per rule active for the run, including pillar / severity / confidence / tags via `properties`).
- `runs[].results` with one entry per finding, mapping severity to SARIF `level`:
  - `critical` / `high` → `error`
  - `medium` → `warning`
  - `low` / `info` → `note`
- `partialFingerprints.gruffFingerprint` carries the gruff-go fingerprint so consumers can match findings across runs.

Upload via GitHub Actions:

```yaml
- name: Upload gruff-go SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: gruff-go.sarif
```

## `github`

GitHub Actions [workflow command](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-error-message) annotations. One line per finding, emitted to stdout:

```text
::warning file=internal/foo/bar.go,line=42,endLine=78,title=complexity.cyclomatic::function cyclomatic complexity is 23, above threshold 20
```

Map of severity to GitHub level:

| gruff-go severity | GitHub level |
|-------------------|--------------|
| `critical` / `high` | `error` |
| `medium` | `warning` |
| `low` / `info` | `notice` |

This format works whether the workflow uses `actions/checkout` directly or an annotated runner — GitHub pulls the annotations from stdout/stderr without any extra step. For richer Code Scanning integration, prefer `sarif`.

## `html`

Self-contained HTML inspection report. Inline CSS, no external resources, no fonts loaded over the network. Open it in any browser, attach it to a PR comment, archive it as a CI artefact, or load it via the local dashboard.

```bash
# Static report on disk.
gruff-go analyse --format html . > gruff-report.html

# With editor links.
gruff-go analyse --format html --report-editor-link vscode . > gruff-report.html

# With the interactive filter UI.
gruff-go analyse --format html --report-interactive . > gruff-report.html
```

### `--report-editor-link none|vscode|phpstorm`

Controls how file:line references render in the report:

- `none` *(default)* — selectable copyable `<span data-path="…">` with no `href`. Safe to ship as an artefact that opens on any machine.
- `vscode` — `<a href="vscode://file/{absPath}:{line}">` anchors. Clicking opens VS Code at the right line on a machine that has the editor installed.
- `phpstorm` — `<a href="phpstorm://open?file={absPath}&line={line}">` anchors. Same idea for JetBrains.

The absolute path is built relative to `--project` (when set) or the working directory at render time. The visible text always shows the project-relative path so it's portable; only the `href` carries the absolute path.

### `--report-interactive`

Adds an inline filter form above the findings list:

- **Severity** multi-select (canonical order `critical → high → medium → low → info`).
- **Pillar** multi-select (alphabetically sorted, deduplicated from the actual findings in the report).
- **Path** text input (case-insensitive substring match against `data-file`).
- **Search** text input (case-insensitive substring match against rule ID + message).
- **Group by** radios: `none` (default), `file`, `rule`.
- **Clear all** button + live count via `aria-live="polite"`.

Filter state is mirrored into the URL hash with stable canonical ordering so deep-links and reload survive. Without `--report-interactive`, the report still emits `data-severity / data-pillar / data-file / data-rule / data-search` attributes on every finding row — only the form + script are omitted.

### What the report contains

Even without flags, the HTML report includes:

- Masthead with the run inputs, scope, format, fail-on threshold, and tool version.
- Verdict block with the tilted grade stamp (`A` through `F` plus numeric composite) and a data-driven subtitle.
- Per-pillar grade grid with severity breakdowns.
- Top-offender file table with cyclomatic, finding count, penalty, and grade per file.
- Cyclomatic distribution histogram with a one-line summary.
- Findings list grouped by document order.
- Footer with version + schema metadata.

`design.*` composite findings appear in the findings list and summary counts, but they do not contribute to per-pillar grades, top-offender penalties, or the numeric composite score.

The visual identity is documented in [`.goat-flow/tasks/0.1/M09-html-report-visual-parity.md`](../.goat-flow/tasks/0.1/M09-html-report-visual-parity.md).

## Exit codes (shared across formats)

The chosen format does **not** change the exit code. All formats use:

| Exit | Meaning |
|------|---------|
| `0` | No findings at or above `--min-severity` and no diagnostics. |
| `1` | At least one finding at or above `--min-severity`. |
| `2` | Diagnostics (path missing, parse error, config error, baseline error, diff error) **or** invalid CLI input. |

Set `--min-severity` to control where the line falls (default: `medium`).

## Schemas

| Schema | Used by | File |
|--------|---------|------|
| `gruff-go.analysis.v0.1` | `json`, `summary-json` | `internal/analysis/report.go` |
| `gruff-go.config.v0.1`   | `.gruff.yaml` / `.gruff.json` config loader | `internal/config/config.go` |
| `gruff-go.baseline.v0.1` | `baseline` subcommand | `internal/baseline/baseline.go` |
| `sarif-2.1.0`            | `sarif` | `internal/report/machine.go` |
