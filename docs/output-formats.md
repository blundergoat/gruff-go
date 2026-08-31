# Output Formats

`gruff-go analyse --format <fmt>` accepts seven formats. Pick the one that matches the consumer - terminals get `text`, CI annotators get `github` or `sarif`, dashboards and report archives get `html`, GitHub PR comments and CI logs get `markdown`, automation gets `json` or `summary-json`. All formats share the same underlying `analysis.Report` data, so a JSON pipeline and a SARIF pipeline see the same findings, scores, and metadata.

The default is `text` if you omit `--format`.

## `text` (default)

Compact terminal-friendly output:

```text
gruff-go 0.5.0 analyse
Composite: A (99.00 / 100)
Findings: 1 total · 0 error · 1 warning · 0 advisory
schema: gruff.analysis.v3
files: 65 scanned, 6 skipped
score coverage: size
score caveat: Composite grade is driven by 1 score-impacting pillar; clean pillars mean no above-threshold findings from configured rules, not broad risk coverage.
complexity distribution: finding-only
findings:
  [warning] internal/foo/bar.go:42 complexity.cyclomatic: function cyclomatic complexity is 23, above threshold 20
exit: 1
```

The text format is intentionally terse. For human review of a full run, prefer `--format html` and open it in a browser.

### Summary scan surface

`gruff-go summary --format text` separates the files that reached Go parsing from files read for raw-text rules:

```text
files: 61 Go parsed, 4 text scanned, 0 failed, 6 skipped
```

`Go parsed` excludes Go files with parse or read diagnostics. `text scanned` counts successfully read configuration, workflow, module, and plain-text inputs used by sensitive-data, workflow-security, and dependency-posture rules. `failed` counts discovered inputs that could not be read or parsed.

Full analysis JSON keeps `summary.analysedFiles` as the combined discovered
Go-and-text count. Use `paths.extensions.go.paths.scanned` when a machine
consumer needs the exact file set.

## `json`

Use `json` for automation. Full reports use `gruff.analysis.v3`:

```sh
gruff-go analyse --format json --min-severity none . > analysis.json
```

Version 3 is the coordinated family machine contract. Paths are project-relative
POSIX paths, `run.projectRoot` is `.`, and unavailable optional fields are
omitted rather than encoded as `null`.

The canonical top-level sections are `schemaVersion`, `tool`, `run`,
`summary`, `score`, `diagnostics`, `findings`, `paths`, and
`suppressions`. `baseline`, `diff`, `displayFilter`, and
`extensions` appear only when their feature or Go-owned data is present.
The important shared shape is:

```jsonc
{
  "schemaVersion": "gruff.analysis.v3",
  "tool": { "name": "gruff-go", "version": "0.5.0" },
  "run": {
    "projectRoot": ".",
    "inputs": ["."],
    "format": "json",
    "failOn": "advisory"
  },
  "summary": {
    "analysedFiles": 65,
    "skippedFiles": 6,
    "ignoredPaths": 6,
    "missingPaths": 0,
    "diagnostics": 0,
    "findings": {
      "advisory": 0,
      "warning": 3,
      "error": 0,
      "total": 3
    },
    "findingsByPillar": { "complexity": 3 },
    "exitCode": 1
  },
  "score": {
    "composite": { "score": 92, "grade": "A" },
    "pillars": [],
    "topOffenders": []
  },
  "paths": {
    "analysedFiles": 65,
    "ignoredPaths": [],
    "details": [],
    "missingPaths": []
  },
  "diagnostics": [],
  "findings": [],
  "suppressions": []
}
```

A canonical finding uses one path key:

```jsonc
{
  "ruleId": "complexity.cyclomatic",
  "message": "function cyclomatic complexity is 23, above threshold 20",
  "file": "internal/foo/bar.go",
  "line": 42,
  "endLine": 78,
  "symbol": "DoTheThing",
  "severity": "warning",
  "pillar": "complexity",
  "secondaryPillars": [],
  "tier": "v0.1",
  "confidence": "high",
  "remediation": "Split independent decisions or move branches into named helpers.",
  "fingerprint": "a3b1c2d4e5f6a7b8",
  "stableIdentity": "b8a7f6e5d4c2b1a3",
  "metadata": {
    "complexity": 23,
    "threshold": 20,
    "locationPrecision": "line-only"
  }
}
```

`column`, `endLine`, and `symbol` are omitted when unavailable. Metadata
declares `locationPrecision` as `scanner-pinpointed` when a column is known
and `line-only` otherwise. The v3 adapter preserves every fingerprint,
`stableIdentity`, score, grade, baseline result, and exit-code decision
produced by the native analyser.

Go-specific data stays in named extension containers:
`summary.extensions.go.summary` carries parser mode,
`paths.extensions.go.paths.scanned` carries the exact scanned set, and
`extensions.go.topLevel.rules` carries the active rule catalogue. Native score
honesty fields such as `coverage`, `complexityDistribution`, and
`complexityDistributionScope` remain inside `score`.

`paths.details` records each skipped path with `path`, canonical `reason`,
`source`, and `pattern` when a pattern caused the skip.
`paths.ignoredPaths` is its ordered path projection. `--include-ignored` can
include Git- or default-ignored files, while config `paths.ignore` still wins.

Changed-region runs report the removed count as
`diff.filteredFindings` and `summary.suppressedFindings`; the two values are
equal. Full scans omit both fields and omit `diff`.

`suppressions` is always present and contains one
`{index, rule, paths, symbol?, reason, suppressed}` row per configured
`sensitiveExclusions` entry, including entries that matched nothing.

### Migrating v2 consumers

Version 3 is a hard break with no v2 writer or compatibility flag:

| v2 | v3 |
|---|---|
| `run.workingDirectory` | `run.projectRoot` with value `.` |
| `summary.filesScanned` and `summary.filesSkipped` | `summary.analysedFiles` and `summary.skippedFiles` |
| `summary.findingsCount` and `summary.countsBySeverity` | `summary.findings.total` and `summary.findings` |
| `summary.countsByPillar` | `summary.findingsByPillar` |
| `findings[].location` | flat `line`, optional `endLine`, and optional `column` |
| `score.composite` plus `score.grade` | `score.composite.score` plus `score.composite.grade` |
| `paths.scanned` | `paths.extensions.go.paths.scanned` |
| `paths.skipped` and `paths.missing` | `paths.details` and `paths.missingPaths` |
| top-level `rules` | `extensions.go.topLevel.rules` |
| top-level `suppressedCount` | `diff.filteredFindings` and `summary.suppressedFindings` |

## `summary-json`

Both `analyse --format summary-json` and `summary --format json` emit the
findings-free projection of analysis v3. The schema changes to
`gruff.summary.v3`, and only the top-level `findings` array is removed.

```sh
gruff-go analyse --format summary-json .
gruff-go summary --format json .
```

Counts, scores, diagnostics, paths, suppressions, baseline, diff, and extensions
therefore retain the analysis values for the same run.

## `sarif`

SARIF 2.1.0. Compatible with [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning), [GitLab SAST integration](https://docs.gitlab.com/ee/user/application_security/sast/), and any other SARIF consumer.

```bash
gruff-go analyse --format sarif . > gruff-go.sarif
```

The output includes:

- `runs[].tool.driver` with the resolved rule registry (one `rules[]` entry per rule active for the run, including pillar / severity / confidence / capability / tags via `properties`).
- `runs[].results` with one entry per finding, mapping severity to SARIF `level`:
  - `error` → `error`
  - `warning` → `warning`
  - `advisory` → `note`
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
| `error` | `error` |
| `warning` | `warning` |
| `advisory` | `notice` |

This format works whether the workflow uses `actions/checkout` directly or an annotated runner - GitHub pulls the annotations from stdout/stderr without any extra step. For richer Code Scanning integration, prefer `sarif`.

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

- `none` *(default)* - selectable copyable `<span data-path="…">` with no `href`. Safe to ship as an artefact that opens on any machine.
- `vscode` - `<a href="vscode://file/{absPath}:{line}">` anchors. Clicking opens VS Code at the right line on a machine that has the editor installed.
- `phpstorm` - `<a href="phpstorm://open?file={absPath}&line={line}">` anchors. Same idea for JetBrains.

The absolute path is built relative to `--project` (when set) or the working directory at render time. The visible text always shows the project-relative path so it's portable; only the `href` carries the absolute path.

### `--report-interactive`

Adds an inline filter form above the findings list:

- **Severity** multi-select (canonical order `error → warning → advisory`).
- **Pillar** multi-select (alphabetically sorted, deduplicated from the actual findings in the report).
- **Path** text input (case-insensitive substring match against `data-file`).
- **Search** text input (case-insensitive substring match against rule ID + message).
- **Group by** radios: `none` (default), `file`, `rule`.
- **Clear all** button + live count via `aria-live="polite"`.

Filter state is mirrored into the URL hash with stable canonical ordering so deep-links and reload survive. Without `--report-interactive`, the report still emits `data-severity / data-pillar / data-file / data-rule / data-search` attributes on every finding row - only the form + script are omitted.

### What the report contains

Even without flags, the HTML report includes:

- Masthead with the run inputs, scope, format, fail-on threshold, and tool version.
- Verdict block with the tilted grade stamp (`A` through `F` plus numeric composite) and a data-driven subtitle.
- Score coverage caveat when the grade is clean or driven by only one or two score-impacting pillars.
- Per-pillar grade grid with severity breakdowns.
- Top-offender file table with cyclomatic, finding count, penalty, and grade per file.
- Cyclomatic distribution histogram with a one-line finding-only summary.
- Findings list grouped by document order.
- Footer with version + schema metadata.

`design.*` composite findings appear in the findings list and summary counts, but they do not contribute to per-pillar grades, top-offender penalties, or the numeric composite score.

## `markdown`

CommonMark-flavoured markdown digest tuned for CI logs and GitHub PR comments. Use `--format markdown` (or the `md` alias) to emit a short header, severity totals, the canonical Pillars table, and a compact top-rules block.

```bash
gruff-go analyse --format markdown . > gruff-report.md
gruff-go analyse --format md .
```

Output shape:

```markdown
# gruff-go report

Composite: **A (100.00 / 100)**
**Schema:** `gruff.analysis.v3`
**Files:** 148 scanned, 13 skipped
Findings: 0 total · 0 error · 0 warning · 0 advisory

## Pillars

| Pillar | Grade | Score | Findings | Advisory | Warning | Error |
|---|---|---:|---:|---:|---:|---:|
| complexity | A | 100.00 | 0 | 0 | 0 | 0 |
| ...
```

The Pillars table mirrors the cross-port summary harmonisation shape used by the text and HTML reporters: every applicable pillar is shown with grade, two-decimal score, finding count, and per-severity counts, sorted by findings descending then pillar ascending. Clean scans surface as grade A rows with score `100.00` and zero counts. The optional `## Top rules` section is omitted when no findings fired.

Pipe characters inside pillar names or rule IDs are escaped (`\|`) so the surrounding table row stays valid.

## Exit codes (shared across formats)

The chosen format does **not** change the exit code. All formats use:

| Exit | Meaning |
|------|---------|
| `0` | No findings at or above `--min-severity` and no diagnostics. |
| `1` | At least one finding at or above `--min-severity`. |
| `2` | Diagnostics (path missing, parse error, config error, baseline error, diff error) **or** invalid CLI input. |

Set `--min-severity` to control where the line falls (default: `advisory`).
The threshold applies only to findings: `--min-severity none` disables exit `1`,
but it cannot hide a missing path, parse failure, baseline load failure, diff
failure, invalid configuration, or invalid CLI input. Those failures always exit
`2`. Analysis diagnostics retain severity `error` as descriptive output; the
presence of any diagnostic, not a second severity threshold, determines exit `2`.
Nonfatal limitations are rendered through existing caveat fields instead.

Agent `hook` mode has one intentional advisory exception: ignored or skipped
explicit paths are reported in-band and exit `0`. Genuine hook configuration,
analysis, or internal failures remain exit `2`.

## Schemas

| Schema | Used by | File |
|--------|---------|------|
| `gruff.analysis.v3`      | `json` | `internal/analysis/report.go` |
| `gruff.summary.v3`       | `summary-json`, `summary --format json` | `internal/analysis/report.go` |
| `gruff-go.config.v0.1`   | `.gruff-go.yaml` config loader | `internal/config/config.go` |
| `gruff-go.baseline.v0.1` | `baseline` subcommand | `internal/baseline/baseline.go` |
| `sarif-2.1.0`            | `sarif` | `internal/report/machine.go` |
