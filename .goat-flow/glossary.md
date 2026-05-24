# Glossary - gruff-go

Last reviewed 2026-05-24.

This glossary defines terms used by `gruff-go`, its public reports, and local project memory. Keep shared gruff-family terms aligned with the sibling implementations; keep Go-specific differences explicit rather than making them look identical.

## Scope

`gruff-go` is the Go implementation of the gruff quality-scanner family. The module is `github.com/blundergoat/gruff-go`; the CLI binary is `gruff-go`; source entrypoint is `cmd/gruff-go/main.go`; product code lives under `internal/`.

## Shared Gruff Terms

### Analysis Report

The complete result of one scan: schema version, tool metadata, run metadata, paths, summary counts, score data, diagnostics, findings, baseline state, and optional diff state. Native JSON uses `gruff-go.analysis.v0.1`.

### Baseline

A reviewed-finding suppression file. `gruff-go` writes and reads `gruff-go.baseline.v0.1`; entries match by stable finding identity so known findings can be suppressed without disabling rules.

### Changed-Code Scan

A scan filtered to changed lines or files. In `gruff-go`, `--diff-base <ref>` parses local Git diff output and keeps findings that overlap changed lines.

### Confidence

The certainty tier attached to a finding. It helps scoring and reviewers distinguish high-signal findings from heuristic prompts.

### Dashboard

The local browser UI served by `gruff-go dashboard`. It binds to `127.0.0.1:8765` by default and has no authentication; use `--port` when another gruff dashboard is already using the port.

### Diagnostic

A run-level problem such as a missing path, read error, parse error, config error, baseline error, or diff error. Fatal diagnostics force exit code `2`.

### Display Filter

A report-only filter such as include/exclude rules or pillars. Display filters change rendered output, not rule execution. Do not use them as policy suppressions.

### Exit Codes

`0` means the run completed and no finding met the failure threshold. `1` means at least one finding met the threshold. `2` means a fatal diagnostic or invalid input stopped the requested scan from being fully trustworthy.

### Finding

One rule-produced result with rule ID, message, severity, confidence, pillar, location, remediation, metadata, and fingerprint.

### Fingerprint

A stable 16-character hash derived from finding identity fields. Baselines and downstream tooling key on it together with rule ID and file path.

### Gruff Config

Project configuration that tunes discovery, allowlists, rule selection, and per-rule thresholds/severity. Shared keys are `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, `selection`, and `rules.<id>`.

### Hotspot Output

A compact JSON view of the worst file offenders in gruff implementations that support it. `gruff-go` does not currently emit a separate hotspot format; use `summary-json` or the full analysis JSON instead.

### Output Format

A renderer over the same analysis report. `gruff-go analyse` supports `text`, `json`, `summary-json`, `sarif`, `github`, and `html`; `report` supports `html` and `json`.

### Pillar

The quality dimension a finding belongs to, such as `complexity`, `security`, `sensitive-data`, or `test-quality`. Pillars feed per-pillar scoring and display filters.

### Rule Catalogue

The set of built-in rules plus their public metadata. `list-rules` reports the effective state after config is applied; use `gruff-go list-rules --no-config` to inspect built-in defaults.

### Rule ID

Stable public identifier for one rule, using dotted gruff-family names such as `size.file-length`, `docs.package-comment`, and `sensitive-data.secret-pattern`. Documentation rules use `docs.*` while the emitted pillar is `documentation`.

### SARIF

Static Analysis Results Interchange Format. `gruff-go` emits SARIF 2.1.0 from the same report data used by the other renderers.

### Score And Grade

The numeric and letter quality summary derived from findings after baseline and filter layers have been applied according to the current command.

### Secret Preview

A redacted representation of sensitive-data matches. Raw secret values must not appear in terminal, JSON, SARIF, GitHub, or HTML output.

### Severity And Failure Threshold

`gruff-go` uses `info`, `low`, `medium`, `high`, and `critical`. `--min-severity` drives exit code `1`; `--fail-on` is accepted as a CLI alias for parity with other gruff tools.

### Source Discovery

The process that turns input paths into classifiable source/text files. `paths.ignore` always applies; `--include-ignored` opts into default-ignored and Git-ignored paths for deliberate inspection.

### Trust Boundary

Default scans are local source inspections. `gruff-go` parses files and may call Git for explicit diff scans; it does not run target code, run tests, call build scripts, or query vulnerability feeds.

## Implementation-Specific Terms

### Parser-Only Scanner

The v0.1 model uses standard-library source discovery and `go/parser` without `golang.org/x/tools/go/packages`. Type-aware rules are deferred until their extra dependency and runtime cost are justified.

### Accepted Abbreviation

An initialism accepted by naming rules through `allowlists.acceptedAbbreviations`. Go convention commonly uses uppercase forms such as `ID`, `HTTP`, and `AST`.

### Composite Design Finding

A score-neutral `design.*` finding derived from already-emitted base findings. Current examples include god-function overlap and multi-pillar file hotspots; composite findings do not feed other composite rules.

### Default-Enabled Rule

Built-in default state before config is applied. `docs.config-field-comment` is opt-in by default; this repository's dogfood config may enable it, which is why `list-rules --no-config` matters.

### Gitignored Discovery Skip

A skipped-path record whose reason is `gitignored`. Discovery reads repository `.gitignore` files but not the user's global gitignore, `.git/info/exclude`, or external Git state.

### Go Flag Parsing

Go's standard `flag` package stops parsing at the first non-flag argument. Put CLI flags before paths unless a command explicitly documents otherwise.

## Agent Workflow Terms

### GOAT Flow

Local agent workflow framework installed from `@blundergoat/goat-flow`. It provides skills, audit commands, safety references, and `.goat-flow/` project-memory directories.

### Agent-Owned Surface

Files one agent setup owns without widening scope. Claude owns `CLAUDE.md` and `.claude/**`; Codex owns `AGENTS.md` and `.codex/**`; shared agent skills live under `.agents/skills/**`.

### Learning Loop

Durable shared project-memory directories under `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, and `.goat-flow/decisions/`.
