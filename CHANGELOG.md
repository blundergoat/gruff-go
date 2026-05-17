# Changelog

All notable changes to `gruff-go` are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Pre-release foundation. The binary reports `0.1.0-dev`. The CLI surface, schemas, and config shape are versioned but may shift before the first tagged release.

### Added

- **CLI** (`gruff-go`) with subcommands `analyse`, `baseline`, `list-rules`, `dashboard`, and `help`. Exit codes: `0` clean, `1` findings at/above `--min-severity`, `2` diagnostics or invalid input.
- **Parser-only analysis pipeline.** `internal/source` discovers files, respects project `.gitignore` rules by default, records ignored files in `paths.skipped`, and skips generated files; `internal/parser` parses Go with `go/parser`; `internal/rule` dispatches rules deterministically; `internal/scoring` produces severity/confidence-weighted scores. No type-loader dependency; type-aware rules are deferred. See [`.goat-flow/decisions/ADR-001`](.goat-flow/decisions/ADR-001-parser-only-scanner-pipeline.md).
- **Rule catalogue (21 rules across 9 pillars).** Default-enabled: `complexity.cyclomatic`, `docs.package-comment`, `sensitive-data.secret-pattern`, `size.file-length`, `size.function-length`. Opt-in: `complexity.nesting-depth`, `dead-code.empty-block`, `design.god-function`, `design.hotspot-file`, `docs.exported-symbol-comment`, `naming.identifier-quality`, `naming.package-underscore`, `security.shell-command`, `sensitive-data.aws-access-key`, `sensitive-data.connection-string`, `sensitive-data.jwt-token`, `sensitive-data.private-key`, `size.parameter-count`, `test-quality.empty-test`, `test-quality.no-failure-path`, `test-quality.skipped-test`. Full reference in [`docs/rules.md`](docs/rules.md).
- **Strict config** at `.gruff.yaml` / `.gruff.yml` / `.gruff.json` (schema `gruff-go.config.v0.1`). Unknown keys, unknown rule IDs, unknown pillars, and invalid thresholds fail closed. Supports `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, `selection.{rules,excludeRules,pillars,excludePillars}`, and `rules.<id>.{enabled,threshold,thresholds,severity,options}`. See [`.goat-flow/decisions/ADR-003`](.goat-flow/decisions/ADR-003-strict-json-operational-surfaces.md).
- **Baseline workflow.** `gruff-go baseline --out gruff-baseline.json` writes a fingerprinted snapshot; `analyse --baseline path` suppresses exact rule/file/fingerprint matches and reports stale entries. Schema `gruff-go.baseline.v0.1`.
- **Diff-mode scanning.** `analyse --diff-base <ref>` keeps line-located findings only on lines changed against the ref, with a recorded "changed-line scope, not full-project proof" caveat in the report.
- **Display filters.** `--include-rules`, `--exclude-rules`, `--include-pillars`, `--exclude-pillars` hide findings from rendering without affecting score or exit code. The filter caveat is preserved in the report so downstream consumers can detect partial display.
- **Output formats.** `text` (default), `json` (`gruff-go.analysis.v0.1`), `summary-json`, `sarif` (2.1.0), `github` (Actions annotations), and `html`. See [`docs/output-formats.md`](docs/output-formats.md).
- **HTML inspection report** (`--format html`). Self-contained document with inline CSS, the paper-on-near-black inspection aesthetic, tilted grade stamp, masthead, verdict + per-severity stats, pillar grid, top-offender table, cyclomatic histogram with summary line, findings list, footer. `--report-editor-link none|vscode|phpstorm` toggles editor-protocol anchors on file:line references.
- **Local dashboard** (`gruff-go dashboard`). Serves the HTML report inside an iframe at `127.0.0.1:8765` with a controls panel for project, paths, config, baseline, scope, fail-on, and the interactive findings toggle. `--allow-public` gates non-loopback binds (refusal by default). `--scan-timeout` enforces a per-scan deadline; the iframe receives a dashboard-error document on timeout.
- **Interactive findings filter** (`--report-interactive`). Inline filter form inside the HTML report — severity multi-select, pillar multi-select, path / search inputs, group-by file/rule, clear-all, live count via `aria-live="polite"`. URL hash mirrors filter state so deep-links and reload survive. The static report still emits `data-severity / data-pillar / data-file / data-rule / data-search` attributes whether or not the script ships.
- **Gitignore-respecting discovery.** `analyse`, `baseline`, `summary`, and dashboard scans skip project `.gitignore` matches by default, expose `gitignored` skip reasons in JSON output, and accept `--include-ignored` when the caller intentionally wants the older broad scan boundary.
- **Scoring.** Severity- and confidence-weighted penalties produce a 0–100 composite plus a letter grade (`A`–`F`). The score object surfaces per-pillar scores, per-pillar grade letters with severity breakdowns, top-5 offender files with per-file findings/grade/max-cyclomatic, and a `1-5 / 6-10 / 11-15 / 16-20 / 21+` cyclomatic distribution.
- **Repository hygiene.** `Makefile` `check` target wraps `go fmt`, `go vet`, `go test ./...`. Strict `gofmt` / `go vet ./...` / `make check` gates kept clean throughout v0.1 work. Self-dogfood (`go run ./cmd/gruff-go analyse .`) returns grade A with zero findings.

### Changed

- Default `size.file-length` and `size.function-length` findings in `_test.go` files keep the same thresholds, messages, metadata, and fingerprints, but report as `low` severity / `medium` confidence under medium severity. Explicit non-medium config severity overrides still apply to test files.
- `docs.package-comment` skips `_test.go`-only external test packages such as `package foo_test`, reducing documentation noise from black-box test packages while preserving production package-comment checks.
- Score output now includes `score.coverage` and `score.complexityDistributionScope`. Text, summary, JSON, and HTML reports make narrow score coverage explicit, and the cyclomatic histogram is labelled as finding-only.

### Known limitations

- Calibration is still single-corpus plus fixtures; no expansion rule was moved to default-enabled without a second real Go corpus or explicit human accepted-risk approval.
- The analysis model is parser-only. Type-aware rules, external linter ingestion, trend storage, package publication, and CI release workflow remain deferred.

### Engineering history

The pre-release foundation was built across twelve implementation milestones tracked in `.goat-flow/tasks/0.1/`; M13-M17 contain research and roadmap follow-up:

- **M01 — Prove Go rubric and layout.** Validated repo state, translated the reference rubric into Go-native rule candidates, secured approval for the v0.1 source layout, recorded the parser-only-vs-package-loader spike.
- **M02 — Build scanner foundation.** Added `cmd/gruff-go`, `internal/{source,parser,rule,analysis,report,scoring}`. First clean `go test ./...` on a real parser pipeline.
- **M03 — Ship Go rule pack and scoring.** Five default-enabled MVP rules, severity-weighted scoring, top-offender list.
- **M04 — Add config, diff, baseline, and reports.** Strict `.gruff.yaml`/`.json` config, `git diff --unified=0`-driven changed-line filtering, JSON baselines, summary JSON, SARIF 2.1.0, GitHub annotations. Recorded as [ADR-003](.goat-flow/decisions/ADR-003-strict-json-operational-surfaces.md).
- **M05 — Dogfood, calibrate, and document.** Repository self-scan hardened, threshold defaults tuned, glossary and architecture docs aligned with shipped behaviour.
- **M06 — Core rubric expansion rules.** Default-disabled `complexity.nesting-depth`, `size.parameter-count`, `docs.exported-symbol-comment` with fixtures and dogfood coverage.
- **M07 — Sensitive-naming and test rubrics.** Default-disabled sensitive-data, naming, and test-quality expansion rules with redaction and rule-option validation.
- **M08 — Composite design and default policy.** Project-level composite design findings and the default policy table tuned from dogfood data.
- **M09 — HTML report visual parity.** Self-contained HTML reporter, paper-frame aesthetic, tilted grade stamp, seven section sequence, `--format html` and `--report-editor-link` flags. `internal/scoring` extended with `PillarDetails`, `ComplexityDistribution`, and enriched `FileScore` (`Findings`, `Grade`, `MaxCyclomatic`).
- **M10 — Local dashboard server.** `gruff-go dashboard` subcommand. `net/http` shell with cog-button controls panel, iframe-rendered report, `postMessage` scan-complete hand-off, signal-driven shutdown, loopback-default bind with explicit public gate.
- **M11 — Interactive findings and accessibility.** Inline filter UI with URL-hash state, data attributes on every finding row, `--report-interactive` flag, dashboard checkbox wiring. Accessibility evidence (Lighthouse, WCAG contrast, screen-reader walk, colour-blind sim) is pending human review.
- **M12 — Gitignore-respecting discovery.** Default scan boundary now follows project `.gitignore` files with `--include-ignored` as the explicit opt-out.

## [0.1.0-dev]

Snapshot date placeholder: this file will be updated with the pinned `0.1.0` date once the first tagged release goes out.
