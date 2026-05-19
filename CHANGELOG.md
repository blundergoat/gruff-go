# Changelog

All notable changes to `gruff-go` are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **`sensitive-data.*` rules now skip Go comments and honor inline suppression annotations.** Lines that are entirely line comments (`//`) or wholly inside a `/* */` block no longer trigger findings, so doc snippets such as `// Format: postgres://user:password@host/db` are silent. Suppression keywords `#nosec` (gosec convention) and `//nolint:gosec` / `//nolint:all` (golangci-lint convention) on the same line also suppress findings.
- **`sensitive-data.connection-string` skips obvious dev/test placeholder credentials.** Connection URLs pointing at a localhost-style host (`localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, `db`, `database`, `postgres`) AND embedding a placeholder password (`change_me`, `changeme`, `your_password`, `placeholder`, `example`, `dummy`, `dev_password`, `test_password`, etc.) are no longer flagged. Both halves must match, so real-looking credentials at any of these hosts continue to fire. The redaction and metadata previews are unchanged.
- **`test-quality.no-failure-path` recognises assertion helpers.** Calls to functions whose name begins with `Assert`, `Require`, `Expect`, `Must`, or `Check` are accepted as failure paths when the testing receiver (`*testing.T` / `*testing.B` / `*testing.F`) is passed as one of the call arguments. This silences false positives on tests that delegate assertions to package-level helpers (e.g. `testutil.AssertStatus(t, ...)`). Tests that only call `MustX` without passing the receiver are still flagged.
- **`test-quality.skipped-test` distinguishes environment guards from debt.** Skip calls (`t.Skip` / `t.Skipf` / `t.SkipNow`) reachable only through an `if`/`for`/`switch`/`range`/`select` body are treated as legitimate "infrastructure not available" guards and no longer flagged. Skips remain flagged when (a) they are unconditional or (b) their string-literal message mentions a debt marker (`TODO`, `FIXME`, `XXX`, `HACK`, `WIP`, case-insensitive).
- **`size.function-length` measures code-bearing lines and honors `//nolint:funlen`.** The reported length now excludes blank lines and comment-only lines, computed via `go/scanner` over the source. The finding message changed from `"function has N lines, above threshold M"` to `"function has N code lines, above threshold M"`, and the metadata adds a `rawLines` field carrying the original span for compatibility. A `//nolint:funlen` (or `//nolint:all`) comment directly attached to the function's doc comment suppresses the rule for that function only.
- **`naming.get-prefix` covers free-function context accessors.** In addition to receiver methods, the rule now flags free functions whose single parameter is `context.Context` and that return one value (or one value + `error`) — the standard context-value accessor shape (`GetLogger(ctx)`, `GetRequestID(ctx)`). The message text changed from `"method ..."` to `"function ..."` and gains a `kind` metadata field (`receiver method` or `context accessor`).

### Added

- **`docs.comment-rubric` quality-floor option `minWordsBeyondSymbol`.** When set to a positive integer, the rule additionally requires the comment to contribute at least that many unique tokens beyond the symbol's own tokenised identifier set. Both inputs are tokenised with the same camel-case-aware splitter the acronym-case rule uses, then lowercased and de-duplicated. The check runs after the existing "comment normalises differently from the symbol" gate; both must pass. Default `0` (option off) preserves existing behaviour. Use this option to reject "name + filler" paraphrase boilerplate while still accepting substantive docs on short-named symbols.
- **`docs.config-field-comment` rule.** New default-disabled documentation rule that flags exported fields on struct types declared inside configured `includePaths` that have no useful doc comment. Embedded and unexported fields are out of scope. The "useful comment" check is shared with `docs.comment-rubric`. Intended for user-facing configuration schema types; projects opt in by enabling the rule and setting `includePaths`.

### Changed

- **`docs.comment-rubric` test-file scoping.** `requireConstComments` and `requireVarComments` no longer fire on `*_test.go` files even when `ignoreTests` is false. Function, named-type, and package-summary checks continue to apply on test files unless `ignoreTests: true`. The whole-file exemption via `ignoreTests: true` is unchanged.
- **`docs.comment-rubric` default `minPackageCommentLines` lowered from `2` to `1`.** A single-line `// Package foo …` summary now passes when `requirePackageSummary: true` and no threshold is configured. Projects with `threshold: 2` (including this repository's dogfood config) continue to use their configured value verbatim, so existing strict configurations are unaffected.

## [0.1.0] - 2026-05-19

First tagged release. The binary reports `0.1.0`. Schemas `gruff-go.analysis.v0.1`, `gruff-go.config.v0.1`, and `gruff-go.baseline.v0.1` are stable within the `0.1.x` line.

### Added

- **CLI** (`gruff-go`) with subcommands `analyse`, `baseline`, `dashboard`, `help`, `list`, `list-rules`, `report`, and `summary`. Exit codes: `0` clean, `1` findings at/above `--min-severity`, `2` diagnostics or invalid input.
- **Parser-only analysis pipeline.** `internal/source` discovers files, respects project `.gitignore` rules by default, records ignored files in `paths.skipped`, and skips generated files; `internal/parser` parses Go with `go/parser`; `internal/rule` dispatches rules deterministically; `internal/scoring` produces severity/confidence-weighted scores. No type-loader dependency; type-aware rules are deferred. See [`.goat-flow/decisions/ADR-001`](.goat-flow/decisions/ADR-001-parser-only-scanner-pipeline.md).
- **Rule catalogue (29 rules across 9 pillars).** All rules ship default-enabled (see ADR-007 below); projects opt out per-rule with `rules.<id>.enabled: false`. Grouped by pillar:
  - **complexity** — `complexity.cyclomatic`, `complexity.nesting-depth`.
  - **dead-code** — `dead-code.empty-block`.
  - **design** — `design.god-function`, `design.hotspot-file` (composite, score-neutral).
  - **documentation** — `docs.comment-rubric`, `docs.exported-symbol-comment`, `docs.package-comment`.
  - **naming** — `naming.acronym-case`, `naming.contextual-generic`, `naming.get-prefix`, `naming.identifier-quality`, `naming.misspelling`, `naming.negated-boolean`, `naming.package-stutter`, `naming.package-underscore`, `naming.receiver-consistency`.
  - **security** — `security.shell-command`.
  - **sensitive-data** — `sensitive-data.aws-access-key`, `sensitive-data.connection-string`, `sensitive-data.jwt-token`, `sensitive-data.private-key`, `sensitive-data.secret-pattern`.
  - **size** — `size.file-length`, `size.function-length`, `size.parameter-count`.
  - **test-quality** — `test-quality.empty-test`, `test-quality.no-failure-path`, `test-quality.skipped-test`.

  Full reference (severities, thresholds, remediation) in [`docs/rules.md`](docs/rules.md). Print the live registry with `gruff-go list-rules`.
- **Strict config** at `.gruff-go.yaml` (schema `gruff-go.config.v0.1`). Unknown keys, unknown rule IDs, unknown pillars, and invalid thresholds fail closed. Supports `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, `selection.{rules,excludeRules,pillars,excludePillars}`, and `rules.<id>.{enabled,threshold,thresholds,severity,options}`. Legacy hyphenated rule IDs (`size-file-length`) and `documentation.*` aliases are canonicalised on load. See [`.goat-flow/decisions/ADR-003`](.goat-flow/decisions/ADR-003-strict-json-operational-surfaces.md).
- **Baseline workflow.** `gruff-go baseline --out gruff-baseline.json` writes a fingerprinted snapshot; `analyse --baseline path` suppresses exact rule/file/fingerprint matches and reports stale entries. Schema `gruff-go.baseline.v0.1`.
- **Diff-mode scanning.** `analyse --diff-base <ref>` keeps line-located findings only on lines changed against the ref, with a recorded "changed-line scope, not full-project proof" caveat in the report.
- **Display filters.** `--include-rules`, `--exclude-rules`, `--include-pillars`, `--exclude-pillars` hide findings from rendering without affecting score or exit code. The filter caveat is preserved in the report so downstream consumers can detect partial display.
- **Output formats.** `text` (default), `json` (`gruff-go.analysis.v0.1`), `summary-json`, `sarif` (2.1.0), `github` (Actions annotations), and `html`. See [`docs/output-formats.md`](docs/output-formats.md).
- **HTML inspection report** (`--format html`). Self-contained document with inline CSS, the paper-on-near-black inspection aesthetic, tilted grade stamp, masthead, verdict + per-severity stats, pillar grid, top-offender table, cyclomatic histogram with summary line, findings list, footer. `--report-editor-link none|vscode|phpstorm` toggles editor-protocol anchors on file:line references.
- **Local dashboard** (`gruff-go dashboard`). Serves the HTML report inside an iframe at `127.0.0.1:8765` with a controls panel for project, paths, config, baseline, scope, fail-on, and the interactive findings toggle. `--allow-public` gates non-loopback binds (refusal by default). `--scan-timeout` enforces a per-scan deadline; the iframe receives a dashboard-error document on timeout.
- **Interactive findings filter** (`--report-interactive`). Inline filter form inside the HTML report — severity multi-select, pillar multi-select, path / search inputs, group-by file/rule, clear-all, live count via `aria-live="polite"`. URL hash mirrors filter state so deep-links and reload survive. The static report still emits `data-severity / data-pillar / data-file / data-rule / data-search` attributes whether or not the script ships.
- **Gitignore-respecting discovery.** `analyse`, `baseline`, `summary`, and dashboard scans skip project `.gitignore` matches by default, expose `gitignored` skip reasons in JSON output, and accept `--include-ignored` when the caller intentionally wants the older broad scan boundary. See [ADR-004](.goat-flow/decisions/ADR-004-gitignore-respecting-discovery.md) and [ADR-005](.goat-flow/decisions/ADR-005-gitignore-matcher-implementation.md).
- **Scoring.** Severity- and confidence-weighted penalties produce a 0–100 composite plus a letter grade (`A`–`F`). The score object surfaces per-pillar scores, per-pillar grade letters with severity breakdowns, top-5 offender files with per-file findings/grade/max-cyclomatic, a `1-5 / 6-10 / 11-15 / 16-20 / 21+` cyclomatic distribution, `score.coverage` to make narrow score coverage explicit, and `score.complexityDistributionScope` to label the histogram as finding-only.
- **Repository hygiene.** `Makefile` `check` target wraps `go fmt`, `go vet`, `go test ./...`. Strict `gofmt` / `go vet ./...` / `make check` gates kept clean throughout v0.1 work. Self-dogfood (`go run ./cmd/gruff-go analyse .`) returns grade A with zero findings.
- **Release tooling.** `scripts/bump-version.sh <new-version>` updates every in-tree version literal (CLI const, analysis report, SARIF driver assertion, `package.json`) and regenerates the CLI golden snapshots in one shot, then prints a sanity-sweep of any remaining stale references.

### Changed

- **Default policy: every shipped rule is `defaultEnabled: true`.** ADR-002's narrow 5-rule pack (`complexity.cyclomatic`, `docs.package-comment`, `sensitive-data.secret-pattern`, `size.file-length`, `size.function-length`) is superseded by [ADR-007](.goat-flow/decisions/ADR-007-comprehensive-default-rule-pack.md). Adopters now get the full 29-rule catalogue out of the box; disable per rule via `rules.<id>.enabled: false`. Severity discipline keeps default `--min-severity medium` CI gates stable — most flipped rules are `low` severity (naming.*, test-quality.*, dead-code.empty-block, docs.*, size.parameter-count, design composites) and appear in reports without flipping exit code. Fingerprints, baseline schema, exit-code semantics, JSON schema version, and rule IDs are unchanged.
- **Threshold defaults moved toward industry-mainstream values.** `complexity.nesting-depth` `maxDepth` `4 → 5` (matches `nestif`); `size.parameter-count` `maxParameters` `5 → 8` (matches revive `argument-limit`); `size.file-length` `maxLines` `400 → 500`. Calibration on a real Go corpus showed `400` was dominated by line-count findings while the production handler size signal is preserved at `500`. Projects pinning the older thresholds in `.gruff-go.yaml` keep the stricter policy.
- **Test-file size downranking.** Default `size.file-length` and `size.function-length` findings in `_test.go` files keep the same thresholds, messages, metadata, and fingerprints, but report as `low` severity / `medium` confidence under medium severity. Explicit non-medium config severity overrides still apply to test files.
- `docs.package-comment` skips `_test.go`-only external test packages such as `package foo_test`, reducing documentation noise from black-box test packages while preserving production package-comment checks.
- **Dashboard field rename: `Options.NoConfig` → `SkipConfig` and `Options.NoBaseline` → `SkipBaseline`** in `internal/dashboard` and `internal/report`, along with all internal references. **CLI flag names `--no-config` and `--no-baseline` are unchanged** (public surface), and URL hash parameter names `noConfig`/`noBaseline` are unchanged (deep-link compatibility). Only the internal Go field names moved to match the positive form recommended by `naming.negated-boolean`.

### Rule additions during v0.1 development

These rules joined the catalogue after the initial 21-rule pack and are included in the v0.1.0 release:

- **`docs.comment-rubric`** — path-scoped maintainer-comment rule. Files listed in its `includePaths` option are checked for a package summary plus directly attached comments on functions, named types, package-scope constants, and package-scope variables. Without configured paths it is a no-op, so its default-on status is harmless on adoption.
- **`naming.acronym-case`** — flags identifiers that spell Go initialisms (`Id`, `Http`, `Url`, `Json`, `Api`, `Xml`, …) with mixed casing. `allowlists.acceptedAbbreviations` suppresses project-specific terms; the rule-local `allow` list handles exact third-party or generated API names that must stay as-is.
- **`naming.get-prefix`** — flags accessor-style receiver methods using a discouraged `Get` prefix (`r.GetName()`). Non-method functions and named getters that disambiguate from a state mutation are left alone.
- **`naming.receiver-consistency`** — project-level rule that groups methods by receiver type across the scanned project, strips leading `*`, and flags methods using the minority receiver name or pointer/value form.
- **`naming.negated-boolean`** — flags boolean identifiers whose names begin with negation prefixes (`No`, `Not`, `Disable`, `Disallow`, `Without`, `Suppress`) followed by an uppercase letter. Type-aware: only flags identifiers whose syntactic type is `bool`. Configurable `prefixes`, `allowList`, and `scope` (`exported` default, `locals`, `all`). The default `allowList` covers English words like `NoOp`, `Notify`, `NoCopy`.
- **`naming.misspelling`** — flags identifiers, doc comments, and struct tags containing tokens from a conservative built-in dictionary of common programming misspellings (`recieve`, `seperate`, `lenght`, `occured`, `enviroment`, etc., ~40 entries). Tokens are extracted with camelCase / snake_case / non-letter splitting and matched exactly. Configurable `extra map[string]string` for project additions and `ignore []string` for proper nouns.
- **`naming.package-stutter`** — flags exported top-level types, non-method functions, and package-scope variables/constants whose lowercase form starts with their own package name (`rule.RuleRegistry`, `httpserver.HttpServerOptions`, `config.ConfigOptions`). Catches both exact-match stutter (allowlisted by default for `Config`, `Finding` per Go community convention) and prefix-then-uppercase stutter. Plain word extensions like `type Rules` in `package rule` do not fire. Method names are not checked. Configurable `allowStutter []string`.
- **`naming.contextual-generic`** — flags identifiers like `result`, `data`, `value`, `item`, `entry`, `temp`, `info`, `obj` only when the surrounding loop or function is large enough that the context no longer disambiguates them. Thresholds: `minBodyLines: 15` for the enclosing block, `minFunctionLines: 50` for the enclosing function. Configurable `genericNames`, `minBodyLines`, `minFunctionLines`.

### Known limitations

- Calibration is single-corpus (this repository) plus fixtures. No second real Go corpus has been used to validate threshold defaults.
- The analysis model is parser-only. Type-aware rules, external linter ingestion, trend storage, package publication, and CI release workflow remain deferred.
- Accessibility evidence for the HTML report and dashboard (Lighthouse, WCAG contrast, screen-reader walk, colour-blind sim) is pending human review.

### Engineering history

The v0.1 foundation was built across twelve implementation milestones tracked in `.goat-flow/tasks/0.1/`; M13-M17 contain research and roadmap follow-up:

- **M01 — Prove Go rubric and layout.** Validated repo state, translated the reference rubric into Go-native rule candidates, secured approval for the v0.1 source layout, recorded the parser-only-vs-package-loader spike.
- **M02 — Build scanner foundation.** Added `cmd/gruff-go`, `internal/{source,parser,rule,analysis,report,scoring}`. First clean `go test ./...` on a real parser pipeline.
- **M03 — Ship Go rule pack and scoring.** Five default-enabled MVP rules, severity-weighted scoring, top-offender list.
- **M04 — Add config, diff, baseline, and reports.** Strict `.gruff-go.yaml` config, `git diff --unified=0`-driven changed-line filtering, JSON baselines, summary JSON, SARIF 2.1.0, GitHub annotations. Recorded as [ADR-003](.goat-flow/decisions/ADR-003-strict-json-operational-surfaces.md).
- **M05 — Dogfood, calibrate, and document.** Repository self-scan hardened, threshold defaults tuned, glossary and architecture docs aligned with shipped behaviour.
- **M06 — Core rubric expansion rules.** Default-disabled `complexity.nesting-depth`, `size.parameter-count`, `docs.exported-symbol-comment` with fixtures and dogfood coverage.
- **M07 — Sensitive-naming and test rubrics.** Default-disabled sensitive-data, naming, and test-quality expansion rules with redaction and rule-option validation.
- **M08 — Composite design and default policy.** Project-level composite design findings and the default policy table tuned from dogfood data.
- **M09 — HTML report visual parity.** Self-contained HTML reporter, paper-frame aesthetic, tilted grade stamp, seven section sequence, `--format html` and `--report-editor-link` flags. `internal/scoring` extended with `PillarDetails`, `ComplexityDistribution`, and enriched `FileScore` (`Findings`, `Grade`, `MaxCyclomatic`).
- **M10 — Local dashboard server.** `gruff-go dashboard` subcommand. `net/http` shell with cog-button controls panel, iframe-rendered report, `postMessage` scan-complete hand-off, signal-driven shutdown, loopback-default bind with explicit public gate.
- **M11 — Interactive findings and accessibility.** Inline filter UI with URL-hash state, data attributes on every finding row, `--report-interactive` flag, dashboard checkbox wiring.
- **M12 — Gitignore-respecting discovery.** Default scan boundary now follows project `.gitignore` files with `--include-ignored` as the explicit opt-out.
- **M24 — Naming pack expansion.** Phases 5-7 added `naming.negated-boolean`, `naming.misspelling`, and `naming.package-stutter`. A follow-up commit added `naming.contextual-generic`. Earlier in v0.1 an unnumbered batch added `naming.acronym-case`, `naming.get-prefix`, `naming.receiver-consistency`, and `docs.comment-rubric`, taking the catalogue from 21 → 25 → 26 → 28 → 29 rules en route to release.

[Unreleased]: https://github.com/blundergoat/gruff-go/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/blundergoat/gruff-go/releases/tag/v0.1.0
