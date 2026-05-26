# Changelog


## [Unreleased]

### Added
- `minimumSeverity:` per-command threshold block in `.gruff-go.yaml` exposes per-command exit-code policy without requiring `--min-severity` on every invocation. Keys: `analyse`, `summary`, `report`, `dashboard`. Values: `advisory | warning | error | none`. `none` is a new "report findings, never exit 1" sentinel for artifact-generation commands (`report`, `dashboard`). Precedence: CLI flag wins over the config block; the config block wins over the binary default. The binary defaults match the user-philosophy "gate on anything for CI, never gate for viewers": `analyse: advisory`, `summary: advisory`, `report: none`, `dashboard: none`. Additive and optional - existing configs continue to load unchanged. **No schema bump.** See [ADR-010](.goat-flow/decisions/ADR-010-per-command-minimum-severity.md).
- `finding.FailThreshold` type and `finding.DefaultFailThresholdFor(cmd)` helper. Both the analysis runner fallback and the dashboard state default consume the helper, so future per-command default changes touch one function instead of four call sites - closes the lockstep footgun in `.goat-flow/footguns/severity.md` by construction.

### Fixed
- Three stale-default bugs from PR #3: `internal/cli/summary.go::runSummary` and `internal/cli/report.go::runReport` no longer hard-code `SeverityWarning`; `internal/analysis/runner.go::normalizeOptions` no longer falls back to `SeverityWarning` for programmatic callers; `internal/dashboard/state.go::defaultState` no longer hard-codes the post-ADR-009-unparseable string `"medium"`. All four sites now route through `finding.DefaultFailThresholdFor`.

## [0.1.2] - 2026-05-25

### Breaking

- Severity model collapses from 5 buckets to 3 (`advisory`, `warning`, `error`), matching gruff-rs, gruff-ts, gruff-py, and gruff-php. The old names (`critical`, `high`, `medium`, `low`, `info`, `notice`, `warn`) are no longer accepted — existing `.gruff-go.yaml` files using them fail to load with `unknown severity "<name>"`. Mapping: `critical` + `high` → `error`; `medium` + `warn` → `warning`; `low` + `notice` → `advisory`; `info` is dropped (no rule emitted it). See [ADR-009](.goat-flow/decisions/ADR-009-three-severity-model.md).
- Default `--min-severity` (and its `--fail-on` alias) lowers from `medium` to `advisory`, so default scans now surface every applicable finding. CI gates that previously failed only on `medium`+ should pass `--min-severity warning` to retain the prior behaviour.
- Analysis schema bumps `gruff-go.analysis.v0.1` → `gruff-go.analysis.v0.2`. The keys in `Report.Summary.CountsBySeverity` and the `PillarDetail.{Critical,High,Medium,Low,Info}` fields change shape; consumers should re-pin against `v0.2`.
- Per-severity penalty weights collapse from `1 / 3 / 8 / 15 / 30` to `1 / 8 / 30` for `advisory / warning / error`. Pillar scores shift at the margin; CLI golden snapshots are regenerated in the same release.

### Added

- The canonical `gruff.summary.v2` JSON pillar object and the analyse `pillarDetails` entries now carry a `penalty` field. Penalty is the raw, unclamped score deduction accumulated for the pillar (score is still `max(0, 100 - penalty)`), preserving the worst-pillar ranking signal when scores floor at zero (e.g. a pillar with 200 advisory findings reports penalty=200, score=0, distinct from a pillar with 1 error finding reporting penalty=30, score=70). Text, markdown, and HTML pillar tables are unchanged.
- `analyse --format=markdown` (alias `md`) renders a CommonMark-flavoured digest tuned for CI logs and GitHub PR comments. The output includes a short header, severity totals, the canonical 7-column Pillars table (pillar, grade, score, findings, advisory, warning, error sorted by findings descending then pillar ascending), and a compact top-rules block when findings exist.
- `scripts/publish-go-pkg.sh` publishes a tagged Go module release, verifies the tag against source metadata, warms `proxy.golang.org`, and checks a temporary `go install`.
- `summary` now renders the cross-port canonical `Pillars` block in text output, listing every applicable pillar with grade, score, and per-severity counts sorted by findings descending. The text block always covers all ten gruff-go pillars so clean scans surface as grade A rows with zero findings.
- New `gruff-go.summary.v0.1` schema for `summary --format=json`. The dedicated digest payload exposes `schemaVersion` and a `pillars` array with `grade`, `score`, `applicable`, and per-severity counts. The heavier `analyse --format=summary-json` output continues to use `gruff-go.analysis.v0.2`.
- `analyse --format=html` now renders the canonical Pillars table (pillar, grade, score, findings, advisory, warning, error) shared with the text and JSON summaries. The table covers every applicable pillar sorted by findings descending then pillar ascending, so clean scans surface as grade A rows with score 100.00 and zero counts.
- Added [ADR-009](.goat-flow/decisions/ADR-009-three-severity-model.md) capturing the cross-port severity-model migration: rationale, mapping table, rejected alternatives, and the schema-bump and golden-regeneration plan.

### Changed

- `summary --format=json` no longer reuses the analysis schema. Existing consumers should migrate to either `analyse --format=summary-json` (full analysis payload at `gruff-go.analysis.v0.2`) or the new `gruff-go.summary.v0.1` digest.
- The HTML report's per-pillar section now renders as a 7-column table replacing the previous card grid. Scores render with two decimal places to match the canonical Pillars block, and every applicable pillar is always shown (clean pillars surface as grade A rows with zero counts).
- `allowlists.acceptedAbbreviations` validation now rejects only blank entries; the previous validator required every entry to be uppercase. Entries are normalised to lowercase before matching, so both `ID` and `id` resolve to the same allowlist key. Documented in `.goat-flow/footguns/setup.md`, including that rule consumers must read the normalised list rather than the raw config and that `acceptedAbbreviations` carries different rule-consumer semantics in gruff-go than in sibling ports.
- `.gruff-go.yaml` per-rule overrides migrate from the old severity vocabulary to the new one (`notice` → `advisory`, `critical` → `error`) as part of the 5→3 collapse; the dogfood configuration remains grade A under the new defaults.

## [0.1.1] - 2026-05-24

### Fixed

- Interactive config bootstrap prompt and status text now write to stderr, keeping JSON and HTML stdout clean for redirection and machine consumers.
- `gruff-go init --reset` now fails unless `--force` is also supplied, matching the documented destructive-reset contract.
- Fresh-start summary hints now quote shell-sensitive input paths before rendering copy/paste commands.
- `gruff-go completion` now reports completion-script write failures instead of returning success after a failed stdout write.
- Local and CI Go commands now prefer Go 1.25.10 via `go.mod` toolchain metadata, clearing current standard-library `govulncheck` findings without suppressing the audit.
- `security.permissive-file-mode` no longer flags `os.OpenFile` calls whose flags are statically known to omit `O_CREATE`, since the kernel ignores the mode argument in that case. Opaque (variable or function-call) flag expressions still flag conservatively to avoid false negatives.
- `scripts/preflight-checks.sh` now skips the `package.json`/`package-lock.json` version check when `node` is not installed in local mode, matching the existing `SKIP_EXIT` behaviour of `check_npm_audit` and `check_go_vuln`. `--release` mode still hard-fails so release-time invariants stay strict.
- Renamed ten `internal/rule/*_m[07|08|37|38]*.go` files to topic-based names (`security_hardening_defaults.go`, `security_sql_and_archive_test.go`, `security_crypto_strength_test.go`, `maintainability_runtime_pitfalls.go`, `test_quality_helper_and_parallel.go`, `test_quality_async_and_tempdir.go`, and their `_test.go` peers). The prior `_m08`/`_m37`/`_m38` filenames survived an earlier milestone-identifier cleanup that only touched markdown and doc comments.

### Changed

- `gruff-go init --force` is now a safe regenerate-with-merge: it parses the existing `.gruff-go.yaml`, splices `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, and every per-rule `enabled`/`severity`/`threshold`/`thresholds`/`options` override into the rendered output, then adds blocks for rules new to the registry at defaults. The legacy destructive overwrite is now opt-in via `--force --reset`.
- `docs.config-field-comment` remains default-enabled but now does nothing until `includePaths` is configured, preventing broad exported-field documentation noise while preserving opt-in checks for configuration schema files.
- Rule pillar metadata now treats `design.hotspot-file` as a maintainability signal and `naming.get-prefix` as a modernisation signal, so pillar counts better match how the findings are used.
- Restored the dogfood `.gruff-go.yaml` tuning that was unintentionally wiped during a prior regenerate, bringing the dogfood scan back to grade A.
- Split the `baseline` subcommand cluster (`runBaseline`, `baselineScanOptions`, `writeBaselineFromScan`) out of `internal/cli/cli.go`, mirroring the existing per-subcommand file pattern and bringing `cli.go` back under the project's 500-line file-length threshold. No behavioural change.
- Documented that `allowlists.secretPreviews` controls preview redaction only and does not suppress sensitive-data findings; use rule exclusions, path ignores, or inline suppressions when a finding should be intentionally hidden.
- Removed the parser-only-as-architectural-commitment ADR. v0.1 rules still report `parser` capability; future rules that need type or SSA capability declare the higher tier and depend on matching runtime support landing.
- Rewrote tracked ADRs, footguns, `CONTRIBUTING.md`, `docs/output-formats.md`, and the `config_field_comment_test.go` doc comment to remove references to internal milestone identifiers (`M01`-`M38`).
- Refactored `dashboard.Serve` to close the new `Ready` channel after the listener binds and the start-up banner prints; `TestServeShutsDownOnContextCancel` now waits on `Ready` instead of sleeping 50ms before cancelling.
- `test-quality.parallel-range-capture` now reports only when the nearest `go.mod` declares `go < 1.22`; modules using Go 1.22+ range-loop semantics, and files with no module metadata, are treated as out of scope.
- `analyse`, `summary`, and `report` now accept `--fail-on` as an alias for `--min-severity`, matching the dashboard flag name and the broader gruff-family CLI vocabulary.
- Global CLI parsing now accepts `--silent` as an alias for `--quiet` and accepts Symfony-style verbosity flags (`-v`, `-vv`, `-vvv`, `--verbose`) for parity; verbosity flags are currently no-ops.
- `scripts/bump-version.sh` now updates `package-lock.json` as well as `package.json`, validates package metadata with Node, checks anchored version literals before editing, regenerates CLI goldens, and scans tracked source for stale version references while excluding historical/agent surfaces.
- CI and release workflows now use `go-version: 1.25.x`, install Node 22 and `govulncheck`, pin `actions/setup-node` to an immutable commit, and run release preflight in `--release` mode before publishing. The release preflight job no longer restores an npm cache.
- README and release documentation were reorganised around the project-pinned `go tool gruff-go` workflow, current command surface, trust boundary, dashboard defaults, stability contract, and release checklist.
- The npm lockfile was refreshed while bumping release metadata, updating locked tooling dependencies such as `markdown-it`, `linkify-it`, and `ws`.

### Added

- Added 23 default-enabled parser rules, bringing the Go catalogue to 64 rules: `complexity.cognitive`, `complexity.npath`, `dead-code.unreachable-code`, `dead-code.unused-private-function`, `docs.suppression-without-rationale`, `maintainability.context-todo-production`, `maintainability.defer-in-loop`, `maintainability.ignored-error`, `maintainability.log-fatal-library`, `maintainability.loop-variable-address`, `maintainability.production-panic`, `modernisation.ioutil-deprecated`, `security.http-client-no-timeout`, `security.http-server-no-timeout`, `security.permissive-file-mode`, `security.request-body-without-limit`, `sensitive-data.gitlab-token`, `sensitive-data.npm-token`, `test-quality.fatal-in-goroutine`, `test-quality.helper-missing-t-helper`, `test-quality.parallel-range-capture`, `test-quality.sleep-in-test`, and `test-quality.tempdir-misuse`.
- `gruff-go init` subcommand writes a default `.gruff-go.yaml` to the working directory, mirroring the registry's per-rule enablement, severity, and threshold defaults. Pass `--force` to overwrite an existing file.
- `gruff-go init --force --reset` performs the legacy destructive overwrite, wiping existing tuning and writing fresh registry defaults. Use only when you explicitly want a clean slate.
- `analyse`, `summary`, `report`, and `dashboard` prompt when no `.gruff-go.yaml` is found and offer to generate one. The prompt is skipped automatically when stdin is not a TTY (CI, scripts), when `--config` or `--no-config` are set, and when the new global `-n` / `--no-interaction` flag is supplied.
- `gruff-go analyse --generate-baseline <path>` writes a fresh-start baseline from a clean scan, rejecting baseline, diff, and display-filter flags that would make the generated file partial.
- `gruff-go completion [bash|zsh|fish]` emits static shell completion scripts for the supported shells.
- Text summaries and setup output now point new users at the concrete `gruff-go analyse --generate-baseline gruff-baseline.json .` workflow, and text summaries show `.gitignore` skip counts when applicable.
- `scripts/dependency-install.sh` and `scripts/dependency-update.sh` install and refresh npm, Go module, and `govulncheck` dependencies for local development.
- `scripts/preflight-checks.sh` now verifies version metadata consistency, runs `npm audit`, runs `govulncheck` when available, and supports `--release` to catch an unbumped source version before tagging.
- Added `docs/README.md` as a documentation index and `docs/releasing.md` as the release checklist.
- `dashboard.Options.Ready` is an optional `chan<- struct{}` that closes once the listener has bound and the start-up banner has been written. Tests and supervised launchers use it to synchronise teardown without polling or sleeping.


## [0.1.0] - 2026-05-23

First public release of `gruff-go`, a parser-only Go code-quality scanner. CLI commands: `analyse`, `baseline`, `dashboard`, `report`, `summary`, `list-rules`. 41 rules across 9 pillars (40 default-on), strict `.gruff-go.yaml` config, baselines, diff-mode, gitignore-aware discovery, six output formats (text/json/summary-json/sarif/github/html), and a local HTML dashboard.

Schemas `gruff-go.analysis.v0.1`, `gruff-go.config.v0.1`, and `gruff-go.baseline.v0.1` are stable within `0.1.x`.

**Install:** `go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.1.0` (or `go get -tool ...@v0.1.0` on Go 1.24+). Prebuilt Linux/macOS/Windows binaries are attached to the GitHub Release.

Known limitations: parser-only (no type/SSA analysis yet); HTML dashboard accessibility review ongoing.

[Unreleased]: https://github.com/blundergoat/gruff-go/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/blundergoat/gruff-go/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/blundergoat/gruff-go/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/blundergoat/gruff-go/releases/tag/v0.1.0
