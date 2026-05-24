# Changelog


## [Unreleased]

### Changed

- `gruff-go init --force` is now a safe regenerate-with-merge: it parses the existing `.gruff-go.yaml`, splices `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, and every per-rule `enabled`/`severity`/`threshold`/`thresholds`/`options` override into the rendered output, then adds blocks for rules new to the registry at defaults. The legacy destructive overwrite is now opt-in via the new `--force --reset` combination. Prevents the dogfood-config wipe behaviour that previously destroyed project-specific tuning on every regenerate (see `.goat-flow/footguns/setup.md`).
- `docs.config-field-comment` remains default-enabled but now does nothing until `includePaths` is configured, preventing broad exported-field documentation noise while preserving opt-in checks for configuration schema files.
- Restored the dogfood `.gruff-go.yaml` tuning that was unintentionally wiped during a prior regenerate: 8-entry `paths.ignore` (`.agents/**`, `.antigravitycli/**`, `.claude/**`, `.codex/**`, `.github/**`, `.goat-flow/**`, `internal/rule/sensitive_test.go`, `internal/report/sensitive_redaction_test.go`), `allowlists.acceptedAbbreviations` (`ID, HTTP, JSON, CLI, AST`), the `docs.comment-rubric` strict `options:` block, `docs.exported-symbol-comment.options.ignoreInternalPackages: true`, `naming.identifier-quality.options.placeholderNames` list, tightened severities on `dead-code.empty-block`, `docs.config-field-comment`, `security.shell-command`, `size.parameter-count`, `test-quality.empty-test`, and tightened thresholds on `complexity.nesting-depth` (5 → 4) and `size.parameter-count` (8 → 5). Restores the dogfood scan to grade A.
- Split the `baseline` subcommand cluster (`runBaseline`, `baselineScanOptions`, `writeBaselineFromScan`) out of `internal/cli/cli.go` into `internal/cli/baseline.go`, mirroring the existing per-subcommand file pattern (`completion.go`, `dashboard.go`, etc.) and bringing `cli.go` back under the project's 500-line file-length threshold. No behavioural change.

### Added

- `gruff-go init --force --reset` flag combination performs the legacy destructive overwrite, wiping existing tuning and writing fresh registry defaults. Use only when you explicitly want a clean slate.

## [0.1.1] - 2026-05-24

### Fixed

- Local and CI Go commands now prefer Go 1.25.10 via `go.mod` toolchain metadata, clearing current standard-library `govulncheck` findings without suppressing the audit.

### Added

- `gruff-go init` subcommand writes a default `.gruff-go.yaml` to the working directory, mirroring the registry's per-rule enablement, severity, and threshold defaults. Pass `--force` to overwrite an existing file.
- `analyse`, `summary`, `report`, and `dashboard` prompt when no `.gruff-go.yaml` is found and offer to generate one. The prompt is skipped automatically when stdin is not a TTY (CI, scripts), when `--config` or `--no-config` are set, and when the new global `-n` / `--no-interaction` flag is supplied.
- `gruff-go analyse --generate-baseline <path>` writes a fresh-start baseline from a clean scan, rejecting baseline, diff, and display-filter flags that would make the generated file partial.
- Text summaries and setup output now point new users at the concrete `gruff-go analyse --generate-baseline gruff-baseline.json .` workflow, and text summaries show `.gitignore` skip counts when applicable.
- `scripts/dependency-install.sh` and `scripts/dependency-update.sh` install and refresh npm, Go module, and `govulncheck` dependencies for local development.
- `scripts/preflight-checks.sh` now verifies version metadata consistency, runs dependency audits, and supports `--release` to catch an unbumped source version before tagging.


## [0.1.0] - 2026-05-23

First public release of `gruff-go`, a parser-only Go code-quality scanner. CLI commands: `analyse`, `baseline`, `dashboard`, `report`, `summary`, `list-rules`. 41 rules across 9 pillars (40 default-on), strict `.gruff-go.yaml` config, baselines, diff-mode, gitignore-aware discovery, six output formats (text/json/summary-json/sarif/github/html), and a local HTML dashboard.

Schemas `gruff-go.analysis.v0.1`, `gruff-go.config.v0.1`, and `gruff-go.baseline.v0.1` are stable within `0.1.x`.

**Install:** `go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.1.0` (or `go get -tool ...@v0.1.0` on Go 1.24+). Prebuilt Linux/macOS/Windows binaries are attached to the GitHub Release.

Known limitations: parser-only (no type/SSA analysis yet); HTML dashboard accessibility review ongoing.

[Unreleased]: https://github.com/blundergoat/gruff-go/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/blundergoat/gruff-go/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/blundergoat/gruff-go/releases/tag/v0.1.0
