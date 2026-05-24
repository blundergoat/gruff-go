# Changelog


## [Unreleased]

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

[Unreleased]: https://github.com/blundergoat/gruff-go/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/blundergoat/gruff-go/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/blundergoat/gruff-go/releases/tag/v0.1.0
