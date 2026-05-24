# Changelog


## [Unreleased]

### Added

- `test-quality.sleep-in-test` flags `time.Sleep` call sites inside `_test.go` files. Sleeps are the dominant cause of flaky Go tests; the rule directs maintainers toward channel- or fake-clock-based synchronisation. Low severity, parser capability.
- `complexity.npath` flags functions whose acyclic-path count (modified NPath) exceeds the configured threshold. The formula treats `return`, `panic`, `os.Exit`, `log.Fatal*`, and `runtime.Goexit` as terminating so idiomatic Go error-as-value chains grow linearly; nested switches and multi-way if/else without terminators still flag. Default threshold `1024` (medium severity, parser capability). `gruff-go`'s own dogfood config raises the threshold to `9000` because the scanner's dispatchers (rule registry, config validators, comment-rubric aggregator) have legitimately wide branch fan-out.
- `dead-code.unused-private-function` flags package-private (lowercase-leading) top-level functions whose names are not referenced anywhere else in the same parsed package. The rule is project-level and precision-first: methods, `init`/`main`, external `_test` packages, and packages that import `reflect` are excluded. Low severity, parser capability.
- `dashboard.Options.Ready` is an optional `chan<- struct{}` that closes once the listener has bound and the start-up banner has been written. Tests and supervised launchers use it to synchronise teardown without polling or sleeping.

### Changed

- Removed the parser-only-as-architectural-commitment ADR. v0.1 rules still report `parser` capability — that is now documented as the current runtime state rather than a binding design ceiling. Future rules that need type or SSA capability declare the higher tier and depend on the matching runtime support landing.
- Rewrote tracked ADRs, footguns, `CONTRIBUTING.md`, `docs/output-formats.md`, and the `config_field_comment_test.go` doc comment to remove references to internal milestone identifiers (`M01`–`M38`). Milestone task files live under the workspace-local `.goat-flow/tasks/` directory which is gitignored, so external readers had no way to resolve those references.
- Refactored `dashboard.Serve` to close the new `Ready` channel after the listener binds and the start-up banner prints; `TestServeShutsDownOnContextCancel` now waits on `Ready` instead of sleeping 50ms before cancelling, eliminating a long-standing flake-prone pattern.
- `test-quality.parallel-range-capture` now reports only when the nearest `go.mod` declares `go < 1.22`; modules using Go 1.22+ range-loop semantics, and files with no module metadata, are treated as out of scope.
- `gruff-go init --force` is now a safe regenerate-with-merge: it parses the existing `.gruff-go.yaml`, splices `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, and every per-rule `enabled`/`severity`/`threshold`/`thresholds`/`options` override into the rendered output, then adds blocks for rules new to the registry at defaults. The legacy destructive overwrite is now opt-in via the new `--force --reset` combination. Prevents the dogfood-config wipe behaviour that previously destroyed project-specific tuning on every regenerate (see `.goat-flow/footguns/setup.md`).
- `docs.config-field-comment` remains default-enabled but now does nothing until `includePaths` is configured, preventing broad exported-field documentation noise while preserving opt-in checks for configuration schema files.
- Rule pillar metadata now treats `design.hotspot-file` as a maintainability signal and `naming.get-prefix` as a modernisation signal, so pillar counts better match how the findings are used.
- Restored the dogfood `.gruff-go.yaml` tuning that was unintentionally wiped during a prior regenerate: 8-entry `paths.ignore` (`.agents/**`, `.antigravitycli/**`, `.claude/**`, `.codex/**`, `.github/**`, `.goat-flow/**`, `internal/rule/sensitive_test.go`, `internal/report/sensitive_redaction_test.go`), `allowlists.acceptedAbbreviations` (`ID, HTTP, JSON, CLI, AST`), the `docs.comment-rubric` strict `options:` block, `docs.exported-symbol-comment.options.ignoreInternalPackages: true`, `naming.identifier-quality.options.placeholderNames` list, tightened severities on `dead-code.empty-block`, `docs.config-field-comment`, `security.shell-command`, `size.parameter-count`, `test-quality.empty-test`, and tightened thresholds on `complexity.nesting-depth` (5 → 4) and `size.parameter-count` (8 → 5). Restores the dogfood scan to grade A.
- Split the `baseline` subcommand cluster (`runBaseline`, `baselineScanOptions`, `writeBaselineFromScan`) out of `internal/cli/cli.go` into `internal/cli/baseline.go`, mirroring the existing per-subcommand file pattern (`completion.go`, `dashboard.go`, etc.) and bringing `cli.go` back under the project's 500-line file-length threshold. No behavioural change.
- Documented that `allowlists.secretPreviews` controls preview redaction only and does not suppress sensitive-data findings; use rule exclusions, path ignores, or inline suppressions when a finding should be intentionally hidden.

### Added

- Added ten default-enabled parser rules to bring the Go catalogue to 61 rules: `docs.suppression-without-rationale`, `maintainability.defer-in-loop`, `maintainability.log-fatal-library`, `maintainability.loop-variable-address`, `security.http-server-no-timeout`, `security.permissive-file-mode`, `sensitive-data.gitlab-token`, `sensitive-data.npm-token`, `test-quality.fatal-in-goroutine`, and `test-quality.tempdir-misuse`.
- Added ten default-enabled parser rules to bring the Go catalogue to 51 rules: `complexity.cognitive`, `dead-code.unreachable-code`, `maintainability.context-todo-production`, `maintainability.ignored-error`, `maintainability.production-panic`, `modernisation.ioutil-deprecated`, `security.http-client-no-timeout`, `security.request-body-without-limit`, `test-quality.helper-missing-t-helper`, and `test-quality.parallel-range-capture`.
- `gruff-go init --force --reset` flag combination performs the legacy destructive overwrite, wiping existing tuning and writing fresh registry defaults. Use only when you explicitly want a clean slate.

## [0.1.1] - 2026-05-24

### Fixed

- Local and CI Go commands now prefer Go 1.25.10 via `go.mod` toolchain metadata, clearing current standard-library `govulncheck` findings without suppressing the audit.

### Changed

- `analyse`, `summary`, and `report` now accept `--fail-on` as an alias for `--min-severity`, matching the dashboard flag name and the broader gruff-family CLI vocabulary.
- Global CLI parsing now accepts `--silent` as an alias for `--quiet` and accepts Symfony-style verbosity flags (`-v`, `-vv`, `-vvv`, `--verbose`) for parity; verbosity flags are currently no-ops.
- `scripts/bump-version.sh` now updates `package-lock.json` as well as `package.json`, validates package metadata with Node, checks anchored version literals before editing, regenerates CLI goldens, and scans tracked source for stale version references while excluding historical/agent surfaces.
- CI and release workflows now use `go-version: 1.25.x`, install Node 22 and `govulncheck`, and run release preflight in `--release` mode before publishing.
- README and release documentation were reorganised around the project-pinned `go tool gruff-go` workflow, current command surface, trust boundary, dashboard defaults, stability contract, and release checklist.
- The npm lockfile was refreshed while bumping release metadata, updating locked tooling dependencies such as `markdown-it`, `linkify-it`, and `ws`.

### Added

- `gruff-go init` subcommand writes a default `.gruff-go.yaml` to the working directory, mirroring the registry's per-rule enablement, severity, and threshold defaults. Pass `--force` to overwrite an existing file.
- `analyse`, `summary`, `report`, and `dashboard` prompt when no `.gruff-go.yaml` is found and offer to generate one. The prompt is skipped automatically when stdin is not a TTY (CI, scripts), when `--config` or `--no-config` are set, and when the new global `-n` / `--no-interaction` flag is supplied.
- `gruff-go analyse --generate-baseline <path>` writes a fresh-start baseline from a clean scan, rejecting baseline, diff, and display-filter flags that would make the generated file partial.
- `gruff-go completion [bash|zsh|fish]` emits static shell completion scripts for the supported shells.
- Text summaries and setup output now point new users at the concrete `gruff-go analyse --generate-baseline gruff-baseline.json .` workflow, and text summaries show `.gitignore` skip counts when applicable.
- `scripts/dependency-install.sh` and `scripts/dependency-update.sh` install and refresh npm, Go module, and `govulncheck` dependencies for local development.
- `scripts/preflight-checks.sh` now verifies version metadata consistency, runs `npm audit`, runs `govulncheck` when available, and supports `--release` to catch an unbumped source version before tagging.
- Added `docs/README.md` as a documentation index and `docs/releasing.md` as the release checklist.


## [0.1.0] - 2026-05-23

First public release of `gruff-go`, a parser-only Go code-quality scanner. CLI commands: `analyse`, `baseline`, `dashboard`, `report`, `summary`, `list-rules`. 41 rules across 9 pillars (40 default-on), strict `.gruff-go.yaml` config, baselines, diff-mode, gitignore-aware discovery, six output formats (text/json/summary-json/sarif/github/html), and a local HTML dashboard.

Schemas `gruff-go.analysis.v0.1`, `gruff-go.config.v0.1`, and `gruff-go.baseline.v0.1` are stable within `0.1.x`.

**Install:** `go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.1.0` (or `go get -tool ...@v0.1.0` on Go 1.24+). Prebuilt Linux/macOS/Windows binaries are attached to the GitHub Release.

Known limitations: parser-only (no type/SSA analysis yet); HTML dashboard accessibility review ongoing.

[Unreleased]: https://github.com/blundergoat/gruff-go/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/blundergoat/gruff-go/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/blundergoat/gruff-go/releases/tag/v0.1.0
