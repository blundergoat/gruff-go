# Changelog

All notable changes to `gruff-go` are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No changes yet.

## [0.1.0] - 2026-05-23

First public release. The binary reports `0.1.0`. Schemas `gruff-go.analysis.v0.1`, `gruff-go.config.v0.1`, and `gruff-go.baseline.v0.1` are stable within the `0.1.x` line.

### Added

- **CLI** (`gruff-go`) with subcommands `analyse`, `baseline`, `dashboard`, `help`, `list`, `list-rules`, `report`, and `summary`. Exit codes are `0` for clean runs, `1` for findings at or above `--min-severity`, and `2` for diagnostics or invalid input.
- **Parser-only Go analysis pipeline** with source discovery, generated-file skipping, Go parser integration, deterministic rule dispatch, and severity/confidence-weighted scoring. Type-aware rules are intentionally deferred.
- **Rule catalogue with 41 rules across 9 pillars.** The built-in pack ships 40 default-enabled rules plus the opt-in `docs.config-field-comment` rule for configuration-style struct fields.
- **Strict `.gruff-go.yaml` config** using schema `gruff-go.config.v0.1`. Unknown keys, unknown rule IDs, unknown pillars, and invalid thresholds fail closed.
- **Baseline workflow.** `gruff-go baseline --out gruff-baseline.json` writes a fingerprinted snapshot; `analyse --baseline path` suppresses exact rule/file/fingerprint matches and reports stale entries.
- **Diff-mode scanning.** `analyse --diff-base <ref>` filters line-located findings to changed lines and records that diff mode is changed-line scoped, not full-project proof.
- **Display filters.** `--include-rules`, `--exclude-rules`, `--include-pillars`, and `--exclude-pillars` hide rendered findings without changing score or exit code.
- **Output formats**: `text`, `json`, `summary-json`, `sarif`, `github`, and `html`.
- **HTML inspection report** with severity stats, pillar breakdowns, top-offender tables, cyclomatic histogram, findings list, and optional editor links.
- **Local dashboard** with loopback-default serving, scan controls, configurable timeout, diff/baseline/config toggles, and iframe-rendered reports.
- **Interactive findings filter** for HTML reports with severity, pillar, path, search, and group-by controls.
- **Gitignore-respecting discovery.** `analyse`, `baseline`, `summary`, and dashboard scans skip project `.gitignore` matches by default and support `--include-ignored` when callers intentionally want to scan ignored paths.
- **Scoring model** with 0-100 composite score, letter grade, per-pillar scores, top offenders, complexity distribution, and score-coverage caveats.
- **CI preflight gate.** GitHub Actions now runs `scripts/preflight-checks.sh`, covering shell syntax, ShellCheck, gofmt, `go vet`, `go test ./...`, and the gruff self-scan.
- **Release tooling.** `scripts/bump-version.sh <new-version>` updates in-tree version literals and regenerates CLI golden snapshots.
- **Broad default rule policy.** Adopters get 40 of the 41 shipped rules out of the box; `docs.config-field-comment` remains default-disabled because broad struct-field enforcement is only appropriate for selected configuration/API files.
- **Mainstream Go thresholds.** Defaults use `complexity.nesting-depth.maxDepth: 5`, `size.parameter-count.maxParameters: 8`, and `size.file-length.maxLines: 500`.
- **Low-severity heuristic coverage.** Documentation, naming, test-quality, design, and heuristic security findings generally report below the default `--min-severity medium` gate unless configured otherwise.
- **Test-file calibration.** Default `size.file-length` and `size.function-length` findings in `_test.go` files report as lower-confidence/lower-severity signals unless a project explicitly overrides severity.
- **Summary scan context.** `gruff-go summary` prints scanned inputs, working directory, analysed/skipped file counts, and scan duration before the score.
- **Robust `.gitignore` handling** with valid-rule preservation around malformed lines, descendants-only trailing `**` semantics, explicit external-input boundaries, and per-subtree fallback gating.
- **Test-quality precision** for runnable Go test signatures, fuzz callbacks, assertion helpers, dot-imported `testing` handles, lexical receiver scoping, and third-party `Skip` method avoidance.
- **Documentation-rule precision** for package-wide doc summaries, inline config-field comments, and the opt-in struct-field documentation rule.
- **Naming-rule precision** for receiver consistency by package, external test package names, receiver accessor `Get` methods, contextual generic identifiers, misspellings, Go initialisms, negated booleans, and package stutter.
- **Size-rule precision** with code-bearing function length measurement and discounted multiline table fixtures in test functions.
- **Security-rule precision** for shell-routed commands, TLS settings, dynamic SQL, archive path traversal containment, weak crypto, and insecure random values used for secrets.
- **Sensitive-data precision** with vendor-prefixed token detectors, GCP service-account key detection, comment skipping, common suppression support, consistent redaction, and local dev/test placeholder avoidance.
- **Config compatibility** that merges legacy top-level lists with nested gruff-family aliases.
- **Portable shell tooling** for release and performance scripts, including BSD/macOS timeout fallback support and safe version replacement.

### Known Limitations

- Analysis is parser-only in v0.1. Type-aware rules, SSA/dataflow analysis, and external linter ingestion are deferred.
- Trend storage, package-manager distribution, hosted service surfaces, and automated release publishing are not included in this release.
- Accessibility validation for the HTML report and dashboard still needs broader manual and assistive-technology review.

[Unreleased]: https://github.com/blundergoat/gruff-go/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/blundergoat/gruff-go/releases/tag/v0.1.0
