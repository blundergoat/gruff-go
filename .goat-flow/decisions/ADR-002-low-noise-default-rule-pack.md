# ADR-002: Low-Noise Default Rule Pack

**Status:** Implemented
**Date:** 2026-05-13
**Updated:** 2026-05-18
**Author(s):** Codex
**Ticket/Context:** `.goat-flow/tasks/0.1`

## Context

The scanner needed a default rule pack that catches concrete quality problems without making a new project fail on taste or unproven heuristics. M03 shipped five default-enabled rules: file length, function length, cyclomatic complexity, package comments, and secret-like assignments. M05 dogfood initially found one real maintainability issue: `internal/analysis/runner.go` had a 98-line `Run` function against an 80-line threshold.

Evidence from this session:

- The initial dogfood scan after M04 reported one `size.function-length` finding in `internal/analysis/runner.go`.
- Refactoring `Run` into helper functions removed the finding without changing thresholds or adding config suppression.
- The follow-up dogfood scan reported 41 files scanned, 0 findings, exit code 0, and score 100/A.
- M08 dogfood after composite-rule implementation reported 78 files scanned, 0 default findings, exit code 0, and score 100/A.
- M08 found `docs.exported-symbol-comment` was too strict when opted in with `ignoreInternalPackages: false`: it reported 185 internal-package findings. The option default is now `true`, and the same opt-in dogfood path reports 0 findings without local suppression.
- 2026-05-18: `size.file-length` default `maxLines` raised from 400 to 500. M22 calibration on `blundergoat-platform` showed default reports were dominated by line-count rules; raising the threshold preserves the production handler size signal while reducing test/declarative-noise volume. Dogfood after the change: 83 files, 0 findings, exit 0, score 100/A. Single hard threshold retained; no tiered/banded confidence introduced.

## Decision

Keep v0.1 defaults narrow and evidence-backed:

- Default-enabled: file length, function length, cyclomatic complexity, package comment, and secret-like assignment.
- Default-disabled opt-in expansion rules may exist after config support is available, but they must not change default scan behavior until dogfood and fixture evidence justify enabling them.
- Composite design findings are normal report findings but score-neutral so they can prioritize overlapping evidence without double-penalizing the underlying size, complexity, documentation, or other base findings.
- Deferred as default-enabled behavior: naming, waste, test-quality, broader security, dead-code, project-design, trend, dashboard, mutation, and external-linter ingestion rules.
- When dogfood exposes noise or weak signal, tune implementation or rule shape rather than hiding default problems with local config.
- Do not add default-disabled heuristic families until config and calibration evidence justify them.

M08 default policy table:

| Rule or family | Decision | Evidence |
| --- | --- | --- |
| `complexity.cyclomatic`, `docs.package-comment`, `sensitive-data.secret-pattern`, `size.file-length`, `size.function-length` | Keep default-enabled. | Default dogfood is clean: 78 files, 0 findings, exit 0, score 100/A. |
| `docs.exported-symbol-comment` | Keep opt-in; tune option default to `ignoreInternalPackages: true`. | Opt-in dogfood dropped from 185 internal-package findings to 0 after the option-default change. Second-corpus evidence is still missing. |
| `size.parameter-count` | Keep opt-in; resolved the `analysis.NewReport` parameter-count follow-up. | Opt-in dogfood now reports 0 findings after replacing the long `NewReport` signature with a `ReportInput` struct. |
| `naming.identifier-quality` | Keep opt-in; tune per project. | Opt-in dogfood reports 11 findings, mostly `data` and `info`, which are often idiomatic in Go. |
| Specific sensitive-data detectors | Keep opt-in. | Opt-in dogfood findings are fixture strings in sensitive-data tests; no production-like leaks found. |
| `test-quality.skipped-test` | Keep opt-in. | Opt-in dogfood reports 1 intentional test skip branch in golden-update support. |
| `complexity.nesting-depth`, `dead-code.empty-block`, `naming.package-underscore`, `security.shell-command`, `test-quality.empty-test`, `test-quality.no-failure-path`, `design.god-function`, `design.hotspot-file` | Keep opt-in. | Opt-in dogfood reports 0 findings in this repository; that is not enough evidence to default-enable without the second corpus. |

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Ship many heuristic rules immediately | New adopters inherit noisy defaults before calibration exists. | Rejected. The scanner would look broader but be less trustworthy. |
| Hide dogfood findings with local config | Defaults can remain bad while this repository appears clean. | Rejected. Dogfood must shape defaults. |
| Keep a small default rule pack and add opt-in expansion rules only after config support | Default coverage is narrower, but findings are explainable and users can experiment without changing default dogfood behavior. | Accepted. The one dogfood finding led to a real refactor, and later opt-in rules stayed disabled by default. |

## Reversibility

Two-way door. Future milestones can add rule families when they include fixtures, dogfood counts, default-enable/default-disable reasoning, and follow-up backlog entries for noisy cases.
