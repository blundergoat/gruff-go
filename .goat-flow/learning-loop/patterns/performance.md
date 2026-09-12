---
category: performance
last_reviewed: 2026-08-22
---

# Performance Patterns

## Pattern: Keep rule metadata out of per-unit dispatch

**Created:** 2026-05-17

**Evidence:** OBSERVED

**Context:** `scripts/test-performance.sh --sweep` showed rule-set timings dominated by fixed per-scan dispatch overhead rather than one expensive rule. Before the registry change, the medium corpus measured `config-default` at `40.1 ms`, `no-config` at `28.0 ms`, and pathological `many-tiny-files` at `77.4 ms`.

**Approach:** Treat rule `Definition()` values and rule enablement as registry construction metadata, not hot-path work. Cache definitions in `internal/rule/rule.go` at `NewRegistryWithComposite`, precompute the active dispatch slices used by `Registry.Analyze`, and avoid duplicate byte-to-string conversion in `internal/parser/parser.go` before line counting. Protect the registry invariants with `internal/rule/rule_test.go` `TestRegistryCachesDefinitionsForDispatch` and `TestRegistryDoesNotDispatchDisabledRules` so future dispatch changes do not reintroduce per-unit definition allocation or disabled-rule calls.

**Result:** The post-change sweep measured `config-default` at `26.5 ms`, `no-config` at `18.5 ms`, and pathological `many-tiny-files` at `65.0 ms`.

## Pattern: Degrade deep source analysis and bind its performance baseline

**Created:** 2026-08-22

**Evidence:** ACTUAL_MEASURED

**Context:** A large `.go` file must remain eligible for size, sensitive-data, and configuration rules even when parsing and AST-backed rules would exceed a predictable cost budget. Skipping the file would make the performance safeguard remove security coverage.

**Approach:** Apply the paired line/byte check in `internal/parser/parser.go` (search: `func ParseWithBudget`) after Go source classification. On overflow, retain the raw source unit, emit the non-fatal `bounded-deep-scan` diagnostic, and omit its AST so `internal/analysis/runner.go` (search: `parserBudget`) keeps text-level analysis while naturally dropping syntax-dependent work. Keep the atomic CLI-over-config decision in `internal/cli/analyse_flags.go` (search: `deep-scan-budget`) and publish the same diagnostic through every reporter rather than treating degradation as an empty or skipped analysis.

**Measurement integrity:** `scripts/test-performance.sh` now rebuilds with `go build -trimpath` on every run, records the runtime-source, artifact, harness, toolchain, and host identities, and stores the comparand at `scripts/performance-baselines/linux-x86_64.json`. Its runtime-source and binary digests match the source-bound M11 cohort build. The sweep runs RSS probes from inside the hidden synthetic corpus so the measured command sees the same 501-file workload as the hyperfine cell.

**Verification:** `internal/analysis/runner_test.go` (search: `TestAnalyzeBoundedDeepScanRetainsTextRules`), `internal/parser/parser_test.go` (search: `bounded-deep-scan`), and `internal/report/machine_test.go` (search: `TestBoundedDeepScanDiagnosticReachesEveryRenderer`) protect retention, boundary, and visibility behavior.
