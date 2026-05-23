---
category: performance
last_reviewed: 2026-05-17
---

# Performance Patterns

## Pattern: Keep rule metadata out of per-unit dispatch

**Created:** 2026-05-17

**Evidence:** OBSERVED

**Context:** `scripts/test-performance.sh --sweep` showed rule-set timings dominated by fixed per-scan dispatch overhead rather than one expensive rule. Before the registry change, the medium corpus measured `config-default` at `40.1 ms`, `no-config` at `28.0 ms`, and pathological `many-tiny-files` at `77.4 ms`.

**Approach:** Treat rule `Definition()` values and rule enablement as registry construction metadata, not hot-path work. Cache definitions in `internal/rule/rule.go` at `NewRegistryWithComposite`, precompute the active dispatch slices used by `Registry.Analyze`, and avoid duplicate byte-to-string conversion in `internal/parser/parser.go` before line counting. Protect the registry invariants with `internal/rule/rule_test.go` `TestRegistryCachesDefinitionsForDispatch` and `TestRegistryDoesNotDispatchDisabledRules` so future dispatch changes do not reintroduce per-unit definition allocation or disabled-rule calls.

**Result:** The post-change sweep measured `config-default` at `26.5 ms`, `no-config` at `18.5 ms`, and pathological `many-tiny-files` at `65.0 ms`.
