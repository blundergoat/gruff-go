---
category: rules
last_reviewed: 2026-05-24
---

# Rule-Authoring Patterns

## Pattern: Use AST comments for Go suppression directives

**Created:** 2026-05-24

**Evidence:** OBSERVED

**Context:** While adding `docs.suppression-without-rationale`, the first line-scan implementation treated `//nolint` and `#nosec` text inside raw string fixtures and explanatory doc comments as live suppressions. Dogfood fell from grade A to B with false positives in `internal/rule/docs_suppression_test.go` (search: `//nolint:gosec`), `internal/rule/function_length_tables.go` (search: `function-length suppression entry`), and `internal/rule/sensitive.go` (search: `hasSecretSuppressionAnnotation`).

**Approach:** For Go files, inspect `unit.AST.Comments` and require the trimmed comment text to start with the suppression directive. Use source line scanning only for non-Go text units. This keeps real same-line code suppressions visible while ignoring raw string fixtures and prose that merely documents suppression syntax. The fixed implementation lives in `internal/rule/docs_suppression.go` (search: `suppressionFindingsFromGoComments`).

## Pattern: Calibrate a metric threshold by sweeping the distribution, then cross-check nesting

**Created:** 2026-05-30

**Evidence:** OBSERVED

**Context:** Deciding whether `complexity.npath`'s default (1024) was right needed the *actual distribution* of the metric across real code, not a guess. The same question recurs for every metric rule (e.g. M31 tightening `complexity.cognitive`).

**Approach:** Build the binary, write a temp config that sets the metric rule's `threshold: 1` so every function reports its value, run `analyse --config <tmp> --format json .`, and aggregate the per-finding `metadata.complexity` / `.lines` / `.depth` into a distribution (p50/p90/p95/p99/max), split production vs `_test.go`. Then cross-check the outliers: for a path/branch metric, measure each above-threshold function's control-flow nesting depth - flat (depth <= 3) high scorers are formula artifacts (sequential branches multiplying), genuinely nested ones are real complexity. This is what proved npath's three worst functions were flat false positives while cyclomatic/cognitive correctly ranked them under threshold. Worked commands + evidence: `.goat-flow/tasks/1.0.0/M00-remove-npath-false-positives.md` (search: `Nesting cross-check`).
