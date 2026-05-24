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
