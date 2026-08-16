---
category: rules
last_reviewed: 2026-08-05
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

## Pattern: Ship broad parser-only dead-code checks as opt-in candidates first

**Created:** 2026-05-31

**Evidence:** OBSERVED

**Context:** M28 expanded `dead-code.unused-private-function` into a shared package reference index and added unused private type, var, and const checks. Functions had prior dogfood calibration and stayed default-enabled. Types, vars, and consts needed broader syntax-safety exclusions for generated files, tests, reflection-heavy packages, iota groups, registration tables, and identifier collisions, but still had no cross-repo false-positive distribution.

**Approach:** Add the new rules to the built-in registry with `DefaultEnabled: false`, label them `candidate`, document their precision boundaries, and cover the intended positive and suppression cases with focused parser-only tests before dogfood. This keeps the catalogue discoverable without letting uncalibrated broad checks dominate default scans.

## Pattern: Test static-shape rules with paired flag and no-flag probes

**Created:** 2026-06-03

**Evidence:** OBSERVED

**Context:** Adding `test-quality.static-analysis-redundant-test` required proving both sides of a narrow parser-only contract: same-package reflection assertions that restate source declarations should flag, while behaviour tests, external `_test` packages, runtime-value reflection, missing-field checks, and unsupported syntax should stay silent. The focused tests now cover supported reflection shape assertions and behaviour/external-package suppressions (file evidence: `internal/rule/test_quality_static_fact_test.go`, search: `TestStaticAnalysisRedundantTestFlagsReflectShapeAssertions`; `internal/rule/test_quality_static_fact_test.go`, search: `TestStaticAnalysisRedundantTestIgnoresBehaviourAssertions`; `internal/rule/test_quality_static_fact_test.go`, search: `TestStaticAnalysisRedundantTestIgnoresExternalTestPackages`).

**Approach:** For parser-only static-shape rules, build fixtures in same-package production/test pairs and divide cases into explicit "must flag" and "must not flag" groups. Positive probes should cover operand order, aliases, init-bound values, supported assertion helpers, and metadata (`assertion`, `staticFact`, `staticFactFile`, `staticFactLine`, `confidenceReason`). Negative probes should cover real behaviour, wrong expected static values, runtime-derived values, external packages, cross-directory same-package names, and intentionally unsupported forms. Keep the rule opt-in until those probes plus external-codebase calibration show the findings are precise enough for default scans.

## Pattern: Validate a precision/rule change against the corpus before shipping

**Created:** 2026-06-14

**Evidence:** OBSERVED

**Context:** A default-rule precision change (a new skip, a broadened or narrowed match) can fix one false positive while creating others, and unit fixtures rarely cover real-world shapes. Unit tests proved the v0.4.0 `sensitive-data.secret-pattern` fix in isolation, but only the corpus showed it removed exactly the 16 commented-placeholder false positives in `cc-connect/config.example.toml` without zeroing the genuine test-fixture and code-sample hits in other repos.

**Approach:** Build once (`go build -o /tmp/gruff ./cmd/gruff-go`). Per corpus repo (cd-per-repo - see the corpus footgun in `../footguns/calibration.md`), capture `analyse --format json --no-config .` and break findings down by `ruleId` (`jq -r '.findings[].ruleId' | sort | uniq -c | sort -rn`). Drill into the rules the change touched plus the high-confidence security/sensitive-data rules: pull `file:line + message`, read the source at each site, and judge true-positive vs false-positive - high-volume rules (docs/complexity/size) on large mature repos are usually working as designed, so spend the budget on the changed and Error-severity rules. Re-scan after the fix and diff the per-rule counts: confirm the FP count dropped to the expected number AND that real positives elsewhere did not disappear (no over-suppression). Finish with the dogfood scan (grade A) - a fixture that embeds a contiguous secret-shaped literal or pushes a `_test.go` past the 500-line `size.file-length` cap will regress gruff's own scan (see the secret-pattern footgun in `../footguns/security-rules.md`).

## Pattern: Anchor marker vocabulary to introduced physical lines

**Created:** 2026-08-05

**Evidence:** OBSERVED

**Context:** `test-quality.skipped-test` used case-insensitive substring search over literal `t.Skip` arguments. Conditional integration skips that merely explained `TODO` handling were reported as debt, including quoted, backticked, plural, and hyphenated-name prose. The regression matrix in `internal/rule/skipped_test_marker_test.go` reproduced six quiet shapes while keeping conventional leading markers actionable.

**Approach:** Unquote AST string literals, split their displayed value into physical lines, and require the marker to introduce a line after optional whitespace or a list bullet. Accept only conventional delimiters: end of line, `:`, `(`, whitespace, or a hyphen followed by whitespace/end. Pair every quiet prose shape with real colon, owner, dash, space, bare, lowercase, bullet, multiline, and Go-style `TODO(username):` cases. Run the existing calibration fixture afterward; if it goes quiet, replace its evidence with a genuinely leading marker rather than weakening the check.

## Pattern: Map cross-port defects to native rule ownership before porting

**Created:** 2026-08-05

**Evidence:** OBSERVED

**Context:** A gruff-ts false-positive pass named process execution, loop-in-test labelling, and nested signature parsing as family defect classes. In gruff-go, `security.shell-command` owns only explicit interpreter execution, `test-quality.parallel-range-capture` owns a separate Go-version capture hazard, and documentation rules inspect `go/ast` declarations rather than `@param` text. Runtime probes in `/tmp/gruff-go-cross-port-repros-f253192aeec9/` plus the registry showed that literal rule-name matching would have invented new Go policy for two non-applicable classes.

**Approach:** Before adapting a sibling fix, map the language primitive, live registry ID, detector input, and user-facing remediation. Run the translated positive and quiet shapes at HEAD, then classify the class as reproduces, already-fixed, or not-applicable. Pin already-correct behavior at the nearest native AST boundary; for not-applicable classes, record complete registry/source-search evidence instead of adding a lookalike rule.
