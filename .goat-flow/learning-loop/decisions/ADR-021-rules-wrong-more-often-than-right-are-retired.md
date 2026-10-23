# ADR-021: Rules wrong more often than right are retired, not tuned

**Status:** Accepted
**Date:** 2026-10-04
**Updated:** 2026-10-14
**Author(s):** Claude, user direction
**Ticket/Context:** precision-floor M19 under family lock M82.

## Context

The 0.6.0 precision measurement evaluated default-enabled rules against judged corpus findings. The operator ruled on 2026-10-04 that a rule right less than half the time is deleted rather than tuned in place, and accepted the gruff-go table with "Accept all (Recommended)".

## Decision

gruff-go retires three rules the 0.6.0 precision measurement found right less than half the time:

- `security.sensitive-data-logging`, right on 0 of 16 judged findings;
- `security.sql-string-query`, right on 1 of 9;
- `sensitive-data.high-entropy-string`, right on 4 of 24, with the built-in lockfile skip that existed only for it
  (FAMILY-CONTRACT.md section 12 and section 13a now bind gruff-rs alone; workspace ADR-005 records the amendment).

Each rule's code, tests, false-positive guidance, dogfood config block and calibration entries are removed. A config,
baseline or `sensitiveExclusions` entry naming one is rejected as an unknown rule, as `complexity.npath` was (ADR-014).

It also turns seven rules off by default, each right less than half the time on fewer than ten findings, too few to
delete on: `dependency.go-mod-local-replace`, `security.insecure-random-secret`, `sensitive-data.aws-access-key`, `sensitive-data.connection-string`, `sensitive-data.gcp-service-account`, `sensitive-data.github-token`, `sensitive-data.google-api-key`. They stay in the catalogue and run when a config enables them.

The family specification records the retirement as a catalogue transition with no successor, and keeps the rule's review
record as `retired` (workspace ADR-010).

## Reversibility

The rule can return as a new, measured rule; `.goat-flow/plans/0.7.0-roadmap/rules-to-rebuild.md` in the workspace keeps
its wrong shapes and what a rebuilt rule needs.

## M02 retirement decision, 2026-10-14

The operator accepted all five M02 tables with "i approve, continue", including Go rows go-002, go-006 and go-007. Under family lock M92, retire these additional Go rules:

| Rule | Judged | Right | Not worth | Wrong | Unresolved | Score | Current right findings removed |
|---|---:|---:|---:|---:|---:|---:|---:|
| `naming.negated-boolean` | 25 | 0 | 25 | 0 | 0 | 0.000 | 0 |
| `test-quality.no-failure-path` | 28 | 4 | 16 | 8 | 22 | 0.143 | 4 |
| `test-quality.skipped-test` | 25 | 8 | 17 | 0 | 0 | 0.320 | 8 |

The no-failure-path sample remains unresolved on 22 cards; its score is conditional on the 28 judged cards. The accepted table records that limit. The operator saw the full prospective loss list before approving: four currently emitting right-labelled no-failure-path findings and eight skipped-test findings are removed. None was confirmed right for negated-boolean naming. Retiring a noisy rule does not mean it had no useful findings.

The rule code, obsolete tests, registry wiring, guidance and dogfood config blocks are removed. Shared assertion and testing-receiver helpers remain for the surviving test-quality rules. The family specification preserves every historical review record as retired, score-neutral and ineligible for exit or hook blocking, using workspace ADR-010 catalogue transitions. A rebuilt rule needs new precision evidence before returning.

Workspace evidence: .goat-flow/plans/0.6.0-precision-floor/evidence/m02/table-answers.json (search: acceptedRows), tables.json (search: go-006), and table-recall.json (search: currentRightIds). Native runtime regression: internal/rule/builtin_rule_ids_test.go (search: TestRetiredLowPrecisionRulesLeaveRegistryAndDispatch).

The fresh M02 capture also removes 35 derived hotspot annotations. One, design.hotspot-file at go/testify/mock/mock_test.go, was labelled right: its underlying group falls from five findings to two, below the unchanged minimum of three. The operator accepted this additional loss with M93, bringing current Go right-label losses to 13. The original TP classification is preserved. Workspace evidence: .goat-flow/plans/0.6.0-precision-floor/evidence/m02/go-retirement-recall.json (search: additionalLossOperatorApproval) and activation-approval-m93.json (search: additionalDerivedRightLoss). The unchanged predicate is internal/rule/composite.go (search: hotspotFileMinFindings).
