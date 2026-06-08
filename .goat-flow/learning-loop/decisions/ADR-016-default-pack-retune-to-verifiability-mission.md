# ADR-016: Default Pack Retune to Verifiability Mission

**Status:** Accepted
**Date:** 2026-05-31
**Author(s):** Codex, human approval
**Ticket/Context:** `.goat-flow/tasks/1.0.0/M31-retune-default-pack-to-mission.md`

## Decision

Retune the built-in rule pack around ADR-011's AI-code verifiability mission:

- `naming.get-prefix`, `naming.acronym-case`, `naming.package-stutter`,
  `naming.package-underscore`, `naming.receiver-consistency`, and
  `modernisation.ioutil-deprecated` are opt-in (`DefaultEnabled: false`).
- `naming.identifier-quality`, `naming.contextual-generic`,
  `naming.negated-boolean`, and `naming.misspelling` remain default-enabled
  because they catch review hazards rather than house style.
- `complexity.cognitive` default `maxComplexity` is `25`.
- `size.file-length` default severity is `advisory`.
- `naming.negated-boolean` accepts CLI/config flag vocabulary such as
  `NoConfig`, `NoBaseline`, and `NoInteraction`.

The catalogue remains 63 rules across 11 pillars. Built-in defaults are now 57
default-enabled rules plus 6 opt-in convention rules.

## Context

ADR-007 flipped every shipped rule to default-enabled. That was correct for a
coverage catch-up phase, but ADR-011 later narrowed the product mission: gruff's
default agent-loop gate should force code a human can verify, not generic style
conformance. Some default-on rules were enforcing Go convention or modernisation
preference rather than review-critical signal.

The cognitive threshold decision follows the metric calibration pattern in
`.goat-flow/learning-loop/patterns/rules.md`. A threshold sweep over the current checkout with
`complexity.cognitive` forced to threshold `1` produced 811 cognitive findings,
p50 `4`, p90 `10`, p95 `13`, p99 `19`, max `34`. Setting the default to `25`
initially caught exactly the three functions deferred by ADR-014/M00:
`diff.Parse` (`34`), `config.Config.RuleOptions` (`32`), and
`rule.CommentRubricRule.aggregatedPackageSummaryFindings` (`27`). Those functions
were refactored rather than hidden behind a dogfood override, following
`.goat-flow/learning-loop/footguns/calibration.md`.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep ADR-007's all-default-on stance | The default agent hook spends attention on house style and deprecation posture that do not materially improve human verification | Rejected. ADR-011 is the newer tie-breaker. |
| Demote all naming rules | Drops useful signals for placeholder names, overly generic names in large contexts, negated booleans, and misspellings | Rejected. These still map to reviewability hazards. |
| Keep `complexity.cognitive` at 35 after removing npath | Leaves the three known comprehension outliers under every complexity metric | Rejected. M00 deliberately routed this decision to M31. |
| Lower cognitive to 25 and refactor dogfood outliers | Gives the comprehension metric real coverage without muting the rule locally | Accepted. |
| Keep `size.file-length` at warning | Raw file length alone carries too much weight; composites already highlight files where size combines with other problems | Rejected. |
| Make file length advisory | Keeps the signal visible while letting `design.hotspot-file` and `design.god-function` carry stronger prioritisation | Accepted. |

## Consequences

- `gruff-go list-rules --no-config --format json` is now the source of truth for
  which rules are default-enabled; future docs must not say every shipped rule is
  enabled.
- M27's `strict` profile should re-enable the six convention-only opt-in rules.
- New rules that are useful but likely noisy can ship opt-in without violating
  the default-pack policy.
- No schema version, rule ID, finding fingerprint, or CLI flag changes are part
  of this decision.

## Reversibility

Two-way door. Re-enable any demoted rule by flipping its `DefaultEnabled` value
and updating docs/goldens. Raise or lower the cognitive threshold only with a
fresh distribution sweep and dogfood review. Revisit if external-codebase
calibration shows that one of the opt-in rules catches high-value review hazards
with low noise.
