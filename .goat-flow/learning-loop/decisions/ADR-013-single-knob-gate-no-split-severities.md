# ADR-013: Single-Knob Gate, No Split Severities

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** Claude, human direction
**Ticket/Context:** Maintainer directive (2026-05-30) during the 1.0.0 plan review. Extends [ADR-006](ADR-006-single-value-rubric-thresholds.md), applies [ADR-011](ADR-011-mission-ai-generated-code-verifiability.md), and deleted the planned `M25` per-severity-count-threshold milestone.

## Decision

gruff does not split severities, at two levels:

1. **Per rule.** Each rule emits at exactly one severity and (for metric rules) one threshold. No value→severity band ladder: `warning: 200 / error: 500` is forbidden - choose one. This restates and extends ADR-006 (single-value rubric thresholds).
2. **At the gate.** The quality gate is single-knob: one severity floor (`--min-severity` / `--fail-on` / [ADR-010](ADR-010-per-command-minimum-severity.md) `minimumSeverity.<cmd>`, default `advisory`). There is no per-severity *count* gate (`failureConditions.severityThresholds.{advisory,warning,error}: N`), no per-pillar count gate, and no composite-score gate.

advisory / warning / error remain as per-rule informational labels and score weights ([ADR-009](ADR-009-three-severity-model.md)); they do not create gate tiers. The adoption / legacy-codebase win is *scoping* the gate to new findings (`--fail-on-new` / `minimumSeverity.new`, M26), not *tolerating* findings per severity.

## Context

The 1.0.0 team-adoption track (`.goat-flow/tasks/1.0.0/ISSUE.md`) imported a Qodana idea - per-severity count thresholds ("tolerate 200 warnings, fail on 5 errors") - as milestone M25. The maintainer rejected it. gruff's mission (ADR-011) is that a coding agent fixes *everything* - advisory, warning, and error alike - so the gate is binary (any finding fails until fixed) and tiering it by severity is pointless: "having both warning and error is pointless since the agent fixes by the warning point anyway." One severity + one value per rule is also simply easier to understand and operate.

Evidence: the directive deleted `M25` (removed from `.goat-flow/tasks/1.0.0/` on 2026-05-30) and resimplified `M26` to a single-knob new-findings gate. gruff's existing rules already comply - each ships one severity + one threshold (search `internal/rule/`: `Severity:` is one value per `Definition`). ADR-010's `minimumSeverity.<cmd>` (one value per command) is the sanctioned gate shape; M25's `failureConditions` matrix was the proposed violation.

## Failure Mode Comparison

| Option | What fails | Why rejected / accepted |
| --- | --- | --- |
| Per-severity count gate (M25 / Qodana) | Splits the gate by tier and tolerates findings the agent should fix; two cutoffs to reason about; conflicts with fix-everything | Rejected. |
| Value→severity bands per rule (`warning: X / error: Y`) | Two cutoffs per rule; complicates fingerprints, baseline, scoring, exit semantics | Rejected (also ADR-006). |
| Collapse advisory/warning/error to one level | Loses cross-port harmony (gruff-rs/ts/py/php use three, ADR-009) and the score-weight + human-triage value | Not taken - labels are kept; only gate-tiering is removed. |
| Single-knob gate + one severity per rule; scope to new findings for adoption | One cutoff to reason about; binary and predictable; serves the agent loop and the legacy ratchet | Accepted. |

## Consequences

- M25 deleted; M26 is a single-knob new-findings gate; per-pillar and composite-score gates are rejected, not deferred (see `ISSUE.md` / `backlog.md`).
- New gate features must stay single-knob; new rules ship exactly one severity + one threshold.
- advisory / warning / error stay for reporting and scoring. `design.hotspot-file`'s multi-axis eligibility (two thresholds → one severity) remains the ADR-006-sanctioned exception and is not a severity split.

## Reversibility

Two-way door but sticky - a product/UX stance tied to the agent-fix-everything mission. Revisit if gruff's primary use shifts to human-team triage where per-severity tolerance is genuinely wanted, or if a sibling port adopts a different shared gate contract. Reverse by superseding this ADR, not by quietly re-adding `failureConditions`.
