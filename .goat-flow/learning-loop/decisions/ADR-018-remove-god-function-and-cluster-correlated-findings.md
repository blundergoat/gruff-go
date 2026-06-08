# ADR-018: Remove design.god-function and Cluster Correlated Findings

**Status:** Accepted
**Date:** 2026-05-31
**Author(s):** Claude, human direction
**Ticket/Context:** Implements the cross-port retirement of the `design.god-*`
composite and the P5 scoring principle from the workspace `DESIGN-PRINCIPLES.md`.
Refines [ADR-017](ADR-017-cross-port-rubric-calibration-contract.md) item 8;
builds on the clustering precedent in gruff-ts ADR-009 and gruff-py ADR-016
(`_finding_penalties`); applies [ADR-011](ADR-011-mission-ai-generated-code-verifiability.md)
and reuses the [ADR-009](ADR-009-three-severity-model.md) penalty weights.

## Decision

Three coupled changes, all in service of P5 ("score one root cause once"):

1. **Remove `design.god-function`.** The composite, its registration, fixtures,
   golden snapshots, docs entry, and the dogfood `.gruff-go.yaml` block are
   deleted. Rule count drops 80 -> 79. This is a breaking change: config
   validation rejects unknown rule IDs, so a config carrying a
   `rules.design.god-function` block fails to load (`config: unknown rule`,
   exit 2); the migration is to remove the block.

2. **Cluster correlated penalties.** `internal/scoring` groups findings that
   share a `(file, symbol, line)` whose rule is in the correlated set
   (`complexity.cyclomatic`, `complexity.cognitive`, `complexity.nesting-depth`,
   `size.function-length`, `size.parameter-count`). When two or more land on one
   symbol, each member's penalty becomes `max(member base penalty) / member
   count`. The members still sum normally into their pillars and file, so the
   cluster's *total* contribution collapses to the single worst member while the
   penalty is distributed across the member pillars. Every finding still renders
   and still counts in `countsByPillar` and per-pillar finding counts; only
   pillar, composite, and file-offender scores change. This mirrors gruff-py's
   `_finding_penalties` exactly and **refines ADR-017 item 8** from the loose
   "one penalty (max of members)" to the cross-port-consistent per-member
   `max/len` (whose total is that same max).

3. **Re-pillar `design.hotspot-file` to `design`.** god-function was gruff-go's
   only rule emitting the `design` pillar; hotspot-file had been pillared
   `maintainability`. Removing god-function would have emptied the `design`
   pillar and broken the workspace consistency check, which asserts
   `list-rules --format json` exposes exactly the 11 user-facing pillars.
   hotspot-file now emits `design`, matching its `design.*` rule ID. It remains
   score-neutral (the `design.` prefix excludes it from penalties), so this moves
   only its reported pillar, not the grade.

## Context

The `design.god-*` composite is a synthetic finding that fires only when a size
finding and a complexity finding already coincide on one symbol. Its only correct
score is neutral - it would otherwise triple-count one root cause - which makes it
clustering logic disguised as a finding. The workspace `DESIGN-PRINCIPLES.md` (P5)
retires the composite family-wide and rests P5 on clustering the real `size.*` +
`complexity.*` findings instead; gruff-rs removed it first, and go/ts/php/py
follow. gruff-go's composite was already score-neutral, so it added no third
penalty - but the underlying size and complexity metrics still double-counted one
hard function, which is the actual P5 gap this ADR closes.

The per-member `max/len` formula (rather than attributing one `max/len` to a
single representative) is chosen because it is exactly what the proven gruff-py
and gruff-ts implementations do: it distributes the cluster penalty across the
member pillars with no arbitrary representative choice, and its total equals the
single worst member - the "score once" guarantee.

## Failure Mode Comparison

| Option | What fails | Why rejected / accepted |
| --- | --- | --- |
| Keep god-function, keep raw per-metric penalties | One hard function bills the grade through overlapping size/complexity penalties; the composite re-describes findings the report already shows. | Rejected - the double-count is the P5 gap. |
| Remove god-function but leave hotspot-file in `maintainability` | The `design` pillar empties; the 11-pillar consistency check fails. | Rejected - drops a contract pillar. |
| Attribute one `max/len` to a representative member | Needs an arbitrary "winning pillar" rule and diverges from the proven gruff-py/gruff-ts template; cluster total would be `max/len`, not `max`. | Rejected - less faithful and not cross-port consistent. |
| Remove god-function, cluster per-member `max/len`, re-pillar hotspot to `design` | One-time breaking config migration. | Accepted - matches the family template, keeps every finding visible, and preserves all 11 pillars. |

## Consequences

- Rule count 80 -> 79; `design` pillar 2 -> 1 rule (`design.hotspot-file`).
  README, `.goat-flow/architecture.md`, `.goat-flow/code-map.md`, `docs/rules.md`,
  and `.goat-flow/glossary.md` counts and pillar references updated.
- Breaking: a config with a `design.god-function` block fails to load; migration
  is to remove the block. CHANGELOG `[Unreleased]` records it; the next release
  is therefore a breaking version bump.
- Scores shift where correlated findings stack on one symbol (lower total
  penalty), and `design.hotspot-file` findings move from the `maintainability`
  count bucket to `design`. The analysis schema, baseline schema, and finding
  fingerprints are unchanged.
- The named "god-function" signal is lost; P5 now rests purely on clustering the
  real size/complexity findings, which is the intended family-wide trade.

## Reversibility

Two-way door (git restores the deleted rule and the prior pillar), but
intentionally sticky: re-adding god-function would reintroduce the disguised
clustering logic the family agreed to retire. Reverse only if the workspace
reverses the cross-port P5 decision. The clustering math is reversible on its own
by changing only `internal/scoring`, its tests, and the affected goldens - not the
finding schema or rule emission.
