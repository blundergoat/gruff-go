# ADR-019: Composite Counts Clean Rule-Backed Pillars

**Status:** Accepted
**Date:** 2026-08-05
**Author(s):** Codex, user direction
**Ticket/Context:** Cross-port false-positive audit, composite monotonicity defect

## Context

`internal/scoring.Calculate` previously built both its numerator and denominator
from pillars with score-impacting findings. A clean pillar therefore disappeared
from the mean. The regression fixture measured two dirty pillars at `85` instead
of `97` across the 11 registered pillars. More seriously, removing a final
advisory finding lowered the composite from `69` to `40` even though no pillar
score became worse.

The workspace [FAMILY-CONTRACT.md](../../../../FAMILY-CONTRACT.md) section 12
is still DRAFT and reserves family-wide penalty, confidence, clustering, and
attribution convergence for the coordinated JSON break. This local denominator
repair does not adopt or pre-empt those wider scoring changes.

## Decision

The composite is the integer mean over every distinct primary pillar declared by
the run's registered rule definitions. A pillar with no score-impacting findings
contributes 100. Configured-off and opt-in rules still establish a rule-backed
pillar, so disabling every rule in an area does not remove that area from the
denominator. If a programmatic caller omits registry metadata, any pillar found
in its score-impacting findings is included as a defensive fallback.

`Score.Pillars` and `Score.PillarDetails` continue to list finding-bearing
pillars only. `ScoreCoverage.ContributingPillars` likewise lists only pillars
that produced deductions; it describes evidence coverage and is not the
composite denominator. The JSON fields, per-pillar scores, penalties, finding
identities, and user-facing coverage caveat remain unchanged.

Each pillar penalty keeps the existing half-away-from-zero rounding. The final
composite keeps Go's existing integer division and therefore truncates a
fractional mean toward zero. Tests pin the N-pillar formula, this rounding choice,
the punished-finisher case, report detail membership, and a loop that removes
every finding index in turn and rejects any lower composite.

For operator review, the proposed FAMILY-CONTRACT section-12 amendment is:

> Section 12 composite canon: the composite is the mean over every rule-backed pillar, a pillar with zero findings counts as 100, and the aggregate is monotone - removing a finding never decreases it. 'Contributing pillars' language is replaced accordingly. Guard test: the monotonicity invariant, adopted per port.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep averaging only finding-bearing pillars | Fixing a pillar can lower the headline grade, and clean areas are invisible. | Rejected because remediation is punished and the aggregate is non-monotone. |
| Hardcode the current 11 pillar names in scoring | A future registered product area silently falls outside the denominator. | Rejected because the registry is the live product catalogue. |
| Count only enabled or applicable pillars | A configuration change can shift the denominator without changing code quality and reintroduce disappearance behavior. | Rejected for this repair; applicability can be revisited only with an explicit contract. |
| Include all registered primary pillars at 100 when clean | Projects receive credit for clean areas while finding evidence stays honest and sparse. | Accepted because it is monotone for the reproduced defect and preserves report shape. |
| Add clean entries to `Pillars` and `PillarDetails` | Machine and rendered report membership changes beyond the required numeric fix. | Rejected as a separate report-shape decision. |

## Consequences

- A project with at least one clean rule-backed pillar receives a higher
  composite than under the finding-only mean; its grade letter can jump.
- Stored score histories show a one-time release-boundary shift even when the
  underlying findings are unchanged. Consumers should annotate or re-baseline
  that point rather than interpret it as a code improvement.
- The headline denominator follows custom registries without global state or a
  hardcoded pillar list. Adding a genuinely new primary pillar changes future
  composites because it expands the product areas being measured.
- FAMILY-CONTRACT section 12 remains DRAFT. Its later coordinated migration may
  still change penalty weights, confidence handling, clustering, and attribution.

## Reversibility

Two-way door. Reverting the scoring argument, report helper, tests, generated
goldens, and changelog restores the prior values without migrating stored data or
schemas. Reverse only if the family explicitly rejects clean-pillar inclusion;
otherwise doing so knowingly restores the punished-finisher defect.
