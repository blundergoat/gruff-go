# ADR-006: Single-Value Rubric Thresholds

**Status:** Accepted
**Date:** 2026-05-18
**Author(s):** Codex, human direction
**Ticket/Context:** `.goat-flow/tasks/0.1/M23-comment-rubrics-for-human-maintainers.md`, `.goat-flow/tasks/0.1/M24-naming-rubric-expansion.md`

## Context

M23 added `docs.comment-rubric` as a stricter, default-disabled maintainer-comment rubric. The first implementation exposed two configured values for the package-summary check: `minPackageCommentLines` and `minPackageCommentWords`. That made the rubric look like a compound warning/error-style range even though the project wanted one calibrated value and one configured severity.

The human correction was explicit: rubric configuration should not be a warning/error range, and it should not expose multiple rubric values. A rubric should have one value and one severity.

The reference implementation in `/home/devgoat/projects/gruff-workspace/gruff-php` supports this public shape through `threshold: <number>` plus `severity: <level>`, represented internally by `SeverityThreshold`. It still has older named-threshold internals for some metric rules, but the relevant public override pattern is the singular threshold/severity pair.

The immediate correction in `gruff-go` removed the extra package-comment word threshold from `docs.comment-rubric`. The rule now exposes exactly one threshold key in the catalogue, `minPackageCommentLines`, and project config uses:

```yaml
rules:
  docs.comment-rubric:
    threshold: 2
    severity: notice
```

Config validation also rejects a rule config that combines `threshold` and `thresholds`, so callers cannot create an ambiguous override shape for a single rule.

## Decision

All rubric-style rules in `gruff-go` must expose one calibrated numeric value and one severity.

For public config, the preferred shape is:

```yaml
rules:
  <rubric-rule-id>:
    threshold: <number>
    severity: info | low | medium | high | critical
```

Rubric rules must not model warning/error ranges. They must not expose separate warning and error threshold values. They must not require multiple independent rubric thresholds to decide one finding's severity.

If a proposed rubric seems to need more than one value, split it into separate rubrics or move secondary switches into clearly named rule options that do not act as severity thresholds. A secondary option is acceptable only when it changes scope or eligibility, not when it creates another numeric cutoff for the same finding severity decision.

Existing non-rubric mechanics may still have multiple implementation thresholds when the rule is genuinely multi-axis, such as a composite file-hotspot rule that gates on both finding count and pillar count. Do not use that exception to introduce warning/error ranges into rubric rules.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Warning/error threshold ranges per rubric | Users must reason about two cutoffs for one rubric and the scanner decides severity from a range. Small config changes become calibration changes and severity-policy changes at once. | Rejected. The user explicitly rejected this shape, and it is harder to explain in docs and dogfood. |
| Multiple named rubric values for one finding | A single rubric starts encoding several preferences. It becomes unclear which value failed and which value should be adjusted. | Rejected. A rubric must have one calibrated value; extra preferences should be separate rubrics or options that do not set severity. |
| One threshold plus one severity per rubric | Users choose the one cutoff and the severity they want when that cutoff is exceeded or missed. The scanner remains strict, deterministic, and easy to document. | Accepted. This matches the corrected `docs.comment-rubric` contract and the singular public override pattern observed in `gruff-php`. |
| Keep multiple thresholds for genuinely multi-axis non-rubric rules | Some rules, especially composite triage helpers, need more than one eligibility gate and are not assigning severity from a warning/error range. | Accepted as a narrow exception. These rules must not be described as rubrics unless they are redesigned into the single-value shape. |

## Consequences

- New rubric proposals must include exactly one configurable numeric threshold and one severity.
- Documentation examples for rubric rules should show `threshold` and `severity`, not `thresholds`.
- Reviewers should challenge any new rubric that adds `warning` / `error` thresholds, `min` / `max` pairs for one severity decision, or multiple numeric values that all contribute to one finding.
- `docs.comment-rubric` remains the reference implementation for this policy in `gruff-go`.
- Config validation should continue rejecting mixed `threshold` plus `thresholds` forms.

## Reversibility

Two-way door before a public v0.1 compatibility promise, but intentionally sticky. A future ADR may supersede this one only with evidence that a rubric cannot be represented as separate single-value rubrics or as one threshold plus non-threshold options.

Revisit triggers:

- A real adopter needs one rubric finding to carry several independent calibrated values, and splitting the rubric would make the user experience worse.
- The config schema changes in a future version to distinguish rubric thresholds from non-rubric eligibility gates more explicitly.
- `gruff-php` or another sibling implementation adopts a stronger shared config contract that replaces this one.
