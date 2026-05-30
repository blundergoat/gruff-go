# ADR-014: Remove the NPath Complexity Rule

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** Claude, human direction
**Ticket/Context:** Executes milestone `M00` (`.goat-flow/tasks/1.0.0/`). Narrows [ADR-007](ADR-007-comprehensive-default-rule-pack.md); applies the [ADR-008](ADR-008-external-codebase-calibration-precision-fixes.md) exception and the [ADR-011](ADR-011-mission-ai-generated-code-verifiability.md) mission.

## Decision

`complexity.npath` is removed from gruff-go entirely - rule, implementation, registration, config, docs, and goldens. The complexity pillar retains `cyclomatic`, `cognitive`, and `nesting-depth`. Rule count: 64 → 63 (all 63 remain default-enabled).

This is a breaking change: config validation rejects unknown rule IDs (`internal/config/validate.go`, search: `unknown rule`), so any config carrying a `rules.complexity.npath` block must drop it.

## Context

NPath is the metric most prone to legitimate false positives: it multiplies sequential branches, so a flat line-by-line parser scores in the thousands while cyclomatic and cognitive correctly rank it as moderate. On gruff-go's own code only three functions exceeded the registry default 1024 - `diff.Parse` (8646), `config.Config.RuleOptions` (5488), `rule.CommentRubricRule.aggregatedPackageSummaryFindings` (8227) - all at control-flow nesting depth 2-3 (flat: the multiplication artifact, not real nesting). The rule needed an 8.8x per-repo `threshold: 9000` override, added in the same commit that introduced it (`29efb39`), to keep the dogfood scan grade A - it was muted on its own repo on day one (see `.goat-flow/footguns/calibration.md`).

ADR-008's presumption is "fix the rule's precision, don't disable it" - but that applies to rules that misfire yet carry unique value. npath has no unique signal to preserve: cognitive complexity already charges nesting super-linearly, which is the part that genuinely impairs human verification (ADR-011). With nothing to preserve, removal - not a formula fix or a demotion - is correct. Maintainer directive: "more trouble than it's worth ... we already have other complexity rubrics."

## Failure Mode Comparison

| Option | What fails | Why rejected / accepted |
| --- | --- | --- |
| Keep npath + the 9000 dogfood override | Ships the FP-prone 1024 default to adopters while hiding it locally; the rule never fires on its own repo | Rejected (the status quo this removes). |
| Fix the modified-NPath formula | Real work on the walker, and even fixed the signal duplicates cognitive complexity | Rejected - nothing unique to preserve. |
| Demote to `DefaultEnabled: false` | Leaves dead code + an opt-in trap that re-introduces the FP for anyone who enables it | Rejected. |
| Remove the rule | One-time breaking change (config migration); cyclomatic/cognitive/nesting cover complexity | Accepted. |

## Consequences

- Rule count 64 → 63; complexity pillar 4 → 3 rules. README, `.goat-flow/architecture.md`, and `docs/rules.md` counts updated.
- Breaking: a config with a `complexity.npath` block fails to load; migration is to remove the block. CHANGELOG `[Unreleased]` records it.
- The three ex-outliers are now flagged by no complexity metric. Whether to tighten `complexity.cognitive` so the honest comprehension metric catches them is milestone **M31**'s coupled decision - tracked, not silently dropped.
- ADR-007's "every shipped rule is default-enabled, comprehensive pack" stance is narrowed: a rule that cannot serve the mission is removed rather than kept for completeness.

## Reversibility

Two-way door (git restores the deleted files), but intentionally sticky - re-adding npath would re-introduce the documented false positives. Reverse only with a formula that distinguishes flat sequential branches from genuine combinatorial nesting, plus evidence it adds signal cyclomatic/cognitive miss.
