# ADR-007: Comprehensive Default-Enabled Rule Pack

**Status:** Implemented
**Date:** 2026-05-18
**Author(s):** Codex
**Ticket/Context:** `.goat-flow/tasks/0.1`
**Supersedes:** [ADR-002](ADR-002-low-noise-default-rule-pack.md).

## Context

ADR-002 established a narrow 5-rule default pack with 20 opt-in expansion rules: file length, function length, cyclomatic complexity, package comment, and secret-like assignment ran out of the box; everything else required explicit `rules.<id>.enabled: true`. The stance was "low-noise defaults, evidence-backed promotion."

Operating experience after M06–M24 changed the picture:

- The opt-in catalogue grew to 20 rules across naming, design composites, sensitive-data detectors, security, dead-code, test-quality, and maintainer-comment families.
- Dogfood evidence on `gruff-go` itself with all 20 opt-ins active produced **3 low-severity findings** (all `naming.receiver-consistency` on the `Registry` type), exit 0. Calibration on `blundergoat-platform` (M22) shaped the production-vs-test discriminators inside the size rules, so noisy test bulk no longer dominates default scores.
- Adopters running `gruff-go` for the first time generally want full coverage, not a 5-rule baseline that requires reading docs to discover the remaining 80% of the catalogue.
- The opt-in promotion gate ("second corpus + explicit human accept") was never going to clear all 20 rules one at a time; the policy became a perpetual block on coverage.

Two thresholds also drifted from common Go-tool defaults:

- `complexity.nesting-depth` defaulted to 4; the `nestif` linter and broader community usage sit at 5.
- `size.parameter-count` defaulted to 5; revive's `argument-limit` sits at 8 and PMD `ExcessiveParameterList` at 10.

## Decision

Flip every shipped rule to `defaultEnabled: true`. Adopters get the full default rule catalogue on first run; disabling a rule is a one-line `rules.<id>.enabled: false` override. At decision time the catalogue shipped 30 rules (`list-rules --format json` is the source of truth); the number grows as new rule families land.

2026-05-23 update: the policy still holds after the security and sensitive-data expansions. The live registry now has 41 rules, with 40 default-enabled and `docs.config-field-comment` remaining the single deliberate opt-in carve-out.

Two threshold adjustments toward industry-mainstream values:

- `complexity.nesting-depth` `maxDepth` **4 → 5** (matches `nestif`).
- `size.parameter-count` `maxParameters` **5 → 8** (matches revive `argument-limit`).

Three thresholds stay where calibration evidence already placed them:

- `complexity.cyclomatic` `maxComplexity` stays at **20** (industry spread 15–30; `gocyclo` common usage 15, golangci-lint `gocyclo` default 30; 20 sits in the middle).
- `size.function-length` `maxLines` stays at **80** (industry range 60–100; `funlen` default 60 is strict-end, real Go projects commonly use 80–120).
- `size.file-length` `maxLines` stays at **500** (recently calibrated; no industry default).

One special case: `docs.comment-rubric` is path-scoped via `includePaths`. Default-on is a no-op for projects that don't configure paths, so flipping it on costs nothing and removes an awkward inconsistency in the policy table.

One deliberate exception: `docs.config-field-comment` stays `defaultEnabled: false`. Its scoping options (`includePaths`/`excludePaths`) default to empty, which under its current `appliesToPath` semantics means the rule applies to every file — and the per-field check fires on every undocumented exported struct field. Unlike `docs.comment-rubric`, the rule is not a no-op without configuration, so defaulting it on would swamp adopters with documentation findings on every exported field across the codebase. The carve-out is recorded here so the rule's `DefaultEnabled: false` flag does not appear to contradict the rest of this ADR.

## Dogfood Evidence

After implementation, with the project's `.gruff-go.yaml` honoured:

- `go run ./cmd/gruff-go analyse --format json .` — 83 files, 3 findings (all `naming.receiver-consistency`, low severity), exit 0.

With `--no-config` (pure default policy on top of unfiltered source):

- 85 files, 9 findings, exit 1: 6 sensitive-data hits in the fixture test files (`internal/rule/sensitive_test.go` and `internal/report/sensitive_redaction_test.go`, both ignored by the project's `paths.ignore`) plus the same 3 receiver-consistency findings. No surprises beyond the known fixture-content suppression and the existing receiver-consistency dogfood task.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep ADR-002's narrow defaults | New adopters see only 5 rules unless they read documentation and edit config; ~80% of the catalogue stays invisible. | Rejected. The default pack should reflect what `gruff-go` actually believes is high-signal. |
| Per-rule promotion to default-on as evidence accrues | Slow, inconsistent, leaves the catalogue split across "blessed" and "experimental" tiers for an unbounded time. | Rejected. Twelve milestones in and no rule had cleared the original promotion gate; the gate was wrong, not the rules. |
| Flip all rules default-on, keep current thresholds | Some thresholds are stricter than common Go-tool defaults (nesting-depth 4, parameter-count 5), producing FPs that the project itself never validated. | Rejected. Industry-mainstream thresholds are a cheap correction that ships with the default flip. |
| Flip all rules default-on, align thresholds to industry mainstream | Adopters get full coverage at threshold values they recognise from `nestif`, revive, funlen-adjacent tools. Some rule families (naming, test-quality, design composites) are still gruff-novel, but they ship default-on with `low` severity so they don't fail CI without explicit configuration. | Accepted. |

## Reversibility

Two-way door. Reversion to ADR-002's narrow defaults is a single-line flip per rule (the same mechanical edit applied in this milestone, run in the opposite direction) plus the inverse threshold change for nesting-depth and parameter-count. The fingerprints, baseline schema, exit-code semantics, JSON schema version, and rule IDs are unchanged by this ADR; only `DefaultEnabled` flags and two threshold constants moved.

## Severity Discipline Under the New Defaults

Most flipped rules are `low` severity. The default `--min-severity medium` threshold means low-severity findings appear in reports but do not flip exit code from 0 to 1. Concretely:

- `medium` and above (cyclomatic, file-length, function-length, nesting-depth, shell-command, all sensitive-data.* except private-key): fail CI when above threshold.
- `critical` (private-key): always fails CI.
- `low` (naming.*, test-quality.*, dead-code.empty-block, docs.*, size.parameter-count, design composites): visible in reports; informational unless the adopter lowers `--min-severity` to `low`.

This severity discipline is what makes the default-on flip safe: adopters won't get a wall of CI failures from the naming/test-quality/design families, but they'll see the findings and can act on them.

## Follow-up

- The 3 `naming.receiver-consistency` dogfood findings on `Registry` (`applyEnablement`, `applySeverities`, `refreshActiveRules`) are real — the right fix is to make `Registry` consistently pointer-receiver, not flip the three outliers. Tracked separately from this ADR.
- `.gruff-go.yaml` keeps explicit per-rule pins where the project's policy is stricter than the new defaults (e.g. `complexity.nesting-depth: threshold: 4`, `size.parameter-count: threshold: 5`). These are project overrides, not bugs in the new default table.
