---
category: calibration
last_reviewed: 2026-05-30
---

# Calibration Footguns

## Footgun: "dogfood must be grade A" tempts you to mute a tripping rule with a per-repo threshold override

**Status:** active | **Created:** 2026-05-30 | **Evidence:** OBSERVED

The project invariant is that `go run ./cmd/gruff-go analyse .` returns grade A on `main`. When you add or tighten a default rule and the dogfood scan trips, the path of least resistance is to bump a threshold in `.gruff-go.yaml` to silence it. Do not - the override hides an FP-prone default that still ships to every adopter.

Evidence:
- `complexity.npath` shipped with registry default `1024` and, in the **same commit** (`29efb39`, search `.gruff-go.yaml`: `complexity.npath`), got a per-repo `threshold: 9000` override to clear gruff's own three flat-but-wide functions (`internal/diff/diff.go` `Parse`, `internal/config/config.go` `Config.RuleOptions`, `internal/rule/comment_rubric.go` `aggregatedPackageSummaryFindings`) and keep the scan green.
- The rule was muted on its own repo on day one and never fired here, while the FP-prone `1024` default shipped to adopters. The override hid the problem instead of fixing it. Full analysis: [ADR-011](../decisions/ADR-011-mission-ai-generated-code-verifiability.md) and `.goat-flow/tasks/1.0.0/M00-remove-npath-false-positives.md`.

The three correct responses (never the override):
- Fix the rule's precision so it stops misfiring (per [ADR-008](../decisions/ADR-008-external-codebase-calibration-precision-fixes.md): fix the rule, don't inflate the threshold).
- If the rule does not serve the mission, demote (`DefaultEnabled: false`) or remove it (ADR-011).
- If the flagged code is genuinely bad, refactor it - that is the rule working.

How to avoid: when dogfood trips on a rule change, ask "is this code actually bad, or is the rule misfiring?" Cross-check a flagged function's nesting depth against its cyclomatic/cognitive scores (see the nesting cross-check in `M00-remove-npath-false-positives.md`) before doing anything. Never reach for a per-repo threshold bump to restore grade A. Directly relevant whenever M28 / M29 / M30 add new default rules.
