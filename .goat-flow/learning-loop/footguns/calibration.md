---
category: calibration
last_reviewed: 2026-08-05
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

## Footgun: the scan-test-repos corpus is gitignored, so a root-relative scan finds nothing

**Status:** active | **Created:** 2026-06-14 | **Evidence:** OBSERVED

The precision corpus lives under `.goat-flow/scratchpad/scan-test-repos/`, which is gitignored in the gruff-go repo (search `.goat-flow/scratchpad/.gitignore`). Discovery honours `.gitignore`, so `gruff-go analyse .goat-flow/scratchpad/scan-test-repos/<repo>` from the gruff-go root prunes every file and exits 2 ("all explicit inputs skipped") with `files=0`. It reads like a clean scan when the scan never ran.

How to avoid:
- Scan each corpus repo as its own root: `( cd .goat-flow/scratchpad/scan-test-repos/<repo> && gruff-go analyse --format json --no-config . )`. Each vendored repo carries its own `.git`, so from inside it the gruff-go `.gitignore` no longer applies. This is what `scripts/calibrate-scratchpad-corpus.sh` does (search: `scan_module`, `cd "$module_root"`).
- Enumerate by `go.mod`, not top-level directory: StackChan's module root is `StackChan/server`, and `cli-printing-press` carries ~20 generated fixture submodules you usually want to ignore.
- `--include-ignored` also bypasses the prune, but pulls in each repo's own ignored build/vendor noise; prefer cd-per-repo.

## Footgun: finding filters do not isolate rule execution or scoring

**Status:** active | **Created:** 2026-08-05 | **Evidence:** OBSERVED

**Symptoms:** A probe run with `--include-rules naming.acronym-case` can render an empty `findings` array while the summary, composite, and exit code still reflect a hidden finding from another rule. This makes a matcher audit look internally inconsistent and can misclassify a clean fixture as failing.

**Why it happens:** `--include-rules`, `--exclude-rules`, `--include-pillars`, and `--exclude-pillars` are presentation filters. `internal/cli/cli.go` (search: `analysis.ApplyDisplayFilter`) runs the full configured registry first, then filters the finished report. `internal/analysis/display_filter.go` (search: `display filters do not change summary counts, score, or exit code`) deliberately preserves the original totals.

**Prevention:** Use a temporary config with `selection.rules` or `selection.pillars` when a calibration probe must execute only the target rules. Use the CLI include/exclude flags only when the full scan should still determine score and exit behavior. Put all `analyse` options before positional paths so the Go flag parser does not treat later options as input paths.
