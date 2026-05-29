# ADR-011: Mission - Govern AI-Generated Code for Human Verification

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** Claude, human direction
**Ticket/Context:** Mission articulated by the maintainer on 2026-05-30 during the `complexity.npath` threshold review. Documented in the same change across `README.md`, [`.goat-flow/architecture.md`](../architecture.md), `CLAUDE.md`, and `AGENTS.md`.

## Decision

gruff-go's optimisation target is the **human-verifiability of AI-generated code**. Its primary deployment is a coding-agent hook: when an agent writes code, gruff is the gate that forces output a reviewer who did not write it can read, review, and sign off on. Three axes:

1. **Legible enough to verify** - a reviewer can confirm the code does what was asked.
2. **Secure where the eye fails** - it catches the security classes human review reliably misses.
3. **Tested for real, not padded** - it forces high-signal tests and rejects low-signal test ceremony.

This mission is the **tie-breaker for default, threshold, and rule decisions**: judge each by whether it raises the odds a human can verify the agent's code *without* forcing low-signal ceremony. Concretely:

- Size and complexity metrics are legibility backstops. Threshold pressure runs tighter, never looser, and a rule is never muted by threshold inflation to keep a scan green (see [ADR-008](ADR-008-external-codebase-calibration-precision-fixes.md): fix the precision bug in the rule, do not inflate thresholds).
- Doc and test rules are core, but only when they enforce *signal*: reject name-restatement comments (`minWordsBeyondSymbol`) and assertion-free tests. Otherwise gruff becomes the ceremony it opposes.
- Doc comments are mandatory even on a private one-liner because the prose (intent, usage, contract, failure behaviour) is what a reviewer checks the implementation against; a mismatch between the doc comment and the code is a signal the change needs a deeper look.
- Honest limit: parser-only gruff can *create* the artifact a reviewer checks (a doc comment, an assertion) but cannot verify that artifact is *truthful*. Semantic truth stays with the reviewer.

## Context

Until now the mission was implicit. `README.md` and `.goat-flow/architecture.md` framed gruff as a generic "code-quality scanner you run beside review." With no written optimisation target, rule and threshold decisions defaulted to the wrong test - "does this keep the dogfood scan green?" - instead of "does this serve human verification?"

Worked example (the trigger). `complexity.npath` was introduced in commit `29efb39` (2026-05-24) with registry default `1024`. gruff's own code already held three functions at NPath `5488 / 8227 / 8646` (`Config.RuleOptions`, `aggregatedPackageSummaryFindings`, `diff.Parse`) - all flat (control-flow nesting depth 2-3), wide sequential-branch parsers and validators that cyclomatic (<=19) and cognitive (<=34) correctly rank under threshold. Rather than ask whether the rule served the mission, the *same commit* set the dogfood threshold to `9000` to clear the existing maximum and keep the scan grade A. The rule was muted on its own repository on day one.

NPath multiplies sequential-but-simple branches, so it over-flags exactly the legible flat code the mission most wants to preserve, and its "execution-path count" framing pushes an agent toward combinatorial test enumeration - the low-signal test bloat axis 3 forbids. A written mission turns that from a judgement call into a clear conflict.

Evidence: commit `29efb39`; the metric distribution over gruff-go production code (npath p95 = 38, p99 = 391, then a gap to 5488+; the three outliers all at nesting depth 2-3); the README/architecture framing prior to this change.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Leave the mission implicit (status quo) | Decisions default to "keep the scan green" or to generic-linter norms; the npath->9000 mute is the worked example of the resulting error | Rejected. The implicit state already produced a wrong call. |
| Position gruff as a generic Go code-quality linter | Competes with `go vet` / `staticcheck` / `golangci-lint` on their terms, loses the one differentiator (governing AI output for human review), and gives no principle for default/threshold choices | Rejected. Undersells the tool and leaves rule decisions unanchored. |
| State the mission as the governing principle, in the truth-order docs plus this ADR | Adds a maintenance surface (mission prose in several files) that can drift | Accepted. The decision-procedure value - every default/threshold/rule judged against verifiability - outweighs the drift cost. `CLAUDE.md` and `AGENTS.md` carry the one-line form and point here. |

## Consequences

- Default/threshold/rule changes cite the mission. "Should we raise this threshold?" is answered against verifiability, and for size/complexity the default answer is no (pressure runs tighter, never looser).
- Rules are not muted by threshold inflation to keep dogfood green. A rule that misfires gets its precision fixed (ADR-008) or, if it cannot serve the mission, is reconsidered.
- `complexity.npath`'s resolution (fix the formula so sequential `continue`-guards stop multiplying, vs. demote to opt-in) follows from this ADR and is tracked separately. This ADR records *why* it must be resolved, not *which* option wins.
- Comment and test rules are held to a signal floor; weakening `minWordsBeyondSymbol` or accepting assertion-free tests is a mission regression, not a calibration.
- Public positioning (`README.md`, `package.json` metadata, the `cmd/gruff-go` package doc) should lead with the AI-code-verification mission as gruff matures toward public adoption.

## Reversibility

Two-way door, but intentionally sticky - this is a positioning/charter decision, not a mechanism. Revisit triggers: gruff's primary use shifts away from agent-generated code; a sibling `gruff-*` port adopts a different shared charter; or evidence that the verifiability framing produces worse rule decisions than a generic-linter framing would. Reverse by superseding this ADR, not by quietly reframing the docs.
