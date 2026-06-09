# ADR-012: Baseline Three-State Classification API (new / unchanged / resolved)

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** Claude, human direction
**Ticket/Context:** Executes milestone `M24` (`.goat-flow/tasks/1.0.0/`). Foundation for `M26` (the `--fail-on-new` gate). Extends the baseline surface introduced in M04; constrained by [ADR-003](ADR-003-strict-json-operational-surfaces.md) (strict JSON) and the no-schema-bump kill-criteria of M24.

## Decision

Baselines become a three-state debt instrument - every current finding is classified `new`, `unchanged`, or `resolved` against the active baseline - **additively**, with no on-disk schema change and no fingerprint change.

1. **`baseline.ApplyResult` gains fields, not a new shape (option a).** Add `Unchanged []finding.Finding` (the findings a baseline entry matched - previously discarded after the `suppressed++` count) and `Resolved []Entry` (baseline entries that matched no current finding - the same set already counted as `StaleEntries`). `Findings` stays exactly the surviving "new" set; `SuppressedFindings` and `StaleEntries` stay populated for backward compatibility. Count helpers `NewCount()`/`UnchangedCount()`/`ResolvedCount()` read the slice lengths.

   *Rejected:* (b) a parallel `Classify` function - duplicates `Apply`'s matching loop, two code paths to keep in sync; (c) a `BaselineStatus` field on every `finding.Finding` - pollutes the finding model for all non-baseline runs and would change finding JSON shape on every scan.

2. **Resolved entries are `baseline.Entry`, not `finding.Finding`.** A resolved item is a baseline record with no current location - it has no live line, severity, or message to render through finding-shaped templates. Keeping it as `Entry` is honest about what is known.

3. **Counts always emit; detail arrays are opt-in.** `analysis.BaselineSummary` gains flat `newFindings`/`unchangedFindings`/`resolvedFindings` ints, emitted in every JSON-shaped report (additive - existing consumers ignore unknown keys). The `unchanged` / `resolved` **arrays** and the human-readable "Baseline status" sections render only under the new `analyse --baseline-show` flag, so default text/HTML output stays byte-identical to pre-M24. A `Show bool` (`json:"-"`) on `BaselineSummary` carries the directive to reporters without appearing in output.

4. **SARIF marks survivors `new`.** When a baseline is applied, each emitted SARIF result carries `baselineState: "new"` (SARIF 2.1.0 §3.27.25). gruff *suppresses* unchanged findings - they are not in `report.Findings` - so they are not emitted as SARIF results, and re-introducing them would violate M24's kill-criterion that `Findings` semantics must not depend on baseline state. The property therefore marks the new set for code-scanning dedupe rather than enumerating unchanged results. A future milestone may add `--baseline-show`-gated `unchanged` SARIF results if a consumer needs them.

## Context

`baseline.Apply` already computes everything the three states need - it just throws two of them away. Matched findings are counted (`suppressed++`) then dropped; stale entries are counted (`len(entries) - len(matched)`) but never collected. M24 is mostly *naming and surfacing* data that already exists, which is why it is additive and schema-stable. The risk is not the computation; it is the public surface (three call sites depend on `ApplyResult`: `internal/analysis/runner.go`, `internal/report/sensitive_redaction_test.go`, `internal/cli/cli_test.go`) and golden stability. Option (a) preserves every existing field, so those call sites compile and pass unchanged.

## Consequences

- M26 reads `ApplyResult.Findings` as the authoritative "new" set with no further work - the gate it builds is "fail on any new finding."
- JSON-shaped reports (`--format json`, `summary-json`) gain three additive count keys on the `baseline` object on **every** run, including no-baseline runs (where they are `0` alongside `applied:false`). This updates those goldens additively; SARIF and text/HTML defaults are unchanged.
- `--baseline-show` is a new `analyse` CLI flag (default off). No other command gains it.
- On-disk `gruff-go.baseline.v0.1`, `gruff-go.analysis.v0.2`, and `ComputeFingerprint` are untouched (verified by M24's static-contract checks).
- The SARIF "new-only" choice is a deliberate, documented limit, not an oversight - recorded here so a future agent does not "fix" missing `unchanged` results by re-surfacing suppressed findings.
