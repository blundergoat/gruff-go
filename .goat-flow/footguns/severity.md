---
category: severity
last_reviewed: 2026-05-25
---

# Severity Footguns

## Footgun: `Confidence` vocabulary shadows the pre-ADR-009 severity vocabulary

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

hallucination-risk: high (an agent sweeping for "stale severity names" after ADR-009 will see `"high"`, `"medium"`, `"low"`, `"info"` in many golden files and source files, and may try to "fix" them — but a chunk of those strings are valid current values for the `Confidence` field, which is a separate enum)

Evidence:
- `internal/finding/types.go` (search: `Confidence`) — `Confidence` is still a 4-bucket enum (`ConfidenceInfo`, `ConfidenceLow`, `ConfidenceMedium`, `ConfidenceHigh`). It was *not* touched by ADR-009.
- `internal/cli/testdata/golden/analyse-composite-sarif.golden` (search: `"confidence":`) — JSON entries throughout this file legitimately carry `"confidence": "high"`, `"confidence": "medium"`, `"confidence": "low"` under the new severity model. These are correct, not stale.
- `internal/rule/calibration_test.go` (search: `ConfidenceHigh`, `ConfidenceMedium`) — calibration assertions deliberately combine the new severity vocabulary with the unchanged confidence vocabulary, e.g. `findings[0].Severity == finding.SeverityError && findings[0].Confidence == finding.ConfidenceHigh`.
- `internal/finding/finding_test.go` — the type's own tests pin both vocabularies side by side.

What this means in practice:
- After ADR-009, the strings `"critical"` and `"notice"` and `"warn"` are unambiguously stale wherever they appear — those values aren't in either enum's vocabulary anymore.
- The strings `"low"`, `"medium"`, `"high"`, `"info"` are *only* stale when attached to severity. As confidence values they remain canonical.
- A naive `rg "\"(critical|high|medium|low|info|notice|warn)\""` flushes out both categories together. The fixer must look at the surrounding key, struct tag, or column header before deciding to migrate.

How to avoid:
- When sweeping for stale severity references, anchor the grep to severity context where possible: `rg '(Severity|severity|fail-on|min-severity).*"(low|medium|high|critical|info|notice|warn)"'`. False negatives are possible (e.g. SARIF level mapping uses bare strings), so a manual second pass is still needed, but the anchored grep drops the confidence-field noise.
- In SARIF goldens, severities surface as the `level` field (`error` / `warning` / `note` after ADR-009's SARIF mapping simplification) and as `properties.severity` on rules. Confidence surfaces as `properties.confidence`. They are different keys; never edit one expecting to fix the other.
- When a sibling-port migration (gruff-rs / gruff-ts / gruff-py / gruff-php) eventually does the same severity collapse, expect this same trap to recur in each port, because confidence has not been harmonised across ports as of 2026-05-25.

## Footgun: Dashboard `fail-on` fallback must track the CLI default, not the previous one

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

hallucination-risk: medium (the migration touched the *parser* and the *CLI default* but not the dashboard fallback; the dashboard's fallback constant looks correct in isolation and only diverges when compared to `internal/cli/cli.go`'s default)

Evidence:
- `internal/dashboard/handler.go` (search: `failOn = finding.Severity`) — when `state.FailOn` is invalid and `opts.FailOn` doesn't parse, the dashboard falls back to a hard-coded severity. Pre-ADR-009 that fallback was `SeverityMedium` (the old CLI default). After ADR-009 the CLI default became `SeverityAdvisory` (search `cli.go`: `ADR-009: default is`), but the dashboard fallback was first migrated to `SeverityWarning` (the *renamed* old default), not `SeverityAdvisory`. That made the dashboard quietly stricter than the CLI by one bucket.
- The codex-connector bot reviewing PR #3 flagged this line as a "preserve legacy fail-on" concern; the actual bug it surfaces is a different one — the fallback target drifted from the CLI default during the rename.

What this means in practice: any time the CLI's default `--min-severity` changes, three places need to move in lockstep:
1. `internal/cli/cli.go` (the flag default, declared at the analyse-flag set).
2. `internal/dashboard/handler.go` (the in-server fallback when no valid fail-on is in scope).
3. The user-facing docs (`docs/configuration.md`, `docs/dashboard.md`, `docs/ci-integration.md`, `docs/output-formats.md`) — see the matching workflow lesson.

How to avoid:
- When the CLI default for `--min-severity` / `--fail-on` changes, grep for every reference to the *old* default constant (e.g. `SeverityWarning`, `SeverityMedium`) used as a fallback, not just as a value, and either replace it or extract a single `finding.DefaultMinSeverity` constant that both the flag default and the dashboard fallback consume.
- Suspicion-trigger: a code review comment that says "preserve legacy X" near a default-flip is often pointing at a real bug, even when the suggested fix (mapping old → new at runtime) is the wrong shape. Look at the *constant* being used for the fallback before deciding the comment is purely about backwards compatibility.
