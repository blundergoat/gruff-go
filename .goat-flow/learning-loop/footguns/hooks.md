---
category: hooks
last_reviewed: 2026-08-11
---

# Hook Footguns

## Footgun: the agent hook re-implements `internal/diff` changed-region logic in bash — the two drift

**Status:** active | **Created:** 2026-06-04 | **Evidence:** OBSERVED

hallucination-risk: high (both layers "do changed-region scoping", so a fix to the Go core reads as done even though the bash hook silently kept the old behaviour)

`.goat-flow/hooks/gruff-code-quality.sh` derives changed-line ranges and selects changed-region scoping **in bash**, independently of the Go pipeline it shells out to (`internal/diff`, `internal/analysis`). They are not one source of truth, so a correctness fix that lands in one half does not propagate to the other. PR #4's automated review (chatgpt-codex / cursor) caught three concrete drifts after the Go side was hardened:

- **Deletion-only hunks.** `internal/diff/diff.go` (search: `func addHunkLines`) anchors a zero-count `+N,0` hunk to the line before the removed block; `.goat-flow/hooks/gruff-code-quality.sh` (search: `parse_diff_ranges`) drops it, so a delete-only edit reports no changed lines and is skipped.
- **Native vs fallback scoping.** `internal/analysis` / `internal/cli` gained `--changed-ranges` / `--changed-scope` / `--no-baseline` (search: `func resolveChangedScope`), but the hook's capability probe (search: `supports_native_changed_regions`) hard-coded `gruff-py` as the only native binary, so Go edits fell back to portable primary-line filtering instead of symbol-aware scoping.
- **Staged edits.** the hook's git fallback (search: `git_diff_ranges`) ran a bare `git diff` (unstaged only), so a staged-only edit yielded empty ranges.

Native-scope detection and staged-edit collection were fixed 2026-06-04 (see `CHANGELOG.md`, search: `Agent hook changed-region parity with the analyzer`). Deletion anchoring is correct in `internal/diff`, but the managed GOAT Flow v1.15.1 hook still skips `count == 0` (search: `Zero added lines is a deletion-only hunk`), so deletion-only edits produce no changed lines; the hook now returns a distinct code 10 (search: `A hunk with no added lines is a completed not-applicable deletion analysis`) instead of an empty range, which reports the gap without closing it. The structural trap remains because the Bash hook is a parallel implementation of the Go core.

How to avoid:
- When you change changed-region derivation or scoping in `internal/diff` / `internal/analysis`, immediately re-read `.goat-flow/hooks/gruff-code-quality.sh` (`parse_diff_ranges`, `git_diff_ranges`, `changed_ranges`, `supports_native_changed_regions`, `run_gruff_json`) and mirror the change. Prefer probing the binary (`analyse --help`) over hard-coding which port supports a flag.
- The v1.15.1 hook's `--self-test=smoke` (search: `self_test`) pins the help-probed native-scope selection but still never calls `parse_diff_ranges`, so it has no deletion-only assertion; an `ok` result therefore does not prove deletion coverage. Any upstream repair must add that regression case before the installed hook can be trusted for delete-only edits.
- E2E the hook by overriding `HOME` to a temp dir whose `.local/bin/<binary>` is a logging wrapper (an early `discover_binary` candidate, search: `discover_binary`), then feed a payload on stdin while running from a subdirectory — that proves both the flags passed and the working directory used. Do not put the logging wrapper in `$root/bin/`: that directory contains the tracked `bin/gruff-go.sh` launcher and ignored local analyzer output, so a wrapper there can shadow normal analyzer discovery. See the resolved `bin/gruff-go` footgun in `build-artifacts.md`.

## Footgun: the hook is advisory exit 0 with in-band skip/ignore reporting — do not make it exit 2

**Status:** active | **Created:** 2026-06-14 | **Evidence:** OBSERVED

`analyse` exits 2 when every explicit input is skipped before parsing: `ReportAllSkippedInputs` adds an error diagnostic and `ResolveExitCode` (`internal/analysis/report.go`, search: `func ResolveExitCode`) returns 2 for any diagnostic. The `hook` command deliberately does NOT mirror this — it omits `ReportAllSkippedInputs` and returns exit 0 for ignored/skipped explicit inputs, surfacing them in-band through the `gruff.hook.v1` payload (`internal/cli/hook.go`, search: `analysisReport.Summary.ExitCode == 2`; the contract's `Ignored.Paths` field). The hook contract is advisory exit 0 with structured `ignored`/`suppressed`/`config` fields so a PostToolUse hook never hard-fails an agent on an ignored path. A PR reviewer (Cursor, PR #5) read this as an inconsistency bug; it is intended behaviour.

How to avoid:
- Do not add `ReportAllSkippedInputs: true` (or any analyse-style fail-louder option) to the hook's `analysis.Options` to "fix" the apparent inconsistency. It breaks the advisory contract and `internal/cli/hook_test.go` (search: `TestHookReportsIgnoredPathsAndConfigErrors`), which pins exit 0 plus `Ignored.Paths` for a config-ignored explicit input. If a skipped explicit path should be more visible to agents, add it to an in-band payload field, not the exit code.

## Footgun: protected-path literals inside data filters can trigger the secret-file guard

**Status:** active | **Created:** 2026-08-11 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Before retrying a blocked data-classification command, distinguish a protected operand from a protected-looking literal inside the filter program; reformulate only when every real input is verified non-secret.
**Trigger phase:** VERIFY
**Incident count:** 1
**Latest occurrence:** 2026-08-11

hallucination-risk: medium

A read-only Vault measurement was blocked before execution even though its file operands were the repository, a redacted gruff JSON report in `/tmp`, and ordinary output files. An inline AWK suffix classifier named a protected environment-file pattern, and the guard reported `Secret-file access (jq)` for the surrounding data-filter pipeline. Replacing that special case with a generic suffix classifier left the inputs and measurement unchanged and allowed the command to run.

Evidence: `.goat-flow/hooks/deny-dangerous/patterns-paths.sh` (search: `check_secret_segment`) applies option-aware local-file parsing only to curl and recognized search commands. Other verbs fall through to `is_secret_path_touch` over the whole command text, so a protected-looking literal in a jq/AWK program is indistinguishable from an operand.

How to avoid:
- Treat the block as real until every command operand and redirection target has been checked. Never reformulate a command that actually reads or writes a protected file.
- For verified non-secret reports, prefer generic extension or type classification that does not embed protected path names in the filter source.
- Record that the original command did not execute; only the successful reformulated run is measurement evidence.

## Resolved Entries

## Footgun: `deny-dangerous` rejected a leading `$VAR` in a delete target but allowed one mid-path

**Status:** resolved | **Created:** 2026-08-08 | **Resolved:** 2026-08-11 | **Evidence:** ACTUAL_MEASURED

Under GOAT Flow v1.15.0 the delete-target guard rejected a target that *begins* with `$` or a backtick, while a target that merely *contains* one passed. The neighbouring `..` traversal check ran against the pre-expansion string, so it saw nothing, and `cache/$TARGET` with `TARGET=../../outside` deleted outside the project after expansion. Raised by coderabbit on PR #6.

The v1.15.1 guard tests for the expansion anywhere in the target rather than only at the front: `.goat-flow/hooks/deny-dangerous/patterns-shell.sh` (search: `Any unresolved expansion can move a reviewed cleanup outside the project`) matches `*'$'*` and `` *'`'* ``. Re-measured 2026-08-11 with `bash .goat-flow/hooks/deny-dangerous.sh --check="<command>"`, one run each:

| Delete target shape | v1.15.0 | v1.15.1 |
|---|---|---|
| known-blocked control (`git push origin main`) | rc=2 | rc=2, so the probe reaches the policy |
| scoped literal (`cache/build`) | rc=0 | rc=0, allowed by design |
| leading variable (`$HOME/.cache`) | rc=2 | rc=2 |
| mid-path backtick (``cache/`echo x` ``) | rc=2 | rc=2 |
| **mid-path variable (`cache/$TARGET`, `./cache/${TARGET}`)** | **rc=0, allowed** | **rc=2, blocked** |

What carries forward: the probe discipline, not the gap. Always include a known-blocked control in the same run - an incorrectly invoked probe returns rc=0 for everything, including targets the live hook blocks. This file is goat-flow-managed, so a future gap belongs upstream rather than patched in tree, where the next `goat-flow install` would revert it.
