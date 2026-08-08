---
category: hooks
last_reviewed: 2026-08-08
---

# Hook Footguns

## Footgun: `deny-dangerous` rejects a leading `$VAR` in a delete target but allows one mid-path

**Status:** active | **Created:** 2026-08-08 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Do not treat a passing `deny-dangerous` check as proof a recursive delete stays inside the project when the target contains a variable anywhere after the first character.
**Trigger phase:** ACT

hallucination-risk: medium (the guard's own comment says an unresolved expansion "can point anywhere once the shell expands it", which reads as full coverage, but the test it describes is a prefix test)

`.goat-flow/hooks/deny-dangerous/patterns-shell.sh` (search: `Demand an explicit literal path`) rejects a target that *begins* with `$` or a backtick. A target that merely *contains* one passes, and the neighbouring `..` traversal check runs against the pre-expansion string, so it sees nothing. Raised by coderabbit on PR #6.

Measured 2026-08-08 with `bash .goat-flow/hooks/deny-dangerous.sh --check="<command>"`, one run each:

| Delete target shape | Result |
|---|---|
| known-blocked control (`git push origin main`) | rc=2, so the probe reaches the policy |
| scoped literal (`cache/build`) | rc=0, allowed by design |
| leading variable (`$HOME/.cache`) | rc=2 |
| mid-path backtick (``cache/`echo x` ``) | rc=2 |
| **mid-path variable (`cache/$TARGET`, `./cache/${TARGET}`)** | **rc=0, allowed** |

With `TARGET=../../outside` the last shape deletes outside the project after expansion.

How to avoid: when a delete target is not a literal path, do not rely on the hook - resolve the variable and pass the expanded literal, or refuse the command. Probe with `--check=` before assuming a shape is covered, and always include a known-blocked control in the same run: an incorrectly invoked probe returns rc=0 for everything, including targets the live hook blocks. This file is goat-flow-managed, so fix it upstream rather than patching in tree, where the next `goat-flow install` would revert it.

## Footgun: the agent hook re-implements `internal/diff` changed-region logic in bash — the two drift

**Status:** active | **Created:** 2026-06-04 | **Evidence:** OBSERVED

hallucination-risk: high (both layers "do changed-region scoping", so a fix to the Go core reads as done even though the bash hook silently kept the old behaviour)

`.goat-flow/hooks/gruff-code-quality.sh` derives changed-line ranges and selects changed-region scoping **in bash**, independently of the Go pipeline it shells out to (`internal/diff`, `internal/analysis`). They are not one source of truth, so a correctness fix that lands in one half does not propagate to the other. PR #4's automated review (chatgpt-codex / cursor) caught three concrete drifts after the Go side was hardened:

- **Deletion-only hunks.** `internal/diff/diff.go` (search: `func addHunkLines`) anchors a zero-count `+N,0` hunk to the line before the removed block; `.goat-flow/hooks/gruff-code-quality.sh` (search: `parse_diff_ranges`) drops it, so a delete-only edit reports no changed lines and is skipped.
- **Native vs fallback scoping.** `internal/analysis` / `internal/cli` gained `--changed-ranges` / `--changed-scope` / `--no-baseline` (search: `func resolveChangedScope`), but the hook's capability probe (search: `supports_native_changed_regions`) hard-coded `gruff-py` as the only native binary, so Go edits fell back to portable primary-line filtering instead of symbol-aware scoping.
- **Staged edits.** the hook's git fallback (search: `git_diff_ranges`) ran a bare `git diff` (unstaged only), so a staged-only edit yielded empty ranges.

Native-scope detection and staged-edit collection were fixed 2026-06-04 (see `CHANGELOG.md`, search: `Agent hook changed-region parity with the analyzer`). Deletion anchoring is correct in `internal/diff`, but the managed GOAT Flow v1.15.0 hook still skips `count == 0`, so deletion-only edits produce no changed lines. The structural trap remains because the Bash hook is a parallel implementation of the Go core.

How to avoid:
- When you change changed-region derivation or scoping in `internal/diff` / `internal/analysis`, immediately re-read `.goat-flow/hooks/gruff-code-quality.sh` (`parse_diff_ranges`, `git_diff_ranges`, `changed_ranges`, `supports_native_changed_regions`, `run_gruff_json`) and mirror the change. Prefer probing the binary (`analyse --help`) over hard-coding which port supports a flag.
- The v1.15.0 hook's `--self-test=smoke` (search: `self_test`) pins the help-probed native-scope selection but has no deletion-only assertion; an `ok` result therefore does not prove deletion coverage. Any upstream repair must add that regression case before the installed hook can be trusted for delete-only edits.
- E2E the hook by overriding `HOME` to a temp dir whose `.local/bin/<binary>` is a logging wrapper (an early `discover_binary` candidate, search: `discover_binary`), then feed a payload on stdin while running from a subdirectory — that proves both the flags passed and the working directory used. Do not put the logging wrapper in `$root/bin/`: that directory contains the tracked `bin/gruff-go.sh` launcher and ignored local analyzer output, so a wrapper there can shadow normal analyzer discovery. See the resolved `bin/gruff-go` footgun in `build-artifacts.md`.

## Footgun: the hook is advisory exit 0 with in-band skip/ignore reporting — do not make it exit 2

**Status:** active | **Created:** 2026-06-14 | **Evidence:** OBSERVED

`analyse` exits 2 when every explicit input is skipped before parsing: `ReportAllSkippedInputs` adds an error diagnostic and `ResolveExitCode` (`internal/analysis/report.go`, search: `func ResolveExitCode`) returns 2 for any diagnostic. The `hook` command deliberately does NOT mirror this — it omits `ReportAllSkippedInputs` and returns exit 0 for ignored/skipped explicit inputs, surfacing them in-band through the `gruff.hook.v1` payload (`internal/cli/hook.go`, search: `analysisReport.Summary.ExitCode == 2`; the contract's `Ignored.Paths` field). The hook contract is advisory exit 0 with structured `ignored`/`suppressed`/`config` fields so a PostToolUse hook never hard-fails an agent on an ignored path. A PR reviewer (Cursor, PR #5) read this as an inconsistency bug; it is intended behaviour.

How to avoid:
- Do not add `ReportAllSkippedInputs: true` (or any analyse-style fail-louder option) to the hook's `analysis.Options` to "fix" the apparent inconsistency. It breaks the advisory contract and `internal/cli/hook_test.go` (search: `TestHookReportsIgnoredPathsAndConfigErrors`), which pins exit 0 plus `Ignored.Paths` for a config-ignored explicit input. If a skipped explicit path should be more visible to agents, add it to an in-band payload field, not the exit code.
