---
category: hooks
last_reviewed: 2026-06-06
---

# Hook Footguns

## Footgun: the agent hook re-implements `internal/diff` changed-region logic in bash — the two drift

**Status:** active | **Created:** 2026-06-04 | **Evidence:** OBSERVED

hallucination-risk: high (both layers "do changed-region scoping", so a fix to the Go core reads as done even though the bash hook silently kept the old behaviour)

`.goat-flow/hooks/gruff-code-quality.sh` derives changed-line ranges and selects changed-region scoping **in bash**, independently of the Go pipeline it shells out to (`internal/diff`, `internal/analysis`). They are not one source of truth, so a correctness fix that lands in one half does not propagate to the other. PR #4's automated review (chatgpt-codex / cursor) caught three concrete drifts after the Go side was hardened:

- **Deletion-only hunks.** `internal/diff/diff.go` (search: `func addHunkLines`) anchors a zero-count `+N,0` hunk to the line before the removed block; the hook's range parser (search: `parse_diff_ranges`) dropped them, so a delete-only edit reported no changed lines and was skipped.
- **Native vs fallback scoping.** `internal/analysis` / `internal/cli` gained `--changed-ranges` / `--changed-scope` / `--no-baseline` (search: `func resolveChangedScope`), but the hook's capability probe (search: `supports_native_changed_regions`) hard-coded `gruff-py` as the only native binary, so Go edits fell back to portable primary-line filtering instead of symbol-aware scoping.
- **Staged edits.** the hook's git fallback (search: `git_diff_ranges`) ran a bare `git diff` (unstaged only), so a staged-only edit yielded empty ranges.

All three were fixed 2026-06-04 (see `CHANGELOG.md`, search: `Agent hook changed-region parity with the analyzer`), but the **structural** trap remains: the bash hook is a parallel implementation of the Go core.

How to avoid:
- When you change changed-region derivation or scoping in `internal/diff` / `internal/analysis`, immediately re-read `.goat-flow/hooks/gruff-code-quality.sh` (`parse_diff_ranges`, `git_diff_ranges`, `changed_ranges`, `supports_native_changed_regions`, `run_gruff_json`) and mirror the change. Prefer probing the binary (`analyse --help`) over hard-coding which port supports a flag.
- The hook's `--self-test=smoke` (search: `self_test`) pins deletion-hunk anchoring and the help-probed native-scope selection; extend it whenever you mirror a new behaviour so the next drift is caught by the self-test, not by a reviewer.
- e2e the hook by overriding `HOME` to a temp dir whose `.local/bin/<binary>` is a logging wrapper (an early `discover_binary` candidate, search: `discover_binary`), then feed a payload on stdin while running from a subdirectory — that proves both the flags passed and the working directory used. Do NOT drop the wrapper into `$root/bin/`; that path holds a committed binary (see the `bin/gruff-go` footgun in `build-artifacts.md`).
