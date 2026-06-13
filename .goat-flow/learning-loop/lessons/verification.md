---
category: verification
last_reviewed: 2026-06-14
---

# Verification Lessons

## Lesson: reproduce a coding-agent PR-review finding before fixing it

**Created:** 2026-06-14

Coding-agent reviewers (Codex, Cursor, Copilot, CodeRabbit) describe behaviour they infer from a diff, and some of that inferred behaviour is intended, not a bug. In PR #5's second review wave, six findings all looked valid on a read; writing a failing-first test (or a throwaway probe) for each showed two were false alarms, and I had already started building both fixes before the reproduction step caught them:

- **Codex "accept testify assertion object methods"** claimed `r := require.New(t); r.NoError(err)` false-positives in `test-quality.no-failure-path`. It does not: `require.New(t)` is itself a recognised failure call. `internal/rule/test_quality.go` (search: `hasAssertionLibrarySelector`) accepts any `require.*`/`assert.*` call that takes a testing receiver, `New` included. A probe (`_ = require.New(t)` with no method calls) returned zero findings, proving the pattern was already handled. The speculative fix was reverted.
- **Cursor "hook skips all-skipped diagnostics"** claimed `hook` should exit 2 like `analyse`. Setting `ReportAllSkippedInputs` on the hook broke `internal/cli/hook_test.go` (search: `TestHookReportsIgnoredPathsAndConfigErrors`): the hook is deliberately advisory exit 0 and surfaces ignored/skipped paths in-band, not as an exit-2 diagnostic. See the hook-contract footgun ("the hook is advisory exit 0 with in-band skip/ignore reporting") in `../footguns/hooks.md`.

The four genuine findings (PEM inline-literal false negative, nested-goroutine sleep whitelisting, wall-clock-only polling exit, dropped package-level finding) each had a test that failed at HEAD and passed after the fix.

How to avoid:
- For every PR-bot finding, write the failing-first test (or a quick probe) that reproduces the claim against current code BEFORE writing the fix. If it passes at HEAD, the finding describes intended behaviour — skip it with a one-line reason; do not ship a fix for a non-bug.
- Trust the reproduction over inspection. Both false alarms read as plausibly correct; only running them exposed the truth. "I agree with it" after reading a diff is not evidence.
