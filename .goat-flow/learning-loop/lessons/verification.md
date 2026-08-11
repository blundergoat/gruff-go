---
category: verification
last_reviewed: 2026-08-12
---

# Verification Lessons

## Lesson: reproduce a coding-agent PR-review finding before fixing it

**Created:** 2026-06-14
**Decision changed:** Re-run the exact failing probe after each semantic fix; do not infer success from changing the review-commented helper.
**Trigger phase:** VERIFY
**Incident count:** 8
**Latest occurrence:** 2026-08-12

Coding-agent reviewers (Codex, Cursor, Copilot, CodeRabbit) describe behaviour they infer from a diff, and some of that inferred behaviour is intended, not a bug. In PR #5's second review wave, six findings all looked valid on a read; writing a failing-first test (or a throwaway probe) for each showed two were false alarms, and I had already started building both fixes before the reproduction step caught them:

- **Codex "accept testify assertion object methods"** claimed `r := require.New(t); r.NoError(err)` false-positives in `test-quality.no-failure-path`. It does not: `require.New(t)` is itself a recognised failure call. `internal/rule/test_quality.go` (search: `hasAssertionLibrarySelector`) accepts any `require.*`/`assert.*` call that takes a testing receiver, `New` included. A probe (`_ = require.New(t)` with no method calls) returned zero findings, proving the pattern was already handled. The speculative fix was reverted.
- **Cursor "hook skips all-skipped diagnostics"** claimed `hook` should exit 2 like `analyse`. Setting `ReportAllSkippedInputs` on the hook broke `internal/cli/hook_test.go` (search: `TestHookReportsIgnoredPathsAndConfigErrors`): the hook is deliberately advisory exit 0 and surfaces ignored/skipped paths in-band, not as an exit-2 diagnostic. See the hook-contract footgun ("the hook is advisory exit 0 with in-band skip/ignore reporting") in `../footguns/hooks.md`.

The four genuine findings (PEM inline-literal false negative, nested-goroutine sleep whitelisting, wall-clock-only polling exit, dropped package-level finding) each had a test that failed at HEAD and passed after the fix.

PR #6 repeated the lesson at a finer boundary. A first fix keyed parsed URL receivers by `ast.Object`, but the regression still failed because the shared taint registry remained keyed by identifier text. The durable change had to carry lexical identity through `internal/rule/security_request_source.go` (search: `taintedBindings`) and the taint-position helper, not only through `parsedURLStringReceiver`. In the same verification pass, a redirect dominance check was accidentally added to the parsed-URL helper that already had it; the focused optional-prefix test stayed red until the check moved to `bodyHasCommittedRelativePrefix`. Both errors looked complete in the diff and were exposed only by re-running the exact reproductions.

The same turn also patched a repeated `type getter` anchor inside an embedded Go fixture instead of after the enclosing test. `gofmt` rejected the host test file immediately. Numbered context around a repeated patch anchor is part of verification when tests embed the same language they are written in; a syntactic match does not establish the intended structural location.

A proactive HTTP-client timeline test then caught a Go-specific binding mistake: `statement.Tok == token.DEFINE` does not mean every left-hand name is newly declared. In `client, marker := ...`, `client` can keep an earlier interface type while only `marker` is new. The corrected implementation checks `identifier.Obj.Decl == statement` before recording an inferred concrete type (search: `recordInferredClientType`).

The first leading-zero hook probe used a byte limit of `08`. After decimal normalization, that value correctly became an 8-byte policy limit and rejected the larger clean fixture, so the probe still failed for the intended policy rather than for octal parsing. Repeating it with `01048576` kept the normal 1 MiB policy and isolated the arithmetic representation; that case exited cleanly.

A full semantic pass found that the HTTP-client timeline asked whether an optional replacement branch contained the earlier client assignment. That is the wrong dominance relation: a replacement matters when its branch contains the later request. A focused case with both the custom-client assignment and request inside one optional branch reproduced the false finding. Comparing the replacement's control regions with the sink position fixed that case without hiding the existing case where the request remains outside an optional replacement branch.

The final Task 1 replay initially labelled valid JSON as `json=no` because its probe guessed the analysis schema was `gruff-go.report.v0.1`; the binary emitted `gruff.analysis.v2`. Both command orders had already exited zero with byte-identical output. The corrected replay decoded the payload and required an object with a string schema identifier, which tests the requested format without coupling the flag-order proof to an unrelated schema literal.

The first final dogfood scan stayed at grade A but returned one `size.function-length` warning because the accumulated redirect regressions had grown one test function to 97 code lines. Splitting the optional-constraint cases into `TestOpenRedirectConstraintDominance` restored the zero-finding project contract without changing the rule threshold or registry policy.

How to avoid:
- For every PR-bot finding, write the failing-first test (or a quick probe) that reproduces the claim against current code BEFORE writing the fix. If it passes at HEAD, the finding describes intended behaviour — skip it with a one-line reason; do not ship a fix for a non-bug.
- Trust the reproduction over inspection. Both false alarms read as plausibly correct; only running them exposed the truth. "I agree with it" after reading a diff is not evidence.
- When a focused test stays red after a plausible fix, trace the semantic fact through every producer and consumer. A binding-safe lookup is still unsafe if an earlier registry collapsed bindings by name.
- Before patching repeated syntax in a test file, inspect the enclosing numbered context so an embedded fixture is not mistaken for host code.
- When Go syntax mixes declaration and assignment, use the resolved declaration object instead of inferring binding status from the statement token alone.
- Choose reproduction values that change only the suspected mechanism. A valid but stricter limit cannot prove numeric parsing because it also changes the policy outcome.
- Express control-flow claims relative to the operation they protect or replace. For a write that must supersede state at a sink, test whether the sink lies inside every optional region around the write—not whether the earlier state-producing write does.
- Assert only the contract under test. A flag-order reproduction needs valid, identical JSON; hard-coding a remembered schema name adds a separate failure mode and can turn correct behavior into a false red result.
- Run the dogfood gate after expanding table or subtest collections. Passing Go tests do not catch a test function that crosses the repository's own maintainability threshold; split it by behavior before changing policy.
