# ADR-008: External-Codebase Calibration as the Precision-Tuning Loop

**Status:** Accepted
**Date:** 2026-05-20
**Author(s):** Claude, human direction
**Ticket/Context:** Spot-check of `blundergoat-platform/apps/api` (~115 files / 480 non-test functions). Resulted in commit `b4998b6` plus the follow-up edits to `internal/rule/sensitive.go`, the `builtin_test.go` split, and `CHANGELOG.md` under `[Unreleased]`.

## Context

The default rule pack (ADR-007) ships every rule enabled. Until M29 the only calibration loop was the dogfood scan against `gruff-go` itself, which has roughly 80 source files of careful, well-styled Go. Running gruff-go against a foreign codebase exposed precision problems that dogfood could not surface, because the dogfood codebase never produces the patterns where the rules misfire.

A spot-check pass on `blundergoat-platform/apps/api` with `--no-config` defaults produced **119 findings** across 115 files. Sampling ~100 of those findings revealed a clear pattern:

| Rule | Findings | False-positive rate observed |
| --- | --- | --- |
| `sensitive-data.connection-string` (HIGH) | 10 | 10/10 — all comments, doc snippets, or `dev_password_change_me`-style fixtures |
| `test-quality.no-failure-path` | 64 | ≈64/64 — tests delegate assertions to helpers (`testutil.AssertStatus(t, ...)`) that the parser-only rule cannot see across |
| `test-quality.skipped-test` | 7 | 7/7 — every skip was `if !infrastructureAvailable() { t.Skipf(...) }`, the standard integration-test guard |
| `size.function-length` | 14 | Multiple borderline — heavily commented dispatchers and Go's `func XHandler(deps) http.HandlerFunc { return func(w, r) {...} }` closure factories were measured by raw line span, including doc/comment lines |
| `naming.get-prefix` | 0 | False **negative** — the rule explicitly required a receiver, so common context-value accessors (`middleware.GetLogger(ctx)`, `GetRequestID(ctx)`) went unflagged |

The shared failure mode was a parser-only rule reasoning about raw text or AST shape without recognising widely-used idioms: Go-style doc snippets that contain example URLs, helper-function assertions, conditional test skips, golangci-lint's `//nolint` opt-outs, the closure-factory handler pattern, and the context-getter convention. Each pattern is conventional enough that calibrating against it is more valuable than weakening the underlying rule.

## Decision

External-codebase calibration is a first-class precision-tuning loop. When dogfood remains grade A but a sampled foreign codebase shows a recurring false-positive (or false-negative) pattern that maps to a conventional Go idiom, we adjust the rule rather than expecting users to opt out.

Operationally:

1. **Calibration changes preserve precision direction.** A change must reduce false positives (or false negatives) without making the rule cease to fire on the genuine signal it was built for. New tests in the rule's `_test.go` lock both halves: at least one new test for the idiom we now accept (or now catch), and at least one for the dangerous shape we must still flag.
2. **Convention-recognition belongs in the rule, not in user config.** Where Go ecosystem conventions already encode "this is fine" (gosec `#nosec`, golangci-lint `//nolint:<linter>` / `//nolint:all`, `if cond { t.Skip(...) }`, `Assert*`/`Require*` helper naming), the rule should recognise them out of the box. Per-project allowlists are still available for project-specific exceptions but should not be the first answer for a recognised convention.
3. **Dogfood is the floor, not the ceiling.** A change that keeps dogfood grade A is the minimum bar. It must also be re-validated against the calibration codebase (or an equivalent sample) and the before/after counts recorded in the PR description.
4. **The seed calibration corpus is `blundergoat-platform/apps/api`.** It is a real Go-Chi service with closure-factory handlers, sqlc-generated code, integration tests, and idiomatic helper packages — patterns that gruff-go's own source does not produce. The codebase is not vendored; calibration is run by pointing the locally-built scanner at the user's local checkout. Adding additional calibration corpora is a strict extension and does not require a new ADR.

The six precision fixes shipped under this decision are the ones in `CHANGELOG.md [Unreleased]` and listed below. They are the worked example of the loop, not the entirety of the decision.

| Rule | Convention now recognised | Still fires on |
| --- | --- | --- |
| `sensitive-data.*` | `//` and `/* */` comment lines; same-line `#nosec` / `//nolint:gosec` / `//nolint:all` | Tokens in real source positions |
| `sensitive-data.connection-string` | localhost-style host + placeholder password substring (`change_me`, `pass`, `invalid`, `dummy`, …) | Real-looking credentials, non-local hosts, or both |
| `test-quality.no-failure-path` | `Assert*`/`Require*`/`Expect*`/`Must*`/`Check*` helpers when the testing receiver is one of the call arguments | Tests with no assertion-helper calls and no direct receiver failure calls |
| `test-quality.skipped-test` | Skips reachable only through `if`/`for`/`switch`/`range`/`select` bodies | Unconditional skips, and conditional skips whose message mentions TODO/FIXME/XXX/HACK/WIP |
| `size.function-length` | Comment-only and blank lines (length is now counted in code-bearing lines via `go/scanner`); `//nolint:funlen` / `//nolint:all` directly attached to the function doc | Functions whose code-line count exceeds the threshold |
| `naming.get-prefix` | Extended to free functions with a single `context.Context` parameter returning one value (or one value + error) | Receiver methods (unchanged), and the newly covered context-accessor shape |

2026-05-23 follow-up calibration: the `naming.get-prefix` context-accessor extension was narrowed back out of the default rule after the same corpus showed `GetLogger(ctx)` and `GetRequestID(ctx)` were conventional helper names rather than useful findings. `security.sql-string-query` also gained a test-support carve-out for fixed-prefix integration-test schema creation (`CREATE SCHEMA ` + `fmt.Sprintf("test_*_%d", time.Now().UnixNano())`) after rescans showed only parser-only noise in `_test.go` and `internal/testutil` setup helpers. Receiver `Get*` methods and arbitrary dynamic SQL/schema variables remain in scope.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep raising thresholds globally until noise drops | Hides genuine signal alongside false positives; weakens the rule's contract; same noise reappears on the next foreign codebase | Rejected. Threshold inflation does not address the precision bug. |
| Push every noisy pattern into per-project allowlists | Forces every new user to discover and configure the same exceptions; gruff-go effectively ships an unusable default | Rejected. ADR-007 commits to a usable default pack; convention recognition is what makes that promise hold. |
| Lower default severities (e.g. drop sensitive-data.connection-string to LOW) | Stops the alert-fatigue symptom but the rule still misfires on doc snippets; the credential check loses its teeth for the real case | Rejected. Symptom relief, not a fix. |
| Recognise Go ecosystem conventions in the rule itself | Adds modest complexity to each rule; needs both positive and negative tests to prevent regression | Accepted. Conventions are stable and small in number; tests pin both halves. |
| Hold dogfood as the only acceptance gate | Dogfood does not produce the failing patterns, so the precision bugs are invisible to it | Rejected. Dogfood remains the floor; calibration is the additional gate. |

## Consequences

- New default-enabled rules must be calibrated against the calibration corpus before merge. PR description records before/after finding counts.
- Each rule's `_test.go` carries explicit positive and negative tests for any convention the rule recognises. Removing or weakening recognition requires updating both halves.
- Rule changes that flip dogfood grade still go through ADR-007's "ask first" gate; calibration changes that keep dogfood grade A do not.
- When a finding message changes (as `size.function-length` did), the CLI goldens are regenerated with `UPDATE_GOLDEN=1` and the diff reviewed. The metadata is allowed to add fields (e.g. `rawLines`) for downstream compatibility.
- Future calibration passes should expect new patterns: the next foreign codebase will surface idioms this one did not. The decision is the loop, not the specific six fixes.

## Reversibility

Two-way door. Each convention recognition can be removed independently (delete the helper + the positive test) if it later proves to swallow real signal. Reversal triggers:

- A genuine credential leak that pattern-matches a placeholder password on a local host (would weaken `isPlaceholderConnectionString`).
- A test that legitimately fails via an `Assert*`-named helper that does NOT take the testing receiver (would weaken `isAssertionHelperCall`).
- A conditional skip that hides debt without a TODO/FIXME marker becoming a recurring incident (would tighten the `skipped-test` heuristic).
- `//nolint:funlen` becoming a load-bearing escape hatch instead of an exception (would warrant disabling the directive recognition project-wide).

If multiple recognitions need to be reversed at once, supersede this ADR rather than amending it.
