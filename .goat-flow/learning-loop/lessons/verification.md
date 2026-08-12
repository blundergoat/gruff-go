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

## Lesson: a remediation brief's evidence is a hypothesis, including its file list and its citations

**Created:** 2026-08-12
**Decision changed:** Before implementing a handed-down brief, re-derive its affected-site list from the code, re-read every contract section it cites, and re-measure any claim it states as a property of the system rather than of a sample.
**Trigger phase:** READ

A remediation brief written from a corpus run reads as verified because it carries measurements. The
measurements can be real and the conclusions drawn from them still wrong in three distinct ways. All
three occurred in one brief, and re-verifying it on 2026-08-12 found each.

**A grep-derived file list is a hypothesis, not an inventory.** The brief located the
flags-after-paths defect with `flag.NewFlagSet` and published the hit list as the affected set:
`analyse_flags.go`, `report.go`, `baseline.go`, `summary.go`, `dashboard.go`, `completion.go`, and
`cli.go`'s `list-rules`. Three of those never take positional paths — `dashboard` reads scan targets
from `--paths`, `completion` uses `Arg(0)` as a shell name, `list-rules` consumes no operands at all —
so the stated mechanism ("every subcommand takes those remaining args as paths") did not apply to
them. More seriously, the grep **missed** `internal/cli/hook.go` (search: `paths:          flagSet.Args()`)
and `internal/cli/check_ignore.go` (search: `paths := flags.Args()`), which do. `hook` is this port's
primary surface. An implementer following the list literally would have shipped
`gruff-go hook <path> --format json` still dropping `--format`. The grep answered "who constructs a
FlagSet"; the question was "who consumes `Args()` as paths", which is a different grep.

**A cited contract section may not say what the brief says it says.** The brief closed debate with
"Under §7 the family flag surface is RATIFIED, so this is a gruff-go conformance defect, not a design
choice open for debate." That section of the family contract — maintained outside this repository —
has two bullets: family flags are accepted on every port with honest help text, and inputs are
files/directories/path sets with `dir/` ≡ `dir/**`. Neither addresses where a flag may sit relative
to an operand. The defect was real
on its own merits — silent wrong results — but the citation was load-bearing for shutting down
discussion and did not carry the weight. When a workspace makes citation mandatory, a citation that
does not cover its claim is worse than none.

**Absence in a sample is not a property of the system.** From "across all ten repos, no `security.*`
rule ever reached `error`" the brief concluded, and the resulting `docs/ci-integration.md` published,
that the built-in registry has no error-tier `security.*` rule. That happens to be true — 20 advisory
and 2 warning of 22 default-enabled, confirmed by `list-rules --no-config --format json` — but it was
never checked against the registry, it was published in a file no test read, and a `security.*` rule
commit landed after the documentation did. The one-line registry check that would have settled it is
now a test: `internal/rule/security_severity_guard_test.go` (search:
`TestDefaultSecurityRulesStayBelowError`).

A fourth, smaller instance in the same brief: "gruff-go's default `--fail-on` is `advisory`, so these
findings do gate by default" is true for `analyse` and `summary` and false for `report` and
`dashboard`, which default to `none` per `internal/finding/threshold.go` (search:
`func DefaultFailThresholdFor`) and ADR-010. A per-command table existed in `docs/configuration.md`
the whole time; the brief generalised from the command it happened to be testing, and three published
docs inherited the generalisation.

The cheap defence is not distrust, it is order: re-derive, re-read, re-measure **before**
implementing, because each of these is a single command, and each was cheaper than the rework it
would have caused.

**Then the same failure recurred inside the re-verification itself, three times in one session.**
Checking whether five ports honour flags placed after a path means running each twice and comparing
stdout. Three of the five first produced an "identical" result that proved nothing: `gruff-ts`
invoked as `node bin/gruff-ts` died with the same `SyntaxError` both times (that file is a shell
wrapper); `gruff-py` under the system interpreter died with the same `ModuleNotFoundError` both
times, then — once running — discovered **zero** files because the fixtures lived under `/tmp` and
py's default ignore set excludes it; `gruff-php` exited 0 and also scanned zero files for the same
reason, visible only in `ignoredPathDetails` as `{"source": "default", "pattern": "tmp"}`. Two equal
outputs from two runs that did no work are equal for the wrong reason.

A comparison-based check needs a **liveness column**: assert the run did something — files scanned,
findings produced, a non-empty artefact — before comparing the two sides. The comparison answers
"same?", never "same, and meaningful?". Scratch fixtures under `/tmp` are a standing trap for any
scanner with a default ignore list; either place fixtures elsewhere or pass the port's
`--include-ignored` equivalent, and check the scanned-file count either way.
