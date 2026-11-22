---
category: hooks
last_reviewed: 2026-11-23
---

# Hook Footguns

## Footgun: the agent hook re-implements `internal/diff` changed-region logic outside the Go core — the two drift

**Status:** active | **Created:** 2026-06-04 | **Evidence:** OBSERVED

hallucination-risk: high (both layers "do changed-region scoping", so a fix to the Go core reads as done even though the hook silently kept the old behaviour)

`.goat-flow/hooks/gruff-code-quality.mjs` and its `gruff/` helpers derive changed-line ranges and select changed-region scoping independently of the Go pipeline they call (`internal/diff`, `internal/analysis`). Until goat-flow 1.19.0 the same logic lived in the Bash `gruff-code-quality.sh`; the Node rewrite kept it as a parallel implementation. They are not one source of truth, so a correctness fix that lands in one half does not propagate to the other. PR #4's automated review (chatgpt-codex / cursor) caught three concrete drifts in the Bash hook after the Go side was hardened:

- **Deletion-only hunks.** `internal/diff/diff.go` (search: `func addHunkLines`) anchors a zero-count `+N,0` hunk to the line before the removed block; the hook drops it, so a delete-only edit reports no changed lines.
- **Native vs fallback scoping.** `internal/analysis` / `internal/cli` gained `--changed-ranges` / `--changed-scope` / `--no-baseline` (search: `func resolveChangedScope`), but the Bash hook's capability probe hard-coded `gruff-py` as the only native binary, so Go edits fell back to portable primary-line filtering instead of symbol-aware scoping.
- **Staged edits.** The Bash hook's git fallback ran a bare `git diff` (unstaged only), so a staged-only edit yielded empty ranges.

Native-scope detection and staged-edit collection were fixed 2026-06-04, and the 1.19.0 Node hook keeps both: it probes `analyse --help` for all three flags (`.goat-flow/hooks/gruff/feedback.mjs`, search: `const native = ["--changed-ranges", "--changed-scope", "--no-baseline"]`) and reads staged hunks (`.goat-flow/hooks/gruff/ranges.mjs`, search: `"--cached", "--unified=0"`). Deletion anchoring is still not mirrored: `.goat-flow/hooks/gruff/ranges.mjs` (search: `return count > 0 ? [`) drops zero-count hunks, and the hook then reports an advisory `analysis-not-applicable` result (`.goat-flow/hooks/gruff/feedback.mjs`, search: `This edit has no remaining source lines for Gruff to analyze`). That reports the gap without closing it. The structural trap remains because the hook is a parallel implementation of the Go core.

How to avoid:
- When you change changed-region derivation or scoping in `internal/diff` / `internal/analysis`, immediately re-read `.goat-flow/hooks/gruff/ranges.mjs` (`hunkRanges`, `changedRanges`) and the native-scope probe in `.goat-flow/hooks/gruff/feedback.mjs`. The hook is managed, so carry the matching change upstream to goat-flow rather than editing it in place (see the managed-hook footgun below). Prefer probing the binary (`analyse --help`) over hard-coding which port supports a flag.
- The 1.19.0 self-test (`.goat-flow/hooks/gruff-code-quality.mjs`, search: `async function selfTest`) runs one single-line `Edit` against a stub analyzer whose help lists neither native flag. It has no deletion-only case and does not exercise native scoping, so an `ok` result proves neither. Any upstream repair must add the deletion regression case before the installed hook can be trusted for delete-only edits.
- E2E the hook by setting `GRUFF_GO_BIN` to a logging wrapper: the hook takes that override before any search path (`.goat-flow/hooks/gruff/analyzer.mjs`, search: ``const override = process.env[`GRUFF_${language.toUpperCase()}_BIN`]``). Then feed a payload on stdin while running from a subdirectory, which proves both the flags passed and the working directory used. A `HOME` override no longer works here: since 1.19.0 `~/.local/bin` is searched after the project's `bin/`, so this checkout's ignored `bin/gruff-go` wins. Do not put the logging wrapper in `$root/bin/` either: that directory contains the tracked `bin/gruff-go.sh` launcher and ignored local analyzer output, so a wrapper there can shadow normal analyzer discovery. See the resolved `bin/gruff-go` footgun in `build-artifacts.md`.

## Footgun: the hook is advisory exit 0 with in-band skip/ignore reporting — do not make it exit 2

**Status:** active | **Created:** 2026-06-14 | **Evidence:** OBSERVED

`analyse` exits 2 when every explicit input is skipped before parsing: `ReportAllSkippedInputs` adds an error diagnostic and `ResolveExitCode` (`internal/analysis/report.go`, search: `func ResolveExitCode`) returns 2 for any diagnostic. The `hook` command deliberately does NOT mirror this — it omits `ReportAllSkippedInputs` and returns exit 0 for ignored/skipped explicit inputs, surfacing them in-band through the `gruff.hook.v2` payload (`internal/cli/hook.go`, search: `analysisReport.Summary.ExitCode == 2`; the contract's `Ignored.Paths` field). The hook contract is advisory exit 0 with structured `ignored`/`suppressed`/`config` fields so a PostToolUse hook never hard-fails an agent on an ignored path. A PR reviewer (Cursor, PR #5) read this as an inconsistency bug; it is intended behaviour.

How to avoid:
- Do not add `ReportAllSkippedInputs: true` (or any analyse-style fail-louder option) to the hook's `analysis.Options` to "fix" the apparent inconsistency. It breaks the advisory contract and `internal/cli/hook_test.go` (search: `TestHookReportsIgnoredPathsAndConfigErrors`), which pins exit 0 plus `Ignored.Paths` for a config-ignored explicit input. If a skipped explicit path should be more visible to agents, add it to an in-band payload field, not the exit code.

## Footgun: protected-path literals inside data filters can trigger the secret-file guard

**Status:** active | **Created:** 2026-08-11 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Before retrying a blocked data-classification command, distinguish a protected operand from a protected-looking literal inside the filter program; reformulate only when every real input is verified non-secret.
**Trigger phase:** VERIFY
**Incident count:** 2
**Latest occurrence:** 2026-11-23

hallucination-risk: medium

A read-only Vault measurement was blocked before execution even though its file operands were the repository, a redacted gruff JSON report in `/tmp`, and ordinary output files. An inline AWK suffix classifier named a protected environment-file pattern, and the guard reported `Secret-file access (jq)` for the surrounding data-filter pipeline. Replacing that special case with a generic suffix classifier left the inputs and measurement unchanged and allowed the command to run.

**2026-11-23, goat-flow 1.19.0:** the Node rewrite kept the fallback. During the upgrade, a `node -e` script that only wrote hook-probe payloads to the scratchpad was blocked with `Secret-file access (node)` because its program text held a dotenv path literal. Replayed through `.goat-flow/hooks/deny-dangerous.mjs` as Claude `PreToolUse` payloads: `node -e` printing that literal exited 2, `cat` of the dotenv file exited 2 (known-blocked control), and `jq -r .verdict` exited 0 (known-allowed control). A second block in the same session, `Secret-file access (-r)` on a compound `jq` pipeline, did not reproduce when its filters were replayed one at a time, so its trigger is not isolated.

Evidence: `.goat-flow/hooks/deny-dangerous/patterns-paths.mjs` (search: `function commandTouchesSecret`) applies option-aware local-file parsing only to curl, recognized search commands, and `git log`. Other verbs fall through to `isSecretPathTouch` over the whole command text, so a protected-looking literal in a jq/AWK/`node -e` program is indistinguishable from an operand. Before 1.19.0 the same fallback lived in the Bash `patterns-paths.sh`.

How to avoid:
- Treat the block as real until every command operand and redirection target has been checked. Never reformulate a command that actually reads or writes a protected file.
- For verified non-secret reports, prefer generic extension or type classification that does not embed protected path names in the filter source.
- Record that the original command did not execute; only the successful reformulated run is measurement evidence.

## Footgun: a local fix inside a managed goat-flow hook is reverted by the next install, and the drift signal is inverted

**Status:** active | **Created:** 2026-08-13 | **Evidence:** OBSERVED
**Decision changed:** where a fix to a `.goat-flow/hooks/` file must be guarded from
**Trigger phase:** VERIFY

`.goat-flow/hooks/post-turn-safety.mjs` and its `post-turn/` scanner modules are managed files: `goat-flow install` restores them from `node_modules/@blundergoat/goat-flow/workflow/hooks/`. Before goat-flow 1.19.0 the hook was the Bash `post-turn-safety.sh`. v0.5.0 hardened that installed copy so nonnumeric and leading-zero scan limits fell back to defaults. The 1.15.x template guarded only `MAX_SECONDS`, so it evaluated `$((MAX_FILE_BYTES))` directly.

That gap is not cosmetic. `MAX_FILE_BYTES` gated every file in the Bash scanner. In bash, `MAX_FILE_BYTES=invalid` evaluates to `0`, so no file is ever under the limit: the safety scanner examines nothing and still reports clean. `08` is worse - `value too great for base` aborts the arithmetic outright.

**2026-10-03, goat-flow 1.17.0:** the Bash template began validating the byte limit itself. The upgrade took the template with `--force-path`, so the v0.5.0 local hardening was gone and `check_post_turn_limit_hardening` still passed. Two cases the local copy covered were not upstream, measured against a disposable repo holding a synthetic AWS key: `GOAT_FLOW_POST_TURN_SAFETY_MAX_FINDINGS=invalid` exited 2 but printed `[: invalid: integer expression expected` in place of the `blocked AWS access key` line, and `GOAT_FLOW_POST_TURN_SAFETY_MAX_SECONDS=08` exited 2 while the budget check errored with `value too great for base`. Neither let a finding through.

**2026-11-23, goat-flow 1.19.0:** the hook is Node and upstream now covers all three limits. The byte limit falls back through `numericSetting`, and the findings and seconds limits strip leading zeros first (`.goat-flow/hooks/post-turn/scanner.mjs`, search: `function createScanState`). Measured against a disposable repo holding a synthetic AWS key: under `MAX_BYTES=invalid`, `MAX_FINDINGS=08`, `MAX_SECONDS=08`, and again under `MAX_FINDINGS=invalid`, the hook exits 2 with `blocked AWS access key`, and a clean file exits 0. The self-test carries its own `invalid byte limit` and `leading-zero byte limit` cases (`.goat-flow/hooks/post-turn-safety.mjs`, search: `name: "invalid byte limit"`), but it pins every scan limit per case, so limits the caller sets never reach the scanner.

Two things make this hard to notice:

- **The in-file self-test disappears with the fix.** The hardening and the self-test cases that exercise it live in the same managed files, so an install that reverts one reverts the other. The hook's `--self-test` then passes on the weakened hook, because the cases that would have failed are gone. Since 1.19.0 it also ignores the caller's limits, so running it under hostile limits proves nothing either.
- **The drift signal is backwards.** Under 1.15.x, `goat-flow audit` reported `drift: fail` on the hardened `post-turn-safety.sh` *while the hardening was present*, and would have reported `pass` once an install stripped it. A green audit there meant the protection was gone; the red one meant it was intact. The 1.19.0 installer instead keeps a locally edited managed file as `local-preserved`, or flags it `both-changed` when the template also changed (`node_modules/@blundergoat/goat-flow/docs/cli.md`, search: `A locally edited managed file no longer blocks an upgrade on its own`). How its audit reports such a file was not re-measured.

How to avoid:
- Guard a managed-file fix from a project-owned file that an install cannot touch. `scripts/preflight-checks.sh` (search: `check_post_turn_limit_hardening`) drives the scanner the way the hook's self-test does, against a disposable repository under hostile limits: a clean file must exit 0, and a synthetic AWS key must exit 2 with `blocked AWS access key`. On 2026-11-23 it passed against the 1.19.0 hook, failed with `scan incomplete` against a copy that read the invalid byte limit as 0, and failed with `synthetic key not reported` against a copy that also skipped oversized files silently. Its earlier form ran the hook's own self-test under hostile limits, which stopped discriminating in 1.19.0.
- Do not "resolve" this drift finding by reinstalling the template. Re-apply the hardening, or upstream it to goat-flow and take the newer template.
- When `goat-flow audit` reports content drift on a hook, diff the installed copy against the template and decide which side is newer before acting. Assuming the template is authoritative silently reverts local security fixes.

## Footgun: goat-flow install leaves missing credential-store deny rules absent while its own audit requires them

**Status:** active | **Created:** 2026-10-03 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** After every goat-flow upgrade, diff `.claude/settings.json` `permissions.deny` against the packaged Claude template and add the missing credential-store rules; a clean install run does not mean the settings match the template.
**Trigger phase:** VERIFY

hallucination-risk: high (install exits 0, prints its settings migration, and a later dry run marks the file `preserve`, so nothing in the install output says rules are missing)

**Prevention:** after `goat-flow install`, compare `jq -r '.permissions.deny[]'` for `.claude/settings.json` against `node_modules/@blundergoat/goat-flow/workflow/hooks/agent-config/claude.json`, add every template rule the project lacks, then rerun `goat-flow audit . --agent claude`. Do not re-add rules the installer retires; the next install strips them again.

**Symptoms:** the audit fails Constraints with "direct literal secret-path blocking incomplete", and its enforcement matrix reports "MISSING Secret file-read paths" even though the settings deny `.env` variants, keys, SSH and AWS paths.

**Why it happens:** the installer pairs only the stores a project already denies: `node_modules/@blundergoat/goat-flow/dist/cli/installer/claude-permissions.js` (search: `Pair only a store the user already denies; absent pairs remain a deliberate project choice`). The audit has required home-directory rules for four plaintext stores regardless since 1.17.0: `node_modules/@blundergoat/goat-flow/dist/cli/facts/agent/settings.js` (search: `const hasPlaintextStores`). The same install deliberately removes the generic rules in `node_modules/@blundergoat/goat-flow/dist/cli/installer/claude-permissions.js` (search: `const RETIRED_DENY_RULES`), including the credentials-prefix and secrets-directory rules. Through 1.18.0 this logic lived in the Bash `workflow/install-goat-flow.sh`, which 1.19.0 no longer ships.

**Evidence:** upgrading from 1.15.1 on 2026-10-03 left 20 template rules missing (the netrc file, Git's plaintext credential store, the GitHub CLI hosts file, pgpass, and gcloud config, each as `Read` and `Edit` in home and project form). Adding them from the template cleared the Constraints failure, and a following `goat-flow install --dry-run` reported `.claude/settings.json` as `preserve`, so complete pairs survive reinstall. Upgrading from 1.18.0 to 1.19.0 on 2026-11-23 left the template's new exact-name pair `Read(**/credentials.json)` and `Edit(**/credentials.json)` missing. The 1.19.0 docs say install does not add it to existing settings (`node_modules/@blundergoat/goat-flow/docs/cli.md`, search: `Existing settings that lack the pair need reviewed setup reconciliation`), so it was added from the template.

## Footgun: a quality report over 16 KB saves only when the command line starts with a `goat-flow` executable

**Status:** active | **Created:** 2026-11-23 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Start a quality-report save with a version-matched executable named `goat-flow` (here `node_modules/.bin/goat-flow quality save '<project>' <<'JSON'`), with nothing before it on that line; do not read the size refusal as "the hook blocks report saves".
**Trigger phase:** ACT

hallucination-risk: high (the refusal names only "the approved stdin/file transport", so a blocked save looks like a framework flaw rather than a command-shape mismatch)

**Why it happens:** `deny-dangerous` refuses any Bash command over 16,384 bytes (`.goat-flow/hooks/policy-input.mjs`, search: `export function policyCommandSizeRefusal`), and a complete quality report is larger. It exempts the masked report body only when the first line of the command resolves to an executable whose base name is `goat-flow`, or to the source CLI (`.goat-flow/hooks/policy-heredoc.mjs`, search: `export function largeQualitySaveHeredocIsBoundedData`).

**Evidence:** on 2026-11-23, 20 KB `quality save` payloads replayed through `node .goat-flow/hooks/deny-dangerous.mjs` gave exit 0 for a `node_modules/.bin/goat-flow` opener and exit 2 with the size refusal for `npx --no-install goat-flow`, `node node_modules/@blundergoat/goat-flow/dist/cli/cli.js`, and `cd <project> && node_modules/.bin/goat-flow`. The same day a quality assessment hit the refusal with a `cd … && npx …` opener, reported it as a framework flaw, and had to retract it.

**Prevention:** run from the project directory and put the bare `goat-flow` executable first on the heredoc's opening line. The hook is managed, so a clearer refusal message or a wider exemption belongs upstream in goat-flow (see the managed-hook footgun above).

## Resolved Entries

## Footgun: `deny-dangerous` rejected a leading `$VAR` in a delete target but allowed one mid-path

**Status:** resolved | **Created:** 2026-08-08 | **Resolved:** 2026-08-11 | **Evidence:** ACTUAL_MEASURED

Under GOAT Flow v1.15.0 the delete-target guard rejected a target that *begins* with `$` or a backtick, while a target that merely *contains* one passed. The neighbouring `..` traversal check ran against the pre-expansion string, so it saw nothing, and `cache/$TARGET` with `TARGET=../../outside` deleted outside the project after expansion. Raised by coderabbit on PR #6.

The v1.15.1 guard tested for the expansion anywhere in the target rather than only at the front: the Bash `patterns-shell.sh` matched `*'$'*` and `` *'`'* ``. Re-measured 2026-08-11 with the Bash hook's `--check="<command>"` mode, one run each:

| Delete target shape | v1.15.0 | v1.15.1 |
|---|---|---|
| known-blocked control (`git push origin main`) | rc=2 | rc=2, so the probe reaches the policy |
| scoped literal (`cache/build`) | rc=0 | rc=0, allowed by design |
| leading variable (`$HOME/.cache`) | rc=2 | rc=2 |
| mid-path backtick (``cache/`echo x` ``) | rc=2 | rc=2 |
| **mid-path variable (`cache/$TARGET`, `./cache/${TARGET}`)** | **rc=0, allowed** | **rc=2, blocked** |

What carries forward: the probe discipline, not the gap. Always include a known-blocked control in the same run - an incorrectly invoked probe returns rc=0 for everything, including targets the live hook blocks. This file is goat-flow-managed, so a future gap belongs upstream rather than patched in tree, where the next `goat-flow install` would revert it. goat-flow 1.19.0 replaced the Bash hook with `deny-dangerous.mjs`, which keeps the check mode: replay a shape with `node .goat-flow/hooks/deny-dangerous.mjs --check="<command>"`, alongside the same known-blocked control. Measured 2026-11-23: `rm -rf cache/$TARGET` exits 2 under 1.19.0.
