---
category: workflow
last_reviewed: 2026-05-27
---

# Workflow Lessons

## Lesson: Milestone `Status: planned` can lag the code by entire milestones — verify against the codebase before executing

**Created:** 2026-05-26

**Incident:** A 0.1.2 execution turn started by reading `tasks/0.1.2/M01-failthreshold-type-and-none-sentinel.md`, which said `Status: planned` and had every task checkbox unticked. The natural conclusion was that M01 was unstarted and the full "land FailThreshold type + 12-site sweep" was ahead. Reality after one grep: `internal/finding/threshold.go` already existed with `FailThreshold`, `ParseFailThreshold`, `Valid`, `IsTriggeredBy`, and `DefaultFailThresholdFor`. `internal/cli/cli.go::resolveFailOn` already implemented ADR-010 precedence. `internal/config/config.go::Config.MinimumSeverity` was already wired. `internal/config/validate.go::validateMinimumSeverity` already rejected unknown command keys. Tests existed at `internal/finding/threshold_test.go`, `internal/cli/precedence_test.go`, and `internal/config/config_test.go`. ADR-010 was already written. M03's docs sweep was already done across `docs/configuration.md`, `docs/ci-integration.md`, and `docs/dashboard.md`. The only genuine M01 straggler was `internal/cli/dashboard.go::runDashboard` still calling `finding.ParseSeverity` (which silently rejected `none` from the CLI even though the dashboard's HTTP handler accepted it) — a real bug, but worth ~5 lines, not the planned multi-hour sweep.

The root cause: a parallel session had executed the production code work and committed it (`75bad51`, `e829fb1`, `0168e16`, `7a154bd`, `9d3f3fd`) without flipping the milestone status fields. Status updates are bookkeeping; commits don't require them. Status drift is inevitable across parallel sessions, deferred-cleanup sessions, and any time the engineering work outruns the milestone-file updates.

**Do differently:** Before executing any milestone task that touches existing code paths, run a targeted grep against the milestone's "Read First" paths to see what already exists. Concretely:

- "Add type X" task: `rg -l "type X\b\|func.*X" internal/`. Type may already exist with the exact shape.
- "Wire field Y through" task: `rg "Y\." internal/ cmd/`. Field may already be wired across the surface.
- "Write ADR-NNN" task: `ls .goat-flow/decisions/ADR-NNN-*` before drafting. Cheaper to discover the existing draft than to overwrite it.
- "Update docs/X.md" task: `grep -c "<key-vocabulary>" docs/X.md` before editing. The docs may already mention it.
- "Sweep N reader sites" task: run the same grep the task spec implies (e.g. `rg "\.FailOn" internal/`) to count actually-stale sites *now*. Don't trust the count in the milestone description; it was true when the milestone was written.

`Status: planned` means "the milestone file hasn't been ticked through", not "no work has been done". The two diverge whenever multiple sessions execute in parallel, when commits land without status-file updates, or when work was done in a prior session and only the bookkeeping was deferred. The fast verification grep takes seconds; the cost of redundant work plus missing the actual stragglers is much higher. Treat the milestone file as a *spec*, not a *state report*.

## Lesson: When a milestone says `Status: complete` but every inner checkbox is `[ ]`, the contradiction is the headline, not a footnote

**Created:** 2026-05-27

**Incident:** A 0.1.2 close-out turn started with the request "execute these: .goat-flow/tasks/0.1.2". Every file in that directory (`ISSUE.md`, `M01`–`M04`) carried `Status: complete` / `Completed: 2026-05-26` at the top, and `ISSUE.md`'s `How` checklist was fully ticked. The agent ran a high-level verification — `make check` clean, dogfood grade A, schema unchanged, ADR-010 present, `FailThreshold` type exported, docs swept — and reported "All four milestones of 0.1.2 are already implemented and verified — no work to execute. … What's left is only bookkeeping drift."

The user pushed back: "this is impossible?? 'All four milestones of 0.1.2 are already implemented and verified' because none of the checkboxes have been ticked." The contradiction was right there in the files: outer header said done, every inner task said `[ ]`. The agent's first reply acknowledged the inner state but treated it as a closing parenthetical ("only bookkeeping drift") rather than as the contradiction the user actually saw on screen. Only after the pushback did the agent map every unchecked task to a file:line that proved the work was done (`internal/finding/threshold.go:17` for `FailThreshold`, `runner.go:132-133` for the fallback, `state.go:30` for the dashboard default, etc.) and offer to flip the boxes. The boxes were then flipped in one bulk Edit per milestone.

The root cause: the agent trusted the file-level header and let the visible inner contradiction slide. This is the mirror image of the [`Status: planned` lesson above](#lesson-milestone-status-planned-can-lag-the-code-by-entire-milestones--verify-against-the-codebase-before-executing) — there, `Status: planned` lagged real completion; here, `Status: complete` lagged the inner bookkeeping. Same drift, opposite direction. Both happen because the status header is one edit and the per-task checkbox sweep is another, and committers do the work but skip the checkbox sweep.

**Do differently:** When a milestone file's outer header (`Status: complete`, `Completed: <date>`) does not match its inner checkbox state (every `- [ ]`, no implementation-notes entry, or an `ISSUE.md` `How` list whose tick state contradicts the inner milestone files), make the contradiction the headline of the first reply. Don't acknowledge it in a closing aside. Two paths, both acted on in the first turn:

- **Outer header is right, inner is stale (this incident):** prove the outer is right with file:line citations on the first reply, AND offer to flip the inner checkboxes in the same turn. A "your file is internally inconsistent, here's the resolution" reply lands cleaner than "everything's done (oh by the way the inner state disagrees)".
- **Inner is right, outer is wrong:** flip the conclusion — the file's header is wrong, the work to do is what the inner state actually says. Re-scope the turn accordingly.

Cheap detection on first read: when summarising a milestone file's status, count `- [ ]` vs `- [x]` in the body. A `Status: complete` file with substantially more unchecked than checked inner boxes is a drift signature — respond to that signature directly, not to the header alone. The same check applies in reverse for `Status: planned` files with mostly-`[x]` interiors.

## Lesson: A vocabulary migration is not complete until `docs/` is swept

**Created:** 2026-05-25

**Incident:** PR #3 (`v0.1.2`) executes ADR-009: a hard-break migration of the severity vocabulary from 5 buckets (`critical/high/medium/low/info`, plus the `notice`/`warn` aliases) to 3 (`advisory/warning/error`). The code migrated cleanly — `internal/finding/types.go`, every rule definition under `internal/rule/`, the config parser, golden snapshots, the dogfood `.gruff-go.yaml`, ADR-009 itself, and the CHANGELOG `[0.1.2]` entry all use the new vocabulary. But the user-facing docs were untouched:

- `docs/configuration.md` still enumerates `severity: info | low | medium | high | critical | notice | warning | warn | error` as the valid set (search: `severity: info | low | medium`); the strict-validation list further down still says severities must be in `info / low / medium / high / critical`; multiple example configs use `severity: high` and `severity: low`.
- `docs/rules.md` carries 64 `**Default severity:**` lines, every single one of them on the old vocabulary (43 × `low`, 11 × `high`, 8 × `medium`, 2 × `critical`).
- `docs/ci-integration.md` recommends `--min-severity high` and claims the default is `medium`.
- `docs/output-formats.md` has a JSON example with `"severity": "medium"`, describes the interactive-report severity multi-select order as `critical → high → medium → low → info`, and says the default `--min-severity` is `medium`.
- `docs/dashboard.md` lists `--fail-on` default as `medium` and embeds a `--min-severity medium` example URL.

A user following the v0.1.2 docs would write a config that fails to load. Worse, the strict-validation section says blank-rejection-only for `acceptedAbbreviations` is no longer the rule (it claims uppercase-only) — also a stale claim that PR #3's validator relaxation contradicts.

The agent that produced PR #3 had already updated CHANGELOG and ADR-009 in the same commit set, so the user-facing prose was *partly* migrated. That partial migration is the trap: a quick eyeball check at the top-level files (CHANGELOG, ADR, README) looked clean and gave false confidence that the migration was done.

**Do differently:** When a vocabulary changes (severity bucket names, pillar names, schema field names, CLI flag names, config keys), run `rg -nF '<old-term>' docs/` for every old term *before* declaring the migration complete. For ADR-009 the sweep would have been `rg -nE '\b(critical|high|medium|low|info|notice|warn)\b' docs/` and produced a punch list of every stale reference in one shot. The CHANGELOG entry for the breaking change is not a substitute — it documents the migration, it does not perform it. Add the `docs/` sweep to the Definition of Done in `CLAUDE.md` for any change that renames a user-visible identifier.

The same lesson applies to confidence (`info/low/medium/high`), pillar names, severity-mapping tables in SARIF output, and any future cross-port vocabulary harmonisation: docs go stale silently because they don't have tests.

The sweep target includes `.goat-flow/tasks/` milestone bodies, not just `docs/`. Milestone files drafted during one version cycle and carried into the next go stale on a release. On 2026-05-30 the 1.0.0 adoption milestones (`M24`-`M27`) still used the five-tier severity vocabulary, `gruff-go.analysis.v0.1`, a colliding `ADR-006` reference (it was already taken by single-value-rubric-thresholds), and `tasks/0.2/` read-first paths - none of which had been swept after v0.2.0 shipped. Before executing a carried-over milestone, `rg --no-ignore` its body (the `.goat-flow/tasks/` dir is gitignored, so a plain `rg` silently skips it - a trap in its own right that produced false "clean" sweeps during the 2026-05-30 refresh) for stale schema versions, severity names, ADR numbers, and version-dir paths, and refresh it first; the milestone is a spec, and an old spec encodes the old world.

## Lesson: After an enum rename, sweep test failure messages for the old name

**Created:** 2026-05-25

**Incident:** ADR-009 renamed severity constants (`SeverityMedium` → `SeverityWarning`, `SeverityLow` → `SeverityAdvisory`, etc.) across the rule package and its tests. The assertion *predicates* were migrated (`if def.Severity != finding.SeverityWarning {`), but the failure-message *format strings* were not: at least five tests still printed `want medium` or `want low` when they failed — `internal/rule/complexity_npath_test.go`, `internal/rule/test_quality_sleep_test.go`, `internal/rule/dead_code_unused_private_test.go`, `internal/rule/calibration_test.go` (twice, once with `want high/high` and once with `want low/medium`). The tests still pass because the predicate matches the new constant, so the rename looked clean — but on failure the operator sees an error message that names a severity bucket that no longer exists.

Worse, the same drift hit non-test code that *stores* user-supplied severity strings verbatim: `internal/dashboard/handler_test.go` had setup constants like `FailOn: "high"` and assertions like `state.FailOn != "high"` that drove the test through a passthrough store path. The tests pass because the code preserves the string as-is, but the test inputs are now invalid severities under the new parser, so the test is documenting wrong behaviour for the new world.

CodeRabbit flagged two of the seven stale strings; codex and CodeRabbit missed the other five.

**Do differently:** After an enum-like rename (severity, pillar, capability, status, log level), grep for `want <oldname>` and old-vocabulary string literals across the whole tree, not just the package that defines the enum. Concretely: `rg -nE '"(want |"|, |= ")(<old1>|<old2>|...)"\b'` flushes out format strings and test input literals in one pass. Plain `grep` for the assertion predicate (`SeverityMedium`) won't catch these because the predicate was already migrated; you have to grep for the *human-readable* name in string form. Treat this as a mandatory step in the verify phase of any enum rename.

**Created:** 2026-05-24

**Incident:** `internal/rule/` carried ten files named after retired internal milestone IDs: `security_m08.go`, `security_m08_test.go`, `security_m37_test.go`, `security_m38_test.go`, `maintainability_m08.go`, `maintainability_m08_test.go`, `test_quality_m07.go`, `test_quality_m07_test.go`, `test_quality_m08.go`, `test_quality_m08_test.go`. Commit `57dbcab` ("update rule registry to 64 default-enabled rules") and its predecessors had explicitly cleaned `M01`-`M38` milestone references out of ADR titles, doc comments, footguns, `CONTRIBUTING.md`, and `docs/output-formats.md` (see the CHANGELOG entry under `[0.1.1]`), but the cleanup only touched markdown and doc-comment prose — file names were never audited. When the user discovered the leftover file names mid-review, they pushed back hard ("files should NEVER have milestone m* name!!!!"). Subsequent rule additions in commits `e027997`, `4ba27c5`, and `29efb39` had also propagated the legacy pattern by following the closest existing example rather than checking the cleanup contract. The ten files were renamed in the same `0.1.1` release to topic-based names (`security_hardening_defaults.go`, `maintainability_runtime_pitfalls.go`, `test_quality_helper_and_parallel.go`, `test_quality_async_and_tempdir.go`, `security_sql_and_archive_test.go`, `security_crypto_strength_test.go`, and matching `_test.go` peers).

**Do differently:** When creating a new file under `internal/rule/` (or anywhere else), name it after its subject — `security_permissive_file_mode.go`, `security_request_body_limit.go`, `test_quality_sleep_in_test.go` — not after an internal milestone, sprint, or ticket identifier. When doing a cleanup pass that removes internal vocabulary from prose, also run `git ls-files | grep -iE "(_m[0-9]+|m[0-9]+_)"` (and any project-specific identifier patterns) before declaring the pass complete, because file names survive every grep against `*.md` and doc-comment text. Pattern-matching against the closest existing file is a primary vector for this kind of drift: when the directory already contains legacy-named files, copy the *naming convention* the user wants, not the *filename shape* of a peer.

## Lesson: Check git history before treating dogfood noise as a rubric gap

**Created:** 2026-05-24

**Incident:** The user's preflight check reported 25 sensitive-data findings in `internal/rule/sensitive_test.go` and `internal/report/sensitive_redaction_test.go`. The agent immediately diagnosed these as "test fixtures intentionally containing secret-shaped strings to exercise the rules" and proposed (a) annotating each fixture line with `//nolint:gosec` and (b) drafting an ADR for a new per-rule path-allowlist knob to fill a "rubric gap." Both proposals were plausible on their face. The actual cause was that commit `8282478` ("feat: update rule pillars and enable config-field-comment by default"), authored the day before, had regenerated `.gruff-go.yaml` from the `gruff-go init` template, wiping an 8-entry `paths.ignore` list that had been excluding the rule-test fixture files for weeks. The 25 findings appeared the moment that `paths.ignore` list disappeared. `git log .gruff-go.yaml` and `git show 8282478^:.gruff-go.yaml` would have surfaced the regression on the first turn. The user had to push back ("why the fuck did these default ignores get removed?") before the agent looked at git history.

**Do differently:** When a quality check, scan, or lint fails on something that obviously should have been excluded - especially when the user expresses surprise ("these used to be ignored") - run `git log -p --follow <config>` and `git diff <prior-commit>..HEAD -- <config>` on the relevant config file BEFORE proposing suppression workarounds or rubric improvements. Stable-looking noise that the user did not expect is usually a regression in policy, not a gap in the original design. The heuristic: if your fix is a suppression annotation or a new allowlist knob, first ask "did this state arise from a recent change?" Workarounds proposed before that check waste the user's time on the wrong layer of the problem.

## Lesson: Check scanner config before agent-skill rubrics

**Created:** 2026-05-23

**Incident:** When asked to list security rubrics, the agent searched for `rubric` and returned the GOAT critique/security-assessment rubric from `.agents/skills/` instead of first checking the project scanner config. The relevant evidence was in `.gruff-go.yaml`, where `security.shell-command` and the `sensitive-data.*` rules were explicitly configured with severities.

**Do differently:** For questions about this repo's security rubrics, rule IDs, configured severities, or active scan policy, read `.gruff-go.yaml` and `docs/rules.md` before consulting agent skill files. Treat `.agents/skills/` as workflow guidance, not the scanner's configured rule source, unless the user explicitly asks about GOAT skills.

## Lesson: Place calibration helpers before dogfood, not after

**Created:** 2026-05-23

**Incident:** While fixing false positives in `internal/rule/builtin.go`, the agent added helper code directly to the already-large builtin rule file. Focused tests passed, but the required dogfood scan reported `size.file-length` and `docs.comment-rubric` findings against the new helpers before the code was split into `internal/rule/function_length_tables.go` with attached comments.

**Do differently:** For rule-calibration changes, check the target file's current line count and configured comment rubric before adding helper blocks. If a file is near the 500-line project threshold, create a focused helper file up front and give every new helper/type an attached comment before running the first dogfood scan.
