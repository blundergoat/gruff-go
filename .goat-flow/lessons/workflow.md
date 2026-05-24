---
category: workflow
last_reviewed: 2026-05-24
---

# Workflow Lessons

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
