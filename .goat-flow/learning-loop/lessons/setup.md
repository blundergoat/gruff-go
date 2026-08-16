---
category: setup
last_reviewed: 2026-08-08
---

# Setup Lessons

## Lesson: Do not backtick nonexistent illustrative paths

**Created:** 2026-05-13

**Incident:** The 2026-05-13 harness audit failed `doc-paths-resolve` after `.goat-flow/code-map.md` used an absent source directory as a backticked example.

**Do differently:** In target docs, reserve backticks for paths that exist on disk. Describe absent future paths in prose or record them as setup gaps.

## Lesson: Harness advisory failures still block zero-failure setup

**Created:** 2026-05-13

**Incident:** The base audit passed, but the 2026-05-13 harness audit failed `commit-guidance` because `.github/git-commit-instructions.md` was missing.

**Do differently:** When the user asks for both audits to pass with zero failures, fix harness advisory failures instead of relying on base audit success.

## Lesson: Refresh transitive lock entries after direct npm dependency updates

**Created:** 2026-08-08
**Decision changed:** A direct npm package update is incomplete until the dependency audit verifies the resolved transitive tree.
**Trigger phase:** VERIFY

**What happened:** `npm install --save-dev @blundergoat/goat-flow@^1.15.0` updated the direct package but retained `js-yaml` 4.3.0. The preflight Node dependency audit rejected that version for CVE-2026-59870; `npm audit fix` moved the lock to 4.3.1.

**Evidence:** `package-lock.json` (search: `"node_modules/js-yaml"`) carries the remediated 4.3.1 resolution. `scripts/preflight-checks.sh` (search: `check_npm_audit`) makes the npm audit a completion gate.

**Prevention:** After a direct npm dependency update, run `npm audit` or the full preflight before treating the lockfile as current. Apply the supported transitive remediation, then rerun the original gate.
