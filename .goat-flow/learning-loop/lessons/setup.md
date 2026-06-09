---
category: setup
last_reviewed: 2026-05-13
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
