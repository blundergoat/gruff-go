---
category: build-artifacts
last_reviewed: 2026-06-04
---

# Build-Artifact Footguns

## Footgun: `bin/gruff-go` is a committed binary, not a build-output scratch file

**Status:** active | **Created:** 2026-06-04 | **Evidence:** OBSERVED

`.goat-flow/code-map.md` (search: `Local build output directory`) describes `bin/` as a "Local build output directory (typically holds `gruff-go` after `go build -o bin/gruff-go ./cmd/gruff-go` for perf scripts)", which reads like a scratch path. But `bin/gruff-go` is tracked in git — a ~12 MB committed blob (confirm with `git ls-tree HEAD bin/`). So the exact command code-map suggests, `go build -o bin/gruff-go`, overwrites a committed file and produces a spurious `Bin … bytes` diff; a follow-up `rm` then shows it as a deletion of a tracked file.

(Triggered 2026-06-04 while building a logging wrapper for a hook e2e test — the wrapper clobbered the committed binary, which then showed as `D bin/gruff-go`; restored with `git checkout HEAD -- bin/gruff-go`.)

How to avoid:
- For ad-hoc builds and hook e2e tests, build to a temp path (`go build -o /tmp/<dir>/gruff-go ./cmd/gruff-go`), not into `bin/`.
- If you must build into `bin/`, restore it afterwards: `git checkout HEAD -- bin/gruff-go`.
- Whether a 12 MB binary belongs in version control at all is a separate open question — the root `./gruff-go` is `.gitignore`d while `bin/gruff-go` is committed, an inconsistency worth raising with the maintainer.
