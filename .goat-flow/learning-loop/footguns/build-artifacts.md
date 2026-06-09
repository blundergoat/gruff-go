---
category: build-artifacts
last_reviewed: 2026-06-06
---

# Build-Artifact Footguns

No active entries. Agents scan only entries above `## Resolved Entries`.

## Resolved Entries

## Footgun: `bin/gruff-go` was a committed binary, not a build-output scratch file

**Status:** resolved | **Created:** 2026-06-04 | **Resolved:** 2026-06-06 | **Evidence:** OBSERVED

**Resolution (2026-06-06):** `bin/gruff-go` is now gitignored. The `!/bin/gruff-go`
un-ignore exception was removed from `.gitignore` (search: `bin/ holds local build output`)
and the blob untracked with `git rm --cached bin/gruff-go`, so `bin/` is build-only
output, consistent with the already-ignored root `./gruff-go`. Build it on demand
with `scripts/build-bin-gruff-go.sh` or the perf harness (`scripts/test-performance.sh`,
search: `if [[ ! -x "$BIN" ]]`); both `go build` into `bin/` when it is missing, and
`go build -o` creates the directory. `.gitattributes` (search: `Release archive hygiene`)
also carries a `/bin export-ignore` backstop so a force-added binary can never reach a
release archive.

**Original trap (historical):** `bin/gruff-go` was tracked in git - a ~12 MB committed
blob - while `.goat-flow/code-map.md` (search: `Local build output directory`) described
`bin/` as scratch output. So `go build -o bin/gruff-go` overwrote a committed file and
produced a spurious `Bin … bytes` diff; a follow-up `rm` then showed it as a deletion of
a tracked file. (Triggered 2026-06-04 while building a logging wrapper for a hook e2e
test - the wrapper clobbered the committed binary, which then showed as `D bin/gruff-go`;
restored with `git checkout HEAD -- bin/gruff-go`.) That clobber risk no longer applies
now that the binary is untracked.
