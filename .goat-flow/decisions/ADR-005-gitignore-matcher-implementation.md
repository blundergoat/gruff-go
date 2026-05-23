# ADR-005: Gitignore Matcher Implementation

**Status:** Accepted
**Date:** 2026-05-16
**Author(s):** Claude
**Ticket/Context:** `.goat-flow/tasks/0.1/M12-respect-gitignore-in-discovery.md`

## Context

[ADR-004](./ADR-004-gitignore-respecting-discovery.md) committed `gruff-go` to honouring the working tree's own `.gitignore` files as the canonical exclusion source for discovery. That ADR settled the behavioural surface - what is matched, how the opt-out works, which sources are not consulted, how the JSON schema grows. It deliberately deferred the narrower question of how the matcher itself is built.

The matcher has one job: given a slash-separated path relative to the discovery root and a boolean for "is this a directory", report whether the working tree's `.gitignore` files exclude it. The semantic surface required by ADR-004 and the M12 test fixtures is:

- Pattern lines with shell-style wildcards (`*`, `?`, `[...]`).
- Negation lines (`!pattern`) that re-include a path the same file or a shallower file had previously excluded.
- Anchored patterns (`/pattern` matches only at the level of the `.gitignore`).
- Un-anchored patterns (`pattern` matches at any depth below the `.gitignore`).
- Directory-only patterns (`pattern/` matches directories but not files).
- Recursive glob suffix (`pattern/**`) that already exists in `internal/pathfilter` semantics.
- Comment lines (`#` at column zero) and blank lines.
- Nested `.gitignore` files at lower depths whose rules layer on top of shallower ones.

The semantic surface explicitly excluded by ADR-004 (and not implemented by this matcher under any configuration) is:

- The user's global gitignore (`core.excludesFile`, `~/.config/git/ignore`).
- The repo-local `.git/info/exclude`.
- Anything that requires shelling out to `git`.

This ADR records which of two implementation routes the matcher takes and why.

## Decision

`gruff-go` implements the gitignore matcher in-tree in `internal/source/gitignore.go` and tests it in `internal/source/gitignore_test.go`. No new module dependency is added to `go.mod`.

Rationale:

- **Dependency surface.** `go.mod` currently declares zero non-standard imports. The codebase's ADR-001 commitment to parser-only analysis (no `golang.org/x/tools/go/packages`) and ADR-002's "narrow defaults, evidence-backed" posture both treat dependency cost as material. Adding a transitive tree for a feature whose semantic surface fits in ~200 lines is out of proportion with that posture.
- **Semantic scope.** The cases the M12 test suite asserts are the cases the matcher needs to handle. Git's own `wildmatch` and `excludes` machinery cover more (e.g. case-folding controlled by `core.ignorecase`, sparse-checkout interactions, partial-clone semantics) than discovery has any business consulting. A library that implements the full spec brings code paths gruff will not exercise; a focused implementation is honest about the scope.
- **Maintenance cost.** The candidate libraries (`github.com/sabhiram/go-gitignore`, `github.com/denormal/go-gitignore`, the gitignore subpackage of `github.com/go-git/go-git/v5`) range from "one maintainer, low commit cadence" to "huge transitive tree pinned to v5". None is a clearly better long-term bet than the ~200 lines of focused code this scanner needs.
- **Test confidence.** A custom implementation forces explicit fixtures covering the matched semantics. The fixtures *are* the contract; if the implementation drifts, the tests fail. Vendoring would replace those fixtures with trust in upstream releases.
- **Supply-chain footprint.** Every external module introduces a release-cadence question, a CVE-watch question, and (for `go-git/v5`) a meaningful binary-size question. None of those costs is recovered by the gain in semantic coverage.
- **Reversibility.** The matcher sits behind a discrete `Matcher` interface in `internal/source/`. If a future decision wants to swap in a library - because the in-tree matcher grew complex, or because Git's spec shifted in a way our tests missed - the swap is local to one file. The cost of starting in-tree and migrating later is small; the cost of starting on a library and migrating off is paying for the library's quirks until the migration is justified.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Vendor `github.com/go-git/go-git/v5/plumbing/format/gitignore` | Pulls in a multi-megabyte transitive tree to use one subpackage. The `v5` lineage drags in crypto, transport, and protocol code the scanner has no use for. | Rejected. Disproportionate dependency cost. |
| Vendor `github.com/sabhiram/go-gitignore` or `github.com/denormal/go-gitignore` | Smaller dependency, but commit cadence is low and the semantic delta from "what gruff needs" is unclear without a fixture-by-fixture audit. The audit cost is comparable to writing the matcher. | Rejected. Comparable work, worse leverage on tests. |
| Shell out to `git check-ignore` | Discovery stops working in tarballs and snapshot extracts, gains an external runtime dependency, and varies with the developer's Git version. Already excluded by ADR-004. | Rejected (and forbidden by ADR-004's kill criteria). |
| Implement the matcher in-tree behind a `Matcher` interface, with semantics tested explicitly | The implementation has to be written and maintained. The kill-criteria from ADR-004 (no global gitignore, no `.git/info/exclude`, no shell-out) become enforced by absence rather than by configuration. | Accepted. The implementation cost is bounded; the tests are the contract; the interface preserves the option to swap later. |

## Reversibility

Two-way door. The matcher is consumed via a small interface (`Matcher` with one `Match(rel string, isDir bool) (matched bool, source string)` method). A future ADR that vendors a library only needs to provide an adapter that satisfies the interface; the walker, the `IncludeIgnored` bypass, the `paths.skipped` reason `gitignored`, and the test fixtures are all unchanged. The migration path is "write the adapter, point `NewMatcher` at it, watch the existing tests stay green."

Revisit triggers:

- A semantic case the in-tree matcher gets wrong that a library would handle correctly, demonstrated by a failing fixture against real-world `.gitignore` content.
- Maintenance burden on the matcher exceeding the dependency cost of one of the candidate libraries (measured by issues filed against the in-tree implementation, not by guessed future effort).
- A change to the canonical gitignore spec that the in-tree matcher would have to track from scratch but a maintained library already tracks.

The kill criteria from ADR-004 (no global gitignore, no `.git/info/exclude`, no shell-out, no `.gitignore` mutation) are inherited by this ADR and apply to any future adapter regardless of which library it wraps.
