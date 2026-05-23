# ADR-004: Gitignore-Respecting Discovery

**Status:** Accepted
**Date:** 2026-05-16
**Updated:** 2026-05-18
**Author(s):** Claude
**Ticket/Context:** `.goat-flow/tasks/0.1/M12-respect-gitignore-in-discovery.md`

## Context

`internal/source.Discover` is the boundary that decides which files the rule registry sees. Its v0.1 design (ADR-001) walks the working directory, classifies files by extension, and drops a hardcoded set of directory names (`.git`, `vendor`, `node_modules`, `dist`, `build`, `coverage`, `.idea`, `.vscode`, plus agent/workflow metadata directories such as `.agents`, `.claude`, `.codex`, `.github`, and `.goat-flow`). Anything else is offered to the parser and the text-rule passes.

That model conflates two boundaries that the working tree already separates:

- "What this project consists of" - the tracked working tree, the contract the developer is willing to publish.
- "What happens to live next to the project" - generated artefacts, machine-local tooling state, editor caches, agent runtime files, dependency caches, build outputs, dotfiles owned by other tools.

Git already maintains a precise, per-project description of that second set in `.gitignore`. Every project that uses Git keeps this file current as a routine consequence of normal work; it is the most reliable signal the scanner can read for "do not analyse this." The hardcoded directory list captures only the broadest, most universal cases of the second set; everything project-specific (or new) leaks through and ends up in front of the rule registry until the developer notices the noise and adds the path to `paths.ignore` in `.gruff-go.yaml`.

Maintaining that exclusion list in two places - `.gitignore` and `paths.ignore` - is a steady-state drift hazard. The repository owner already names the boundary once in `.gitignore`; the scanner should consume that source rather than ask the owner to mirror it.

A secondary concern is reproducibility. The decision to read `.gitignore` is straightforward; the temptation to also read the user's global gitignore (`core.excludesFile`), the repo-local `.git/info/exclude`, or the result of `git check-ignore` is the part that breaks two engineers running the same commit and getting different scans. The decision below draws that line explicitly.

A tertiary concern is the discovery-time cost of running rules over files the developer has chosen not to ship. Beyond noise, certain rule families (sensitive-data, secret-pattern) are actively harmful when run over local state: a finding produced against a path the working tree treats as private can leak that path into a shared report. The most direct mitigation is to stop walking those files at the discovery layer rather than filter them at the rule or report layer.

## Decision

`gruff-go` discovery treats the repository's own `.gitignore` files as the canonical exclusion source for the analysed set:

- `internal/source.Discover` consults a gitignore matcher for every directory and file it encounters. A path that the matcher reports as ignored is added to `paths.skipped` with reason `gitignored` and is not handed to the classifier, the parser, or any rule.
- The matcher implements the gitignore spec as Git itself defines it: hierarchical `.gitignore` files at every depth, later rules override earlier rules within the same file, deeper files override shallower files, explicit `!pattern` re-includes a previously excluded path, anchored vs un-anchored patterns and directory-only `/` suffixes are honoured.
- Only `.gitignore` files inside the discovery root participate. The user's global gitignore, `.git/info/exclude`, and `core.excludesFile` are not consulted. Discovery does not shell out to `git` and does not require the `.git` directory to exist.
- VCS metadata directories (`.git`, `.hg`, `.svn`) and non-application metadata directories (`.agents`, `.claude`, `.codex`, `.github`, and `.goat-flow`) are always excluded unless `--include-ignored` is set; they are not project source. The broader hardcoded directory list (`vendor`, `node_modules`, `.idea`, etc.) remains in place only as a per-subtree fallback for trees lacking a `.gitignore` anywhere in the ancestor chain (extracted tarballs, vendored snapshots, build contexts where `.gitignore` was pruned). Once a `.gitignore` exists in the chain - either at the root or in a subtree - that file owns the project boundary for its subtree's broad cache, dependency, and build directories; the fallback steps aside so a monorepo subtree's `.gitignore` is not silently overridden by the rootless default.
- `paths.ignore` in `.gruff-go.yaml` continues to layer additively on top. A path matched by either source is skipped. Neither source can re-include a path the other has dropped; `paths.ignore` does not support negation in this revision.
- A new boolean flag, `--include-ignored`, on `analyse`, `baseline`, `summary`, `report`, and the dashboard's `/scan` query bypasses the gitignore matcher, generated-file skip, and hardcoded default/fallback ignore lists. `paths.ignore` continues to apply because it is explicit scanner policy, not a working-tree ignore source. When the flag is set, the JSON output exposes `run.includeIgnored: true`; when unset, the field is omitted.
- The JSON schema gains exactly one value: `gitignored` is added to the set of allowed strings on `paths.skipped[].reason`. The schema version is unchanged. No other field is added or renamed.
- `gruff-go` does not modify `.gitignore` under any circumstance. The scanner reads; it never writes.
- The matcher is a per-discovery artefact, not a process-wide singleton. Two scans against different roots in the same process do not share matcher state.

The choice of matcher implementation - vendored library vs. in-tree parser - is a separate, narrower decision and is captured in a follow-up ADR alongside the licence, supply-chain, and maintenance review.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep the hardcoded directory list as the sole exclusion source | Project-specific local state outside the universal names (editor caches, agent runtime files, generated reports) keeps reaching the rule registry. Every adopter has to enumerate the same paths in `paths.ignore`; the list drifts from `.gitignore` and silently loses coverage as the working tree grows. | Rejected. The drift cost is paid by every adopter forever. |
| Require adopters to mirror `.gitignore` into `paths.ignore` | The configuration becomes the source of truth instead of the working tree. The two lists fall out of sync the first time an entry is added to `.gitignore` and forgotten in `paths.ignore`. | Rejected. The scanner should consume the boundary the working tree already maintains. |
| Respect `.gitignore` plus the global gitignore and `.git/info/exclude` | Two engineers running the same commit on different machines see different scans. CI and local diverge. Shareable reports lose their meaning. | Rejected. Reproducibility is a hard constraint. |
| Shell out to `git check-ignore` | Discovery stops working in tarballs, snapshot extracts, and environments without Git installed. The scanner gains a transitive dependency on the developer's Git version. | Rejected. The scanner must run on any directory, with or without Git. |
| Respect `.gitignore` by default with a documented opt-out (`--include-ignored`) and keep the hardcoded list as fallback | The default scan matches the working tree's published boundary. Repositories without `.gitignore` keep the existing v0.1 behaviour. Users who explicitly want to scan ignored paths have one knob to flip. | Accepted. The default matches the boundary the developer has already named; the opt-out is honest and explicit; the fallback covers the tarball case. |
| Make the exclusion configurable per rule (some rules ignore gitignored paths, some scan them) | The mental model fragments. Two findings from the same scan reflect two different definitions of "the project." Calibrating thresholds and reading reports both get harder. | Rejected for this revision. The single-axis design is the right starting shape; a per-rule split can be revisited if calibration evidence demands it. |

## Reversibility

Two-way door at the behaviour level. The matcher sits behind a discrete interface in `internal/source/`; a future decision can replace its policy (e.g. split gitignore handling per rule pillar, honour `.git/info/exclude`, accept a project-wide opt-out flag in `.gruff-go.yaml`) without rewriting the walker, the classifier, or any rule. The hardcoded fallback list stays in place, so disabling the gitignore matcher entirely returns the scanner to its v0.1 behaviour without further change.

One-way door at the JSON schema level: the `gitignored` value on `paths.skipped[].reason` is additive and will not be removed once consumers depend on it. A later decision that retires the matcher must still emit `gitignored` for the lifetime of `gruff-go.analysis.v0.1`, or move the contract to a new schema version.

Revisit triggers:

- Calibration evidence that a sensitive-data or secret-pattern rule misses real findings because the file lived under an ignored path. The follow-up shape is a per-rule "scan ignored files" opt-in, captured in a new ADR.
- Adoption signals that `--include-ignored` is the wrong granularity (e.g. users want "scan ignored files but only under this subtree"). The follow-up shape is a `paths.include` config knob or a per-rule opt-in; either choice supersedes the relevant clause of this ADR.
- A reproducibility regression traced to the matcher implementation. The matcher swap is in-scope without amending this ADR; a change to *which* sources are consulted (global gitignore, `.git/info/exclude`) is not, and requires a superseding ADR.
