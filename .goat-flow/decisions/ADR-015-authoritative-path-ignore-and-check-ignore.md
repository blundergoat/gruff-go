# ADR-015: Authoritative `paths.ignore` in Every Mode, and a `check-ignore` Command

**Status:** Accepted
**Date:** 2026-05-30

## Context

gruff's primary deployment is a coding-agent hook ([ADR-011](ADR-011-mission-ai-generated-code-verifiability.md)):
after an agent edits files, a hook runs gruff on the changed paths and gates on
the result. A hook passes gruff **explicit file paths** (or a diff), not a
project root to walk.

`paths.ignore` in `.gruff-go.yaml` is applied during discovery's directory walk.
The concern raised cross-port was that explicit-path and diff invocations might
bypass discovery and so bypass `paths.ignore`, making gruff flag files the
project deliberately excludes - wasting agent effort "fixing" out-of-scope code
(generated files, vendored trees, fixtures).

Verification on gruff-go (2026-05-30, throwaway repro + the existing
`TestDiscoverIncludeIgnoredPreservesConfigIgnores`): every invocation shape -
explicit file argument, `--changed-ranges`, `--diff -`, `--since`, `--diff-base`
- already routes through `source.Discover` first; the diff layer only *filters*
already-discovered files. So `paths.ignore` was already authoritative in gruff-go.
The real gaps were (a) the machine output said only *that* a path was skipped
(`reason`), not which layer or glob decided it, and (b) there was no way to ask
"would gruff ignore this path?" without running a full scan - the question a hook
wants to answer before invoking gruff at all.

A subtlety: the ignore decision had two consumers (discovery's skip records and,
now, the check-ignore command). Implementing the check twice would risk drift
between "what analyse ignores" and "what check-ignore reports" - the one thing
that must never disagree.

## Decision

1. **`paths.ignore` is authoritative in every invocation mode** - traversal,
   explicit file arguments, and all diff/changed-region modes. This was already
   true in gruff-go; it is now locked by regression tests
   (`TestAnalyzeExplicitIgnoredArgProducesNoFindings`,
   `TestAnalyzeDiffModeHonorsConfigIgnore`,
   `TestAnalyzeIncludeIgnoredKeepsConfigIgnore`) rather than left as an emergent
   property. `--include-ignored` opts into git-ignored / default-ignored paths
   only and never overrides config `paths.ignore`.

2. **Skip entries carry `source` and `pattern`.** `source.SkippedPath` and
   `analysis.SkippedPath` gain `source` (`config | gitignore | default |
   generated`) and `pattern` (the exact `paths.ignore` glob, set only for
   `source: config`). Both are additive `omitempty` JSON fields; the existing
   `reason` code is retained, so `{path, reason}` consumers and the SARIF surface
   are unaffected. No analysis schema bump (`gruff-go.analysis.v0.2` unchanged).

3. **Single ignore engine.** All path-based ignore logic is folded into one
   walker method, `decideIgnore(rel, isDir) IgnoreDecision`, used by discovery's
   `visitDir`/`visitFile` and exported via `source.CheckIgnore`. There is no
   second glob/ignore implementation. Generated-file detection stays in
   `addFile` because it must read file contents - it is therefore out of the
   path-only engine and never reported by `check-ignore` (which is O(1) per
   path).

4. **New `check-ignore` command.**
   `gruff-go check-ignore [--format text|json] [--config <path>|--no-config]
   [--include-ignored] <path>...`. It shares analyse's config resolution
   (`configuredRegistry`) and the engine above, performs no analysis, mirrors
   `git check-ignore` exit codes (0 = ≥1 ignored, 1 = none, 2 = error), and emits
   the agent contract as JSON: `[{path, ignored, source, pattern}]`. Text mode
   lists only ignored paths, one per line.

5. **Cross-port contract.** `CONTRACT.md` records `paths.ignore` authority in
   every mode, the `source`+`pattern` skip fields, the `--include-ignored`
   boundary, and that every implementation exposes `check-ignore`.

### Rejected alternatives

- **Map `reason` onto the `source` vocabulary (rename `config-ignore` →
  `config`, drop `reason`).** Cleaner long-term but a breaking value-rename for
  current `reason` consumers; the no-legacy-compat policy permits breaks, but
  there was no need - additive `source`/`pattern` carries the new signal without
  touching `reason`.
- **A `--format json` flag on the global `-v` for verbose text.** gruff-go's
  global flag layer reserves `-v`/`--verbose` as a cross-port no-op and strips it
  before any subcommand runs, so a text `-v` variant would be swallowed. The
  source/pattern detail lives in `--format json` (the agent contract) instead;
  text mirrors `git check-ignore`'s plain path list.

## Consequences

- A hook can call `check-ignore` to skip gruff entirely for excluded files, and
  can read `source`/`pattern` on any skip to explain an exclusion rather than
  silently dropping a file.
- analyse and check-ignore cannot drift: they share one engine, asserted by
  `TestCheckIgnoreSharesEngineWithDiscover` and
  `TestCheckIgnoreSharesEngineWithAnalyse`.
- Schema stays `gruff-go.analysis.v0.2`; SARIF and `{path, reason}` consumers are
  unaffected. The dogfood scan remains grade A.
- The dead `pathUnderRoot` helper was removed when the per-shape gitignore checks
  were unified into `decideIgnore` (which works in repo-relative slash form via
  `repoRelative`).
