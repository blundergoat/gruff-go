# ADR-009: Collapse Severity Model to advisory/warning/error

**Status:** Accepted
**Date:** 2026-05-25
**Author(s):** Claude, human direction
**Ticket/Context:** Cross-port summary-output harmonisation. Sibling gruff-rs / gruff-ts / gruff-py / gruff-php all use the 3-bucket `advisory / warning / error` model; gruff-go is the only port using 5 (`critical / high / medium / low / info`). Aligning required either dual-projecting at the renderer or migrating the canonical model. The migration was chosen.

## Decision

gruff-go's `Severity` type collapses from 5 buckets to 3. Canonical names match the sibling ports:

| Old (5-bucket) | New (3-bucket) |
| --- | --- |
| `critical` | `error` |
| `high` | `error` |
| `medium` | `warning` |
| `low` | `advisory` |
| `info` | dropped (no rule ever emitted it; not aliased) |
| `notice` (parse-only alias of `low`) | dropped (was a render-side compat alias) |
| `warn` (parse-only alias of `medium`) | dropped |

**Hard break.** Parsing rejects all old names (`critical`, `high`, `medium`, `low`, `info`, `notice`, `warn`) with `unknown severity "<name>"`. Existing user `.gruff-go.yaml` files with `severity: critical` or `severity: notice` fail to load until updated. The CHANGELOG entry under `[Unreleased]` documents this loudly.

**Default `--min-severity` becomes `advisory`** (show everything). Previously `medium`, which semantically equalled today's `warning`. The new default is intentionally more permissive: the rule pack is broad and advisory-tier findings (the largest bucket) become visible by default.

The schema version bumps `gruff-go.analysis.v0.1` → `gruff-go.analysis.v0.2` because public JSON fields change (`Report.Summary.CountsBySeverity` keys and `PillarDetail.{Critical,High,Medium,Low,Info}` fields).

## Context

The pre-migration state had three competing severity vocabularies in the codebase:

1. **Internal 5-bucket** (`internal/finding/types.go`): `info / low / medium / high / critical` with weights `1 / 3 / 8 / 15 / 30`.
2. **External 3-bucket aliases** (`internal/config/render.go::renderSeverityAlias`): emit `notice` for `low`, `warning` for `medium`, `error` for `high`; pass `info` and `critical` through verbatim.
3. **CLI strict 5-bucket** (`internal/cli/cli.go::ParseSeverity`): `--min-severity` / `--fail-on` accept only the internal 5 names, not the rendered aliases — so `--fail-on warning` was a runtime error even though the rendered config used `warning`.

The asymmetry was itself a footgun: a user copying `severity: warning` from their `.gruff-go.yaml` into `--fail-on warning` got a parse error. Sibling ports avoid this because their internal model matches their external surface.

Cross-port survey (2026-05-25):

| Port | Severities |
| --- | --- |
| gruff-php, gruff-rs, gruff-ts, gruff-py | `advisory / warning / error` (3) |
| gruff-go | `critical / high / medium / low / info` (5) |

Without a migration, the summary output (text + JSON) could not share a column shape across all five ports. Either the renderer projects 5→3 lossily for output only (keeps the asymmetry, adds a translation layer), or the canonical model becomes 3. The migration was chosen because the asymmetry was already paying a maintenance cost.

Rule distribution before migration (counted in `internal/rule/*.go`): **43 Low, 10 Medium, 11 High, 2 Critical, 0 Info**. The 5→3 mapping keeps every non-zero bucket addressable; the two Critical-tier rules (`sensitive-data.private-key`, `sensitive-data.gcp-service-account`) collapse to `error` alongside the High-tier rules without losing operator signal in CI (any CI gating on Critical also gates on the new Error tier).

The new penalty weights `1 / 8 / 30` retain the rough stair-step of the old `1+3 / 8 / 15+30`: collapsing the bottom pair to weight 1 and the top pair to weight 30 changes per-pillar scores at the margin, but the migration is paired with golden-snapshot regeneration in the same change so the new baselines are committed once and audited.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| A. Keep 5-bucket internal model; project to 3 at every output boundary | Permanent translation layer (text summary, JSON, SARIF, HTML, dashboard each need their own 5→3 mapping); the existing CLI-parse vs config-render asymmetry persists; sibling-port parity is cosmetic only. | Rejected. The asymmetry is the real cost; pushing the projection to N output sites multiplies it. |
| B. Add aliases so the 3-bucket names parse too (soft-break) | Two vocabularies live in the codebase forever; users see both in tooling output; every new rule contributor has to decide which name set to use. | Rejected as a long-term state, though considered briefly as a transition window. The user direction was hard-break with prominent CHANGELOG warning, sized to the pre-1.0 schema (`v0.1`). |
| C. Hard break to 3-bucket internal model | Existing user configs with `severity: critical` / `severity: notice` fail to load until updated. New CLI flag default (`--min-severity advisory`) shows more findings than the old default (`--min-severity medium` ≈ new `warning`). One-time golden-snapshot regeneration. | **Accepted.** Cleanest end state; the schema is pre-1.0 (`v0.1`), so the migration cost lands while the user surface is smallest. Recovery for an affected user is a one-line `sed`. |
| D. Migrate other ports to 5-bucket instead | Largest blast radius (4 ports change instead of 1); affects every rule definition in 4 codebases; harder to justify when 3-bucket is the cross-language convention (matches PHPStan-style severities, ESLint, ruff). | Rejected. The minority migrates, not the majority. |

## Consequences

- **User-visible breaking change.** Configs with `severity: critical|high|medium|low|info|notice|warn` no longer load. Migration is mechanical: `critical|high → error`, `medium|warn → warning`, `low|info|notice → advisory`. CHANGELOG `[Unreleased]` carries the explicit list of replacements.
- **Default CLI behaviour change.** `--min-severity` default goes from `medium` (≈ new `warning`) to `advisory`. Default scans show roughly 40-60% more findings depending on rule pack. CI integrations that relied on the implicit default for gate sizing should pin `--min-severity warning` explicitly.
- **Schema bump.** `gruff-go.analysis.v0.1` → `gruff-go.analysis.v0.2`. JSON consumers (dashboards, history readers, third-party scripts) parsing `Report.Summary.CountsBySeverity` or `PillarDetail` see renamed keys. Both fields drop the `Critical`/`High`/`Medium`/`Low`/`Info` keys and gain `Advisory`/`Warning`/`Error`.
- **Score values shift slightly.** Penalty weights move from `1/3/8/15/30` (5-bucket) to `1/8/30` (3-bucket). A pillar previously scored against 10 `low` + 5 `medium` (penalty `10×3 + 5×8 = 70`) scores against 10 `advisory` + 5 `warning` (`10×1 + 5×8 = 50`) under the new weights — a numeric reduction even though the rule mix is unchanged. Golden snapshots regenerated in the same change reflect the new equilibrium.
- **SARIF mapping simplifies.** `Critical|High → error`, `Medium → warning`, `Low|Info → note` collapses to a direct 1:1 (`error→error`, `warning→warning`, `advisory→note`). The dual-bucket source-side branch disappears.
- **Dogfood `.gruff-go.yaml` is updated in the same change** so the project's own config loads under the new parser. Hand-tuned severities (`notice`/`warning`/`error`/`critical`) are rewritten per the mapping.
- **`internal/cli/baseline.go::62` hardcoded `SeverityCritical`** becomes `SeverityError`.

## Reversibility

**One-way door for the schema bump and user configs.** Reverting requires:

1. `git revert` the migration commit (mechanical).
2. Every user who has updated their `.gruff-go.yaml` since the migration must revert that file too (manual).
3. The schema version reverts to `v0.1`, but consumers that adapted to `v0.2` field names break.

**Revisit trigger:** if cross-port harmonisation pressure ever reverses (e.g., a sibling port adopts a richer severity model and forces the others to follow), the lookup table above is the canonical record of which old name maps to which new tier. The two `Critical`-tier rules (`sensitive-data.private-key`, `sensitive-data.gcp-service-account`) are the obvious re-promotion candidates if a fourth "critical" tier ever returns.
