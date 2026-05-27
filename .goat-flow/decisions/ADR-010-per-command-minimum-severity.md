# ADR-010: Per-Command minimumSeverity Config Dimension

**Status:** Accepted
**Date:** 2026-05-26
**Author(s):** Claude, human direction
**Ticket/Context:** PR #3 left three CLI consumers (`summary`, `report`, and `runner.go`'s programmatic fallback) defaulting to `SeverityWarning` while `analyse` had been intentionally lowered to `SeverityAdvisory` in ADR-009. The same repo produced different exit codes from different commands without telling the user. The dashboard hard-coded an unparseable `"medium"` default. Sibling ports (gruff-rs / gruff-ts / gruff-py / gruff-php) already model "never fail" as a `None` value on their `FailThreshold` enum; gruff-go had no equivalent.

## Decision

A new `minimumSeverity:` block in `.gruff-go.yaml` carries per-command default thresholds for `analyse`, `summary`, `report`, and `dashboard`. A new `none` value joins the existing 3-bucket vocabulary (`advisory / warning / error`), meaning "report findings, never exit 1." Implemented via a new `finding.FailThreshold` type separate from `Severity`.

Final shape:

```yaml
minimumSeverity:
  analyse: advisory
  summary: advisory
  report: none
  dashboard: none
```

**Precedence rule (tested):**

```
CLI flag (--min-severity / --fail-on)  >  config minimumSeverity.<cmd>  >  binary default
```

The binary default is `finding.DefaultFailThresholdFor(cmd)`. Both the analysis runner fallback (`internal/analysis/runner.go::normalizeOptions`) and the dashboard state default (`internal/dashboard/state.go::defaultState`) consume this single helper - the lockstep footgun in `.goat-flow/footguns/severity.md` is closed by construction, not by a docs-sweep contract.

**No SchemaVersion bump.** The `MinimumSeverity` field is additive and optional; existing `.gruff-go.yaml` files without the key continue to parse cleanly. The bump is deferred until the first actual config-shape break. Matches the same policy `tasks/0.1.3/M05` uses for the additive `StableIdentity` field.

**FailThreshold is a separate type from Severity** (`internal/finding/threshold.go`). Severity is the per-finding urgency tag; FailThreshold is the process gate with one extra value (`None`) the per-finding type cannot meaningfully carry. Mirrors gruff-rs's `pub(crate) enum FailThreshold { None, Advisory, Warning, Error }`.

**`finding.DefaultFailThresholdFor(cmd)` is the canonical default source.** The runner fallback and dashboard default both consume it; the lockstep cannot drift because there is one map:

| Command | Default |
| --- | --- |
| `analyse` | `Advisory` (gating: fail on anything) |
| `summary` | `Advisory` (gating) |
| `report` | `None` (artifact generator) |
| `dashboard` | `None` (artifact generator) |

Unknown command names fall back to `Advisory` (conservative "fail on anything" for gating contexts) rather than erroring; callers that want to surface "unknown command" as a user warning validate the command name at their own boundary.

## Context

The pre-ADR-010 state had four stale or divergent threshold defaults:

1. `internal/cli/cli.go:189` (`analyse`) - correctly set to `SeverityAdvisory` post-ADR-009.
2. `internal/cli/summary.go:25` - still defaulted to `SeverityWarning`. Stale.
3. `internal/cli/report.go:24` - still defaulted to `SeverityWarning`. Stale.
4. `internal/analysis/runner.go:128-129` - programmatic fallback for empty `Options.FailOn` was `SeverityWarning`. Stale; the dashboard hit this path.
5. `internal/dashboard/state.go:20` - hard-coded `"medium"` which no longer parses post-ADR-009. Unreachable but visible in code review.

Without `none`, "viewing" commands (`report`, `dashboard`) had no way to express "render the artifact, never exit 1." The sibling ports already model this:

| Port | FailThreshold values |
| --- | --- |
| gruff-rs | `None / Advisory / Warning / Error` (4) |
| gruff-php 0.1.4 M11 | same 4 |
| gruff-go (pre-ADR-010) | `Advisory / Warning / Error` (3) - no off-switch |

The wording brainstorm at `.goat-flow/logs/critiques/2026-05-26-config-wording-brainstorm-b5k2x.md` initially picked `never` for the off-switch value; the user reversed to `none` post-review for cross-port consistency.

The 2026-05-26 plan critique at `.goat-flow/logs/critiques/2026-05-26-0815-0.1.2-plan-7e3k1.md` surfaced three structural changes against the original plan: (a) move M05 (StableIdentity) and M06 (remediation rewrite) out of 0.1.2 because they were orthogonal to this theme; (b) absorb the 12-site `.FailOn` reader sweep into M01 rather than punting it to M02 (the original plan's "kill if >6 readers" criterion was already triggered at 12); (c) drop the SchemaVersion bump because the new key is additive. All three accepted.

## Cross-Port Consistency

Recorded so a sibling-port reviewer doesn't flag either fact as inconsistency:

- **Value vocabulary is aligned.** gruff-php 0.1.4 M11 also settled on `none` as the off-switch value. The original wording brainstorm picked `never`; both ports reversed independently to `none` per the same user direction.
- **Gating-commands surface area is deliberately divergent.** gruff-go validates 4 keys (`analyse | summary | report | dashboard`); gruff-php 0.1.4 M11 validates only 3 (`analyse | report | dashboard`) because PHP's `summary` command does not gate exit code. Intentional, not port drift.

## Naming Rationale

Three names exist for what is conceptually one concept:

| Surface | Name | Why |
| --- | --- | --- |
| YAML key | `minimumSeverity:` | Matches the existing `--min-severity` CLI flag (already shipped). |
| Go type | `FailThreshold` | Matches the gruff-rs port. |
| CLI flag | `--min-severity` (and `--fail-on` alias) | Already shipped; rename would be a breaking change. |

The Go-type / YAML-key inconsistency is accepted explicitly here rather than left to surface as confusion later. Renaming the Go type to `MinimumSeverity` would diverge from the gruff-rs port (worse cross-port reviewability); renaming the YAML key to `failThreshold:` would diverge from the user-facing flag (worse user reviewability). Both diverge in some direction; the chosen split optimises for the two reader groups that hit each surface most often (Go contributors → Go type; YAML editors → YAML key).

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| A. Hardcoded defaults per consumer (status quo without the config block) | Projects with non-default gating policies pass `--min-severity` on every CLI invocation; CI scripts duplicate the value across `analyse` / `summary` / `report` calls; the stale `summary`/`report`/`runner` defaults stay buried until the next audit. | Rejected. The whole point is to make the per-command policy declarative. |
| B. Config-only (no `--min-severity` flag override) | A user can't override the config for a one-off CI run without editing the file. | Rejected. The flag exists; precedence over config is expected. |
| C. `defaults.failOn:` wording instead of `minimumSeverity:` | Diverges from the existing CLI flag name (`--min-severity`); creates a third name for the same concept. | Rejected per the wording brainstorm. |
| D. `failThreshold:` YAML key (match the Go type) | Diverges from the CLI flag; the YAML-key vs CLI-flag mismatch is worse than the YAML-key vs Go-type mismatch (users see the CLI more than the Go type). | Rejected. See Naming Rationale. |
| E. Bump `SchemaVersion` `v0.1` → `v0.2` for this change | Four sites to update (`internal/config/config.go`, `internal/analysis/report.go`, `internal/report/machine_test.go`, `package.json`); existing in-tree configs need a mechanical bump; M05 (StableIdentity, also additive) would have to bump too or the policy splits. | Rejected. Additive optional key is not a breaking change. Reserve `v0.2` for the first config-shape break. |
| F. Single global `failOn:` value without per-command keys | Cannot express the "fail on advisory for analyse, never fail for report" philosophy that motivates this whole milestone. | Rejected. The per-command split is the feature. |
| G. Hard-break the `--min-severity` flag rename to match `minimumSeverity:` | Every CI integration that already pins `--min-severity` breaks. | Rejected. The flag stays; the YAML key uses the same name. |
| H. Add `--no-fail` flag instead of a `none` value | Two off-switches (flag and config) for one concept; CLI surface grows unnecessarily. | Rejected. `none` covers it. |

## Consequences

- **Backward-compatible config.** Existing `.gruff-go.yaml` without `minimumSeverity:` continues to parse and run. The new key is opt-in.
- **CLI consumer defaults change.** `summary` and `report` move from `FailThresholdWarning` to `DefaultFailThresholdFor(cmd)` (= `Advisory` and `None` respectively). Default `summary` runs now exit 1 on advisory-tier findings; default `report` runs exit 0 regardless of findings.
- **Programmatic runner fallback changes.** `internal/analysis/runner.go::normalizeOptions` empty-`FailOn` fallback moves from `SeverityWarning` to `DefaultFailThresholdFor("analyse")` (= `Advisory`). Callers that constructed `analysis.Options{}` without explicit `FailOn` see exit 1 on advisory findings where previously they saw exit 0 on advisory-only runs.
- **Dashboard stale literal fixed.** `internal/dashboard/state.go:20`'s `"medium"` (unparseable post-ADR-009) replaced by `DefaultFailThresholdFor("dashboard")` (= `None`).
- **Validator rejects legacy values.** `minimumSeverity.analyse: medium` errors out at config load time per `no-legacy-compat`; the user must migrate to `warning`.
- **Lockstep footgun reduced.** The CLI default + dashboard default + runner fallback all read from `finding.DefaultFailThresholdFor`. Future per-command default changes require updating ONE function, not four call sites.
- **Naming inconsistency surfaced, not hidden.** YAML uses `minimumSeverity:`, Go uses `FailThreshold`, CLI uses `--min-severity`. Future contributors see the three names side by side in this ADR rather than discovering them serially.
- **No schema bump pollution.** `gruff-go.config.v0.1` stays canonical; M04 verifies `v0.2` does NOT appear anywhere in the tree.

## Reversibility

**Soft door.** Reverting the config block requires:

1. `git revert` the M02 commit (mechanical).
2. Remove `minimumSeverity:` from `.gruff-go.yaml` files that adopted it (manual; users may have added per-command overrides).
3. CLI consumers fall back to their bare M01-era defaults (`FailThresholdAdvisory` for `analyse`, `FailThresholdWarning` for `summary`/`report`).

The `none` value is the hardest part to reverse: external scripts depending on the four-value vocabulary lose the off-switch. If reverting, communicate clearly that gating-disable now requires `--min-severity error` plus accepting that error-tier findings still trigger exit 1.

**Revisit trigger:** if a sibling port adds a fifth threshold value (e.g. an explicit `info`-tier triggerable gate), this ADR is the cross-port record of why gruff-go stopped at four. The `finding.FailThreshold` type is the obvious extension point.
