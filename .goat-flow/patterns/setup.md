---
category: setup
last_reviewed: 2026-05-26
---

# Setup Patterns

## Pattern: Re-derive numeric claims from the live registry before writing architecture

**Created:** 2026-05-21

**Evidence:** OBSERVED

**Context:** `.goat-flow/architecture.md` and `.goat-flow/code-map.md` carried a "29-rule default-enabled registry" claim across four lines while `go run ./cmd/gruff-go list-rules --format json` reported 30 rules. The drift went unnoticed because the count is asserted in prose rather than derived.

**Approach:** When an orientation doc states a count (rules, pillars, packages, version literals), re-derive it from the canonical source in the same session before writing or editing the claim. Authoritative sources: `go run ./cmd/gruff-go list-rules --format json` for rules and pillars; `go list ./...` for Go packages; `grep -c '"id"'` is unreliable for nested JSON - prefer `python3 -c "import json; …"` or `jq`. Cite the command used in the commit or PR so the next reader can re-run it.

## Pattern: Collapse lockstep-dependency defaults into one helper that all sites consume

**Created:** 2026-05-26

**Evidence:** OBSERVED

**Context:** ADR-009 (3-bucket severity migration) left four scattered fallback constants for the per-command `--min-severity` default - `internal/cli/cli.go`, `internal/cli/summary.go`, `internal/cli/report.go`, and `internal/analysis/runner.go` each carried their own literal. The dashboard server (`internal/cli/dashboard.go::runDashboard`) carried a fifth, parsed via the 3-value `ParseSeverity` which silently rejected `--fail-on none`. The lockstep was enforced by a footgun in `.goat-flow/footguns/severity.md` ("five places need to move in lockstep") - a docs-as-contract that any next default change would re-trigger.

ADR-010 (v0.1.2 minimumSeverity work) introduced `finding.DefaultFailThresholdFor(cmd string) FailThreshold` as a single map keyed by command name. Every site now consumes the helper: the four CLI consumers, the runner fallback, the dashboard state default, and the `gruff-go init`-rendered `minimumSeverity:` block. The footgun's enforcement flipped from manual ("don't forget to grep for SeverityWarning") to structural ("change the map; the rest follow"). The plan critique caught a sixth site (`internal/cli/dashboard.go`) that an earlier pass missed - a structural helper makes such omissions visible because the inconsistency surfaces as a compile-time or runtime mismatch with the helper's canonical values, not as silent drift.

**Approach:** Whenever a piece of state is read from N >= 3 sites and changing the value at any one site without the others is a bug, collapse those reads into one helper that lives next to the type (e.g. `finding.DefaultFailThresholdFor`). Three properties to preserve:

1. The helper lives in the package that owns the type, not in a CLI/UI layer - this prevents lower layers from going through indirection back up.
2. The helper takes the discriminator (here: command name) as input and returns the canonical value. Adding a new command means editing the helper, not the call sites.
3. Document the lockstep footgun with a "Future per-command default changes should edit the helper, not the call sites" sentence so the next contributor sees the contract before scattering a literal.

When this pattern lands, also update the relevant `.goat-flow/footguns/` entry to bump `last_reviewed:` and rewrite the "How to avoid" section to point at the helper rather than at a docs-sweep checklist - the manual enforcement step is now structural and worth recording so future audits don't redundantly grep for the old constants.
