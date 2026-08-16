# ADR-020: Security-Tier Evidence Is Routed To The Family, Not Decided Locally

**Status:** Accepted
**Date:** 2026-08-12
**Author(s):** Claude, user direction
**Ticket/Context:** 0.5.0 go-live review of the 2026-08-11 cross-port remediation brief

## Decision

gruff-go keeps its `security.*` severity tiers exactly as shipped. No rule severity,
`DefaultEnabled`, threshold, scoring weight, or `.gruff-go.yaml` value changes on the strength of
this record.

What changes is that the evidence is written down and routed. The question — *should any
`security.*` rule carry `error` severity, and should a detected `security.*` finding cap the
composite below grade A* — belongs to the family contract's scoring-and-severity-parity section,
which is DRAFT and rides the coordinated JSON break. That section already names go's position and
records it as a coherent design rather than drift. This ADR supplies the evidence that section was
missing, including one fact that had never left a config file.

A future agent finding the tier surprising should read this record and stop, not raise a severity.

## Context

Five measurements, all taken 2026-08-12 at `4bb1c00`.

**1. The registry.** 22 `security.*` rules, all default-enabled: **20 advisory, 2 warning, 0 error**
(`gruff-go list-rules --no-config --format json`). By contrast `sensitive-data.*` is 16 rules at
**13 error, 3 warning**. Two families covering adjacent risk sit two tiers apart. The below-error
invariant is now pinned by `internal/rule/security_severity_guard_test.go` (search:
`TestDefaultSecurityRulesStayBelowError`).

**2. The observable consequence.** A fixture whose handler passes request input to both
`exec.Command("sh", "-c", …)` and a concatenated SQL query:

```
Composite: A (99.00 / 100)
Findings: 4 total · 0 error · 1 warning · 3 advisory
  [warning]  security.shell-command: exec.Command invokes a shell interpreter
  [advisory] security.sql-string-query: SQL query string is constructed dynamically
EXIT(--fail-on=error)=0
EXIT(default advisory)=1
```

Both rules fire. The scanner is not missing the vulnerability; the tier is deciding it cannot fail an
error-only gate.

**3. The fact that was never on the record.** `.gruff-go.yaml` — gruff-go's own dogfood config —
raises exactly one `security.*` rule above its shipped default:

```yaml
  security.shell-command:
    enabled: true
    severity: error
```

The built-in `ShellCommandRule.Definition()` in `internal/rule/expansion.go` ships
`finding.SeverityWarning`. The project does not scan itself at the tier it ships, for precisely the
rule the fixture in point 2 uses. The override is deliberate and rule-specific rather than blanket
dogfood hardening: `security.sql-string-query` is left at `advisory` five lines below it.

This cuts two ways and the family should see both readings. Either the shipped tier is too low and
the maintainer's own config is the honest calibration; or dogfooding a scanner against itself
warrants a stricter profile than adopters need, and the override is a local policy choice with no
bearing on the default pack.

**4. The mitigating design.** gruff-go's gating commands default to `advisory`
(`internal/finding/threshold.go`, search: `func DefaultFailThresholdFor`), so on `analyse` and
`summary` these findings *do* gate — `EXIT(default advisory)=1` above. The gap opens only when a
user selects `--fail-on=error`, or uses `report`/`dashboard`, which default to `none` and have no
finding gate at all. That second case was undocumented until this release; `docs/ci-integration.md`
and `docs/rules.md` now state the default per command.

**5. The precedent that cuts against raising tiers.**
[ADR-007](ADR-007-comprehensive-default-rule-pack.md) ships every rule default-enabled, and
[ADR-009](ADR-009-three-severity-model.md) lowered the default gate to `advisory` precisely so
severity tier and gate threshold became independent knobs. Raising `security.*` tiers to make an
error-only gate meaningful would partially re-couple them, and would do it in the port the family
contract currently holds up as the coherent design. Any proposal must engage with this rather than
treat the current tiers as an oversight.

## Options For The Family

Presented, not chosen. Each is a family decision because severities are serialized, grade-visible,
and cross-port.

| Option | What it changes | Cost |
| --- | --- | --- |
| Keep tiers; keep gates independent | Nothing | The `--fail-on=error` ceiling stays real; mitigated only by documentation |
| Raise selected `security.*` rules to error | Serialized severities, exit codes at `error` and `warning`, pillar scores, grades, baseline entries keyed on severity | Re-couples tier and gate against ADR-009; four sibling ports must take a parity position |
| Cap the composite when any `security.*` finding exists | Scores and grades in every port | Largest blast radius; changes what grade A means family-wide |
| Keep tiers, make the ceiling unmissable | Documentation and gate defaults only | Already partly done this release; does not close the `--fail-on=error` gap |

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Decide locally and raise severities | Four ports' parity breaks silently; serialized output changes outside the coordinated JSON break | **Rejected.** The family contract reserves severity parity for ratification, and the 2026-08-11 brief was explicit that a unilateral tier change is out of bounds |
| Leave the evidence in a config file | The dogfood override stays invisible to the ratification that needs it; a future agent "fixes" the discrepancy in whichever direction they notice first | **Rejected.** This is the durable-exception case the decisions README names |
| Record the evidence and route it | Nothing in the running system | **Accepted** |

## Reversibility

Two-way door, and deliberately cheap to reverse: nothing in the running system changed, so this ADR
can be superseded by the family ratification without a migration.

Revisit triggers:

- The family scoring-and-severity-parity section is ratified — this ADR is then superseded by it, and
  `docs/ci-integration.md`'s open-question section must be rewritten to match.
- `TestDefaultSecurityRulesStayBelowError` fails, meaning a `security.*` rule reached error without
  this record being revisited.
- The `.gruff-go.yaml` override is removed or extended, which would change the evidence in point 3.

## Consequences

- `docs/ci-integration.md` links this record from its open-question section, so the published
  question and the internal evidence stay connected.
- The dogfood override is now a documented deliberate deviation. A future agent must not "reconcile"
  `.gruff-go.yaml` with the shipped default in either direction without the family decision.
- No CHANGELOG entry: nothing user-visible changed beyond the doc link, which is covered by this
  release's existing CI-guide entry.
