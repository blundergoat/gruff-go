# ADR-017: Cross-Port Rubric Calibration Contract

**Status:** Accepted
**Date:** 2026-05-31
**Author(s):** Codex, human direction
**Ticket/Context:** `.goat-flow/tasks/0.3.0/M34-cross-port-rubric-calibration.md`

## Decision

The gruff family shares one calibration contract for rule precision:

1. **Preserve semantic identifier identity.** Casing and identifier-quality rules
   must not erase meaningful digits or domain suffixes. `adr013`, `adr020`,
   `V110`, and `step0` are domain identifiers unless the stem is generic or the
   file proves a placeholder enumeration such as `item1` / `item2`.
2. **Respect public and serialized names.** Public, CLI, DTO, schema, and wire
   fields may need exact names such as `verbose`, `enabled`, `ok`, `force`,
   `help`, or `version`. Ports should expose an exact-name allowlist for those
   contract surfaces and should not require renaming a serialized key to satisfy
   a predicate-style boolean rule.
3. **Treat boundary mappings as intentional.** A camelCase local beside a
   snake_case wire key, an `_unused` convention, or a SCREAMING_SNAKE constant
   feeding a camelCase local is not casing drift when the boundary is clear.
4. **Prefer table-driven test clarity over ceremony.** Test loops and
   conditionals are findings only when they hide expected behaviour. Fixture
   arrays, local const-bound case tables, file/glob sweeps, invariant checks,
   and labelled contract sweeps are acceptable when the assertion remains easy
   to inspect.
5. **Do not treat meaningful counts as magic.** Small cardinality assertions and
   length/count checks are usually the contract under test. Opaque thresholds,
   unexplained large numbers, and undocumented constants remain findings.
6. **Require parseable disabled code before flagging commented-out code.**
   Separators, prose examples, regex/search anchors, and documentation snippets
   are not enough; a port should require parseable disabled code or a multi-line
   disabled block.
7. **Keep docs, security, and sensitive-data strict.** Documentation rules stay
   default-on when they create a reviewable contract, but boilerplate comments
   must not satisfy the rubric. Security and sensitive-data rules stay strict
   and default-on unless a fixture/dummy/redaction carve-out is high-confidence,
   tested both positive and negative, and never hides real secrets.
8. **Score root causes once without hiding findings.** Correlated complexity,
   size, and design findings may be clustered for grade math once per symbol,
   but the detailed findings remain visible for maintainers.

This contract is language-neutral. Each port may implement it with local parser
evidence, config names, and rule surfaces, but ports should keep the user-facing
policy vocabulary aligned unless a language has a stronger native convention.

## Context

M34 calibrated `gruff-ts` against goat-flow after two coding agents reported
high-volume false positives in naming, test-quality, maintainability, and score
math. The first implementation pass reduced the targeted goat-flow scan from
524 findings to 302 findings while keeping gruff-ts dogfood at 0 findings and
grade A. The largest drops came from preserving numeric identifier meaning,
accepting serialized boolean names, accepting domain-numbered identifiers,
recognising small count assertions, and rejecting prose-like commented-code
matches.

The calibration follows ADR-008's precision loop and ADR-011's mission: a rule
should make AI-generated code easier for a human to verify, not force rewrites
that damage public contracts or replace readable table tests with noisy
ceremony. It also narrows ADR-007 through ADR-016: useful default rules are
refined first, while convention-only or unproven noisy rules may be opt-in.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Disable noisy rules | Hides useful findings with the false positives and weakens the default gate. | Rejected. The user explicitly wanted refinement, not `enabled: false`. |
| Push every exception into per-project config | Every adopter rediscovers the same CLI, DTO, fixture, and table-test conventions. | Rejected. Stable conventions belong in rules or shared config surfaces. |
| Rename public or wire names to satisfy style rules | Breaks API, CLI, schema, and serialized contracts for cosmetic predicate naming. | Rejected. Public contract stability outranks naming ceremony. |
| Keep raw score penalties for overlapping complexity rules | One hard function dominates the grade several times even though the maintainer reviews one root cause. | Rejected. Detailed findings remain; score math should prioritise root causes. |
| Record a cross-port contract and let each port implement local evidence | Requires follow-up implementation work per language. | Accepted. It preserves shared policy without forcing identical AST machinery. |

## Consequences

- New or changed gruff rules should state whether they are enforcing a
  reviewability contract, a security/sensitive-data protection, or only a local
  convention.
- Calibration evidence must include before/after rule counts from at least one
  real target project and focused positive/negative tests for the accepted
  convention.
- Documentation-rule cleanup must reject boilerplate such as repeated
  "Maintainer note" comments; a passing doc rule should state contract, side
  effects, errors, invariants, or verification-relevant rationale.
- Security and sensitive-data fixture carve-outs must prove redaction and
  dummy/fixture boundaries without allowing raw secrets into reports.
- Ports should document score clustering as a numeric-semantic change when it
  changes score values while preserving report field names.

## Reversibility

Two-way door per rule family. A port can tighten or remove one convention
recognition if calibration later shows it hides real signal. Revisit this ADR if
two or more ports find that a listed convention is language-specific rather
than gruff-family policy, or if a future schema change introduces an explicit
machine-readable contract for clustered score penalties or accepted public
boolean names.
