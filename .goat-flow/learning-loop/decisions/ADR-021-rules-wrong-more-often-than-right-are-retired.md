# ADR-021: Rules wrong more often than right are retired, not tuned

**Status:** Accepted
**Date:** 2026-10-04
**Author(s):** Claude, user direction
**Ticket/Context:** precision-floor M19 under family lock M82. The operator ruled on 2026-10-04 that a rule right less than
half the time is deleted, and accepted the gruff-go table with "Accept all (Recommended)".

## Decision

gruff-go retires three rules the 0.6.0 precision measurement found right less than half the time:

- `security.sensitive-data-logging`, right on 0 of 16 judged findings;
- `security.sql-string-query`, right on 1 of 9;
- `sensitive-data.high-entropy-string`, right on 4 of 24, with the built-in lockfile skip that existed only for it
  (FAMILY-CONTRACT.md section 12 and section 13a now bind gruff-rs alone; workspace ADR-005 records the amendment).

Each rule's code, tests, false-positive guidance, dogfood config block and calibration entries are removed. A config,
baseline or `sensitiveExclusions` entry naming one is rejected as an unknown rule, as `complexity.npath` was (ADR-014).

It also turns seven rules off by default, each right less than half the time on fewer than ten findings, too few to
delete on: `dependency.go-mod-local-replace`, `security.insecure-random-secret`, `sensitive-data.aws-access-key`, `sensitive-data.connection-string`, `sensitive-data.gcp-service-account`, `sensitive-data.github-token`, `sensitive-data.google-api-key`. They stay in the catalogue and run when a config enables them.

The family specification records the retirement as a catalogue transition with no successor, and keeps the rule's review
record as `retired` (workspace ADR-010).

## Reversibility

The rule can return as a new, measured rule; `.goat-flow/plans/0.7.0-roadmap/rules-to-rebuild.md` in the workspace keeps
its wrong shapes and what a rebuilt rule needs.
