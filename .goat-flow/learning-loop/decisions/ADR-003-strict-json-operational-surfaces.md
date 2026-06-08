# ADR-003: Strict Gruff Config Operational Surfaces

**Status:** Implemented
**Date:** 2026-05-13
**Updated:** 2026-05-18
**Author(s):** Codex
**Ticket/Context:** `.goat-flow/tasks/0.1`

## Context

Operational scanner surfaces were added after core findings became deterministic: config, baselines, diff filtering, summary JSON, SARIF, and GitHub annotations. A follow-up aligned `gruff-go` with a language-specific config convention by making `.gruff-go.yaml` the only auto-discovered config file before public release.

Evidence from this session:

- `internal/config` uses a small strict YAML subset for `.gruff-go.yaml`, with unknown-field rejection and validation for unknown rules, thresholds, path ignores, abbreviations, pillars, and preview allowlists.
- `internal/baseline` stores exact rule ID, file, and fingerprint entries under schema `gruff-go.baseline.v0.1`.
- A temporary git smoke generated a baseline with 1 finding, then re-ran analysis with 0 findings, exit code 0, and 1 suppressed finding.
- The same smoke confirmed SARIF output includes version 2.1.0 and the `complexity.cyclomatic` rule ID.

## Decision

Use strict gruff-family operational files for v0.1:

- Config schema: `gruff-go.config.v0.1`.
- Default config discovery file: `.gruff-go.yaml`.
- Root `.gruff-go.yaml` expresses per-project policy overrides on top of the registry's default rule pack. (Historical note: this ADR was written when expansion rules shipped default-off; [ADR-007](ADR-007-comprehensive-default-rule-pack.md) supersedes that policy and flips every shipped rule to default-on, leaving the project config to express per-rule overrides and threshold overrides instead.) Config changes must be treated as scanner policy changes rather than a way to hide dogfood findings.
- `--config` selects an explicit file, and `--no-config` skips default discovery.
- Baseline schema: `gruff-go.baseline.v0.1`.
- Config and baseline parsing fail closed on malformed files or unknown contract elements.
- Diff mode uses local `git diff --unified=0 --no-ext-diff --relative` and records that changed-line scans are not full-project proof.
- Reporters share the same `analysis.Report` data for text, full JSON, summary JSON, SARIF, and GitHub annotation output.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Add YAML/TOML dependencies now | Package metadata changes become necessary before the project proves config semantics. | Rejected for v0.1. |
| Accept unknown config keys | Misspelled rules and thresholds silently fail to affect scans. | Rejected. Strict validation is part of the public contract. |
| Use strict gruff config with standard library parsing plus a narrow YAML subset | The YAML support is intentionally not a general YAML parser, but it supports the expected `.gruff-go.yaml` config shape without package metadata changes. | Accepted. It keeps v0.1 small and deterministic while avoiding pre-release compatibility baggage. |

## Reversibility

Two-way door before public release. A future config format can be added if it preserves strict validation, schema versioning, deterministic baseline matching, and reporter compatibility.
