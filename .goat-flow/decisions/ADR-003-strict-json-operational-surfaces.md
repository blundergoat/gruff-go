# ADR-003: Strict Gruff Config Operational Surfaces

**Status:** Implemented
**Date:** 2026-05-13
**Updated:** 2026-05-13
**Author(s):** Codex
**Ticket/Context:** `.goat-flow/tasks/0.1`

## Context

M04 added operational scanner surfaces after core findings became deterministic: config, baselines, diff filtering, summary JSON, SARIF, and GitHub annotations. A follow-up aligned `gruff-go` with the gruff-family config convention by adding `.gruff.yaml` auto-discovery while keeping the implementation standalone and avoiding dependency or package metadata changes.

Evidence from this session:

- `internal/config` uses `encoding/json` for JSON plus a small strict YAML subset for `.gruff.yaml`/`.gruff.yml`, with unknown-field rejection and validation for unknown rules, thresholds, path ignores, abbreviations, pillars, and preview allowlists.
- `internal/baseline` stores exact rule ID, file, and fingerprint entries under schema `gruff-go.baseline.v0.1`.
- A temporary git smoke generated a baseline with 1 finding, then re-ran analysis with 0 findings, exit code 0, and 1 suppressed finding.
- The same smoke confirmed SARIF output includes version 2.1.0 and the `complexity.cyclomatic` rule ID.

## Decision

Use strict gruff-family operational files for v0.1:

- Config schema: `gruff-go.config.v0.1`.
- Default config discovery order: `.gruff.yaml`, `.gruff.yml`, `.gruff.json`.
- Root `.gruff.yaml` mirrors default-enabled rule behavior and keeps default-disabled expansion rules opt-in; config changes must be treated as scanner policy changes rather than a way to hide dogfood findings.
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
| Use strict gruff-family config with standard library parsing plus a narrow YAML subset | The YAML support is intentionally not a general YAML parser, but it supports the expected `.gruff.yaml` config shape without package metadata changes. | Accepted. It keeps v0.1 small and deterministic while matching gruff-family conventions. |

## Reversibility

Two-way door before public release. A future config format can be added if it preserves strict validation, schema versioning, deterministic baseline matching, and reporter compatibility.
