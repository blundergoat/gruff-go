# ADR-001: Parser-Only Scanner Pipeline

**Status:** Implemented
**Date:** 2026-05-13
**Updated:** 2026-05-18
**Author(s):** Codex
**Ticket/Context:** `.goat-flow/tasks/0.1`

## Context

The first `gruff-go` implementation needed to become useful without adding dependency metadata or requiring a complete build environment for every scanned target. M01 compared parser-only loading with package/type loading in scratch fixtures and selected a standard-library parser path for the v0.1 rule pack. M02 implemented `cmd/gruff-go`, `internal/source`, `internal/parser`, `internal/rule`, `internal/analysis`, `internal/report`, and `internal/scoring`.

Evidence from this session:

- `go test ./...` exited 0 after the parser-only implementation.
- `go run ./cmd/gruff-go analyse --format summary-json .` scanned 41 files, reported 0 findings, exit code 0, and score 100/A after dogfood tuning.
- `go.mod` and package metadata were not changed by the implementation.

## Decision

`gruff-go` v0.1 uses a parser-only analysis pipeline:

- `internal/source` expands paths, classifies Go and text/config files, applies default/configured ignores, and skips generated Go files.
- `internal/parser` reads files and parses Go with the standard library `go/parser`.
- Rules operate on parser units, source text, ASTs, and project-level unit collections.
- Type/package-aware rules are deferred until a later milestone proves that they need type information and can degrade cleanly when imports or packages fail.

M21 addendum: rule definitions also carry an explicit capability label with the closed enum `parser`, `type`, `ssa`, and `dataflow`.

- `parser` means the rule can run with source discovery, source text, Go parser units, ASTs, or already-produced findings.
- `type` means the rule requires package/type information that the v0.1 runtime does not provide.
- `ssa` means the rule requires an SSA/IR representation that the v0.1 runtime does not provide.
- `dataflow` means the rule requires path/taint/dataflow evidence that the v0.1 runtime does not provide.

All shipped v0.1 rules must report `parser` while this ADR remains the runtime contract. A future rule may declare a higher tier only in the same milestone that adds and verifies the runtime capability needed to serve that tier; capability labels are metadata, not permission to over-claim scanner coverage.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Require type/package loading in v0.1 | Incomplete modules and missing imports can block basic size, documentation, complexity, and secret scans. | Rejected for v0.1. The starter rule pack does not need type information. |
| Use parser-only loading with explicit diagnostics | Type-aware rules are deferred, but basic scans stay deterministic and dependency-light. | Accepted. It matched the approved starter pack and avoided package metadata changes. |
| Use text-only scanning | Go-specific AST rules such as function length and package comments become brittle. | Rejected. Parser units provide needed structure without full type loading. |

## Reversibility

Two-way door. A future milestone can add a package/type loader alongside parser units if it preserves parser-only fallback behavior, keeps diagnostics deterministic, proves the added rules need type data, and updates the capability invariant with runtime evidence.
