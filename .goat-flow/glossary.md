# Glossary

## gruff-go

The target project checkout. It now contains a parser-only Go CLI scanner foundation plus GOAT Flow and agent setup files.

## GOAT Flow

The local agent workflow framework installed from `@blundergoat/goat-flow`. It provides Claude skills, audit commands, safety references, and `.goat-flow/` project-memory directories.

## Agent-Owned Surfaces

Files that one agent setup owns without widening scope. Claude owns `CLAUDE.md`, `.claude/skills/`, `.claude/settings.json`, and `.claude/hooks/`; Codex owns `AGENTS.md`, `.codex/config.toml`, `.codex/hooks.json`, and `.codex/hooks/`.

## Shared Agent Skills

The `.agents/skills/` directory installed for Codex and Gemini GOAT Flow skills. Skill files are copied verbatim from GOAT Flow and should not be customized with project-specific content.

## Learning Loop

The durable shared project-memory directories under `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, and `.goat-flow/decisions/`.

## Harness Audit

The GOAT Flow setup audit mode invoked with `--harness`. It checks structural setup concerns beyond the base agent audit, including context, constraints, verification, recovery, and feedback-loop surfaces.

## Bootstrap Repository

A repository state where setup/configuration and project metadata may exist, but runtime source, tests, CI, deployment files, and domain behavior have not been added yet.

## Parser-Only MVP

The v0.1 loading direction chosen in M01 and implemented in M02. It uses standard-library source discovery and `go/parser` without `golang.org/x/tools/go/packages`; type-aware rules are deferred until a future milestone has evidence they are needed.

## Diagnostic

A run-level problem, such as a missing input path or parse error. Diagnostics force analysis exit code `2`.

## Finding

A rule-produced quality result with rule ID, severity, confidence, pillar, location metadata, remediation, and a stable fingerprint.

## Gruff Config

The analysis config loaded explicitly by `--config` or discovered as `.gruff.yaml`, `.gruff.yml`, then `.gruff.json`. The root `.gruff.yaml` is this repository's standalone dogfood config and should reflect intentional scanner policy, not hide current findings. Config validation rejects unknown top-level keys, unknown rule IDs, unknown threshold names, invalid path ignore patterns, invalid pillars, and invalid sensitive-data preview allowlist patterns before a scan runs.

## Baseline

A JSON file with schema `gruff-go.baseline.v0.1` that stores rule ID, file, and fingerprint entries. Applying a baseline suppresses only exact matches and reports stale entries.

## Diff Mode

The `--diff-base` analysis mode. It uses local `git diff --unified=0` output to keep findings whose location overlaps changed lines and records a caveat that the run is changed-line scoped rather than full-project proof.

## SARIF

The Static Analysis Results Interchange Format. `gruff-go` emits SARIF 2.1.0 from the same report data used by text, JSON, summary JSON, and GitHub annotation output.

## Opt-In Rule

A rule listed by `list-rules` with `defaultEnabled: false`. It can be enabled through strict JSON config, but default scans skip it so experimental or context-sensitive signals do not change baseline dogfood behavior.
