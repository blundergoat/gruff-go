# Glossary

## gruff-go

The target project checkout. Despite the name, it currently contains no Go module or application source; it is a bootstrap repository with GOAT Flow and Claude setup files.

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

A repository state where setup/configuration exists but runtime source, tests, CI, deployment files, and domain behavior have not been added yet.
