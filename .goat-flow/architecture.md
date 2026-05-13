# Architecture

## System Overview

`gruff-go` is currently a bootstrap repository for GOAT Flow project memory and agent guardrails. There is no application source tree yet; the live components are npm package metadata, installed Claude/Codex skills and safety hooks, and GOAT Flow shared knowledge directories.

`package.json` and `package-lock.json` pin `@blundergoat/goat-flow` as the only declared dependency. `.claude/` contains Claude-owned settings and hooks, `.codex/` contains Codex-owned settings and hook registration, `.agents/skills/` contains Codex/Gemini shared skills, and `.goat-flow/` contains shared project context that future agents should update as the repository gains source code.

## Request Flow

A representative agent setup flow starts with the user request, then the active agent instruction file (`CLAUDE.md` for Claude or `AGENTS.md` for Codex) routes the agent through READ, SCOPE, ACT, and VERIFY. If a goat-* skill is invoked, the agent loads the matching installed skill under `.claude/skills/` or `.agents/skills/`; setup and audit commands execute through `node_modules/@blundergoat/goat-flow/dist/cli/cli.js`; durable findings are written back to `.goat-flow/`.

There is no HTTP request path, application middleware, database layer, or runtime response flow in this checkout.

## Auth / Trust Boundaries

No project authentication or authorization layer exists yet. The relevant trust boundary is local-agent safety: `.claude/settings.json` and `.codex/config.toml` define agent permissions, while `.claude/hooks/deny-dangerous.sh` and `.codex/hooks/deny-dangerous.sh` enforce Bash command safety checks before tool use.

Secrets should not be added to this repository. `.env.example` is allowed by Claude settings for documentation, but `.env*`, key files, credentials, and common cloud config paths are denied.

## Data Flow

Durable project memory lives in `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, `.goat-flow/decisions/`, `.goat-flow/architecture.md`, `.goat-flow/code-map.md`, and `.goat-flow/glossary.md`. Local continuity and active planning notes live under `.goat-flow/logs/sessions/` and `.goat-flow/tasks/`; scratch work belongs in `.goat-flow/scratchpad/`.

Dependency state flows from `package.json` through `package-lock.json` into `node_modules/`. `node_modules/` is a dependency cache and should not be edited directly.

## Deployment / Operations

No deployment target, CI workflow, release process, or runtime infrastructure is present. The only verified operational gates are the GOAT Flow audit commands run through the local package install.

`npm test` is the default npm placeholder and currently exits with `Error: no test specified`, so it is not a valid project health gate.
