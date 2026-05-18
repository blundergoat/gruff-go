# Architecture

## System Overview

`gruff-go` is a Go CLI code-quality scanner plus GOAT Flow project memory and agent guardrails. `go.mod` declares module `github.com/blundergoat/gruff-go`; `.gruff-go.yaml` pins the repository's dogfood scanner config; `cmd/gruff-go` contains the executable entrypoint; `internal/` contains the parser-only analysis pipeline, low-noise default rule pack, opt-in expansion rules, scoring, and report rendering.

`package.json` and `package-lock.json` pin `@blundergoat/goat-flow` as the only declared npm dependency. `.claude/` contains Claude-owned settings and hooks, `.codex/` contains Codex-owned settings and hook registration, `.agents/skills/` contains Codex/Gemini shared skills, and `.goat-flow/` contains shared project context that future agents should update as the repository gains source code.

## Request Flow

A representative agent setup flow starts with the user request, then the active agent instruction file (`CLAUDE.md` for Claude or `AGENTS.md` for Codex) routes the agent through READ, SCOPE, ACT, and VERIFY. If a goat-* skill is invoked, the agent loads the matching installed skill under `.claude/skills/` or `.agents/skills/`; setup and audit commands execute through `node_modules/@blundergoat/goat-flow/dist/cli/cli.js`; durable findings are written back to `.goat-flow/`.

The analyzer runtime is local CLI plus an optional local dashboard. `cmd/gruff-go/main.go` delegates to `internal/cli`, which dispatches `analyse`, `baseline`, `list-rules`, `summary`, `report`, and `dashboard`. `analyse` can auto-load `.gruff-go.yaml`, apply JSON baselines, filter findings by git changed lines, and render text, full JSON, summary JSON, SARIF, GitHub annotation, or HTML output. `baseline` writes a JSON baseline from current findings. `list-rules` returns registry metadata. `dashboard` binds a local `net/http` server and serves the same HTML report through an iframe; scan requests pass an explicit root/context into `analysis.Run` and do not mutate process cwd. There is no application middleware, database layer, hosted service, or remote dashboard surface in this checkout.

## Auth / Trust Boundaries

No project authentication or authorization layer exists yet. The relevant trust boundary is local-agent safety: `.claude/settings.json` and `.codex/config.toml` define agent permissions, while `.claude/hooks/deny-dangerous.sh` and `.codex/hooks/deny-dangerous.sh` enforce Bash command safety checks before tool use.

Secrets should not be added to this repository. `.env.example` is allowed by Claude settings for documentation, but `.env*`, key files, credentials, and common cloud config paths are denied.

## Data Flow

Durable project memory lives in `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, `.goat-flow/decisions/`, `.goat-flow/architecture.md`, `.goat-flow/code-map.md`, and `.goat-flow/glossary.md`. Local continuity and active planning notes live under `.goat-flow/logs/sessions/` and `.goat-flow/tasks/`; scratch work belongs in `.goat-flow/scratchpad/`.

Go module identity flows from `go.mod`. The current `Makefile` discovers Go packages with `go list ./...`, then runs `go fmt`, `go vet`, and `go test` across the discovered package list.

Analyzer data flow:

1. `internal/source` expands input paths relative to the working directory, classifies Go and text/config files, and applies two layered exclusions before handing files to the parser. The primary filter is the repository's own `.gitignore` chain (see ADR-004); paths matched by it are recorded in `paths.skipped` with reason `gitignored`. Scanner discovery always skips non-application metadata directories (`.agents/`, `.claude/`, `.codex/`, `.github/`, and `.goat-flow/`) plus VCS metadata unless `--include-ignored` is set. A hardcoded fallback list still drops dependency, build-output, and local-tooling directories for repos that lack a `.gitignore`, and `paths.ignore` from `.gruff-go.yaml` layers additive project-specific excludes on top. Generated Go files are skipped after classification. The `--include-ignored` flag on `analyse`, `baseline`, `summary`, and the dashboard's `/scan` route bypasses both the gitignore filter and the hardcoded list; when set, `run.includeIgnored: true` appears in the JSON output.
2. `internal/parser` reads discovered files. Go files are parsed with the standard library `go/parser`; text/config files become source units without ASTs. Parse failures become diagnostics and the failed file is excluded from rule dispatch.
3. `internal/config` optionally loads strict gruff config from explicit `--config` or `.gruff-go.yaml`. The root `.gruff-go.yaml` mirrors the current default rule pack and leaves expansion rules disabled unless a future change intentionally opts in. The supported shape follows the gruff-family layout: `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, `selection.rules`, `selection.excludeRules`, `selection.pillars`, `selection.excludePillars`, and `rules.<id>.enabled/threshold/thresholds/severity/options`.
4. `internal/rule` validates rule definitions, sorts rule metadata by ID, dispatches enabled per-unit rules, project-level rules, then score-neutral composite rules, and sorts findings deterministically. The default-enabled registry contains file length, function length, cyclomatic complexity, package comment, and secret-like assignment rules. Opt-in rules currently cover package names with underscores, empty control-flow blocks, shell command execution, skipped tests, nesting depth, parameter count, exported-symbol comments, specific sensitive-data detectors, identifier quality, empty tests, no-failure-path tests, god-function composites, and hotspot-file composites.
5. `internal/baseline` can suppress exact rule/file/fingerprint matches from a JSON baseline and report stale entries.
6. `internal/diff` can ask local `git diff` for changed lines and filter findings to line-overlapping changes while reporting a partial-scope caveat.
7. `internal/scoring` computes severity/confidence-weighted per-pillar and composite scores after suppression/filtering. `design.*` composite findings are score-neutral annotations and do not add a second penalty on top of the underlying findings.
8. `internal/analysis` combines discovery, parse diagnostics, findings, skipped paths, missing paths, baseline/diff summaries, score, parser mode, rule metadata, and exit semantics into schema `gruff-go.analysis.v0.1`.
9. `internal/report` renders the report as compact text, full JSON, summary JSON, SARIF 2.1.0, GitHub annotations, standalone HTML, dashboard shell HTML, and optional interactive finding filters.

npm dependency state flows from `package.json` through `package-lock.json` into `node_modules/`. `node_modules/` is a dependency cache and should not be edited directly.

## Deployment / Operations

No deployment target, CI workflow, release process, or runtime infrastructure is present. The verified operational gates are the GOAT Flow audit commands run through the local package install and `make check`.

`npm test` is the default npm placeholder and currently exits with `Error: no test specified`, so it is not a valid project health gate.
