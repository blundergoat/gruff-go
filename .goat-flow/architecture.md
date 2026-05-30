# Architecture

## Mission

gruff-go exists to make AI-generated code something a human can trust. Its primary deployment is a **coding-agent hook**: when an agent writes code, gruff is the gate that forces output a reviewer who did not write it can read, review, and sign off on. It optimises for three things:

- **Legible enough to verify** — the reviewer can confirm the code does what was asked.
- **Secure where the eye fails** — it catches the security classes human review reliably misses.
- **Tested for real, not padded** — it forces high-signal tests and rejects low-signal test ceremony.

The intent it encodes: *you are a coding agent, and a human who didn't write this code has to read, review, and trust it.* Coding agents routinely produce code that superficially works while misunderstanding the requirement, so gruff forces the agent to state intent, usage, contract, and failure behaviour in prose — which is why doc comments are required even on a private one-liner. The doc gives a reviewer something to check the implementation against; a mismatch between the doc comment and the code is a signal the change needs a deeper look.

This mission is the tie-breaker for default, threshold, and rule decisions: judge each by whether it raises the odds a human can verify the agent's code *without* forcing low-signal ceremony. Size and complexity metrics are legibility backstops — pressure on their thresholds runs toward tighter, never looser. Honest limit: parser-only gruff can create the artifact a reviewer checks (a doc comment, an assertion) but cannot verify it is truthful; that judgement stays with the reviewer. This decision is recorded in [ADR-011](decisions/ADR-011-mission-ai-generated-code-verifiability.md).

## System Overview

`gruff-go` is a Go CLI code-quality scanner plus GOAT Flow project memory and agent guardrails. `go.mod` declares module `github.com/blundergoat/gruff-go`; `.gruff-go.yaml` pins the repository's dogfood scanner config; `cmd/gruff-go` contains the executable entrypoint; `internal/` contains the parser-only analysis pipeline, the 63-rule registry, scoring, report rendering, and the local dashboard.

`package.json` and `package-lock.json` pin `@blundergoat/goat-flow` as the only declared npm dependency; the Go binary itself has no runtime dependencies outside the standard library. `.claude/` contains Claude-owned settings and hooks, `.codex/` contains Codex-owned settings and hook registration, `.agents/skills/` contains Codex/Gemini shared skills, and `.goat-flow/` contains shared project context for future agents.

## Request Flow

A representative agent setup flow starts with the user request, then the active agent instruction file (`CLAUDE.md` for Claude or `AGENTS.md` for Codex) routes the agent through READ, SCOPE, ACT, and VERIFY. If a goat-* skill is invoked, the agent loads the matching installed skill under `.claude/skills/` or `.agents/skills/`; setup and audit commands execute through `node_modules/@blundergoat/goat-flow/dist/cli/cli.js`; durable findings are written back to `.goat-flow/`.

The analyzer runtime is local CLI plus an optional local dashboard. `cmd/gruff-go/main.go` delegates to `internal/cli`, which dispatches `analyse`, `baseline`, `dashboard`, `help`, `list`, `list-rules`, `report`, and `summary`. `analyse` can auto-load `.gruff-go.yaml`, apply JSON baselines, filter findings by git changed lines, and render text, full JSON, summary JSON, SARIF, GitHub annotation, or HTML output. `baseline` writes a JSON baseline from current findings. `list-rules` returns registry metadata. `dashboard` binds a local `net/http` server and serves the same HTML report through an iframe; scan requests pass an explicit root/context into `analysis.Analyze` and do not mutate process cwd. The hardcoded dependency-skip fallback (vendor/node_modules/dist) is gated per-subtree against the `.gitignore` chain, so a monorepo subtree that owns its own `.gitignore` is no longer overridden by the rootless fallback. There is no application middleware, database layer, hosted service, or remote dashboard surface in this checkout.

## Auth / Trust Boundaries

No project authentication or authorization layer exists yet. The relevant trust boundary is local-agent safety: `.claude/settings.json` and `.codex/config.toml` define agent permissions, while `.claude/hooks/deny-dangerous.sh` and `.codex/hooks/deny-dangerous.sh` enforce Bash command safety checks before tool use.

Secrets should not be added to this repository. `.env.example` is allowed by Claude settings for documentation, but `.env*`, key files, credentials, and common cloud config paths are denied.

## Data Flow

Durable project memory lives in `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, `.goat-flow/decisions/`, `.goat-flow/architecture.md`, `.goat-flow/code-map.md`, and `.goat-flow/glossary.md`. Local continuity and active planning notes live under `.goat-flow/logs/sessions/` and `.goat-flow/tasks/`; scratch work belongs in `.goat-flow/scratchpad/`.

Go module identity flows from `go.mod`. The current `Makefile` discovers Go packages with `go list ./...`, then runs `go fmt`, `go vet`, and `go test` across the discovered package list.

Analyzer data flow:

1. `internal/source` expands input paths relative to the working directory, classifies Go and text/config files, and applies two layered exclusions before handing files to the parser. The primary filter is the repository's own `.gitignore` chain (see ADR-004); paths matched by it are recorded in `paths.skipped` with reason `gitignored`. Scanner discovery always skips non-application metadata directories (`.agents/`, `.claude/`, `.codex/`, `.github/`, and `.goat-flow/`) plus VCS metadata unless `--include-ignored` is set. A hardcoded fallback list still drops dependency, build-output, and local-tooling directories for repos that lack a `.gitignore`, and `paths.ignore` from `.gruff-go.yaml` layers additive project-specific excludes on top. Generated Go files are skipped after classification. The `--include-ignored` flag on `analyse`, `baseline`, `summary`, and the dashboard's `/scan` route bypasses both the gitignore filter and the hardcoded list; when set, `run.includeIgnored: true` appears in the JSON output.
2. `internal/parser` reads discovered files. Go files are parsed with the standard library `go/parser`; text/config files become source units without ASTs. Parse failures become diagnostics and the failed file is excluded from rule dispatch.
3. `internal/config` optionally loads strict gruff config from explicit `--config` or `.gruff-go.yaml`. The root `.gruff-go.yaml` reflects the project's preferred dogfood thresholds layered on top of the default-enabled rule pack. The supported shape follows the gruff-family layout: `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, `selection.rules`, `selection.excludeRules`, `selection.pillars`, `selection.excludePillars`, and `rules.<id>.enabled/threshold/thresholds/severity/options`.
4. `internal/rule` validates rule definitions, sorts rule metadata by ID, dispatches enabled per-unit rules, project-level rules, then score-neutral composite rules, and sorts findings deterministically. Per [ADR-007](decisions/ADR-007-comprehensive-default-rule-pack.md) every shipped rule is default-enabled; path-scoped documentation rules such as `docs.comment-rubric` and `docs.config-field-comment` remain no-ops until configured with `includePaths`. The current catalogue spans 11 pillars - complexity, dead-code, design, documentation, maintainability, modernisation, naming, security, sensitive-data, size, and test-quality - across 63 rules. `design.god-function` and `design.hotspot-file` are score-neutral composites derived from already-emitted findings.
5. `internal/baseline` can suppress exact rule/file/fingerprint matches from a JSON baseline and report stale entries.
6. `internal/diff` can ask local `git diff` for changed lines and filter findings to line-overlapping changes while reporting a partial-scope caveat.
7. `internal/scoring` computes severity/confidence-weighted per-pillar and composite scores after suppression/filtering. `design.*` composite findings are score-neutral annotations and do not add a second penalty on top of the underlying findings.
8. `internal/analysis` combines discovery, parse diagnostics, findings, skipped paths, missing paths, baseline/diff summaries, score, parser mode, rule metadata, and exit semantics into schema `gruff-go.analysis.v0.1`.
9. `internal/report` renders the report as compact text, full JSON, summary JSON, SARIF 2.1.0, GitHub annotations, standalone HTML, dashboard shell HTML, and optional interactive finding filters.

npm dependency state flows from `package.json` through `package-lock.json` into `node_modules/`. `node_modules/` is a dependency cache and should not be edited directly.

## Deployment / Operations

`gruff-go` is shipped as a Go binary built from source. The verified operational gates are `make check` (gofmt + go vet + go test ./...) and the dogfood scan (`go run ./cmd/gruff-go analyse .` returns grade A with zero findings on `main`). `scripts/bump-version.sh` updates every in-tree version literal and regenerates CLI goldens for a release bump. `scripts/test-performance.sh` provides smoke/matrix/sweep performance modes against synthetic corpora and a regression gate against a pinned baseline.

There is no hosted service, package-manager distribution, or automated release publishing yet. The repository does include a GitHub Actions dogfood workflow at `.github/workflows/gruff-go.yml`; the public 0.1 install path is the tagged Go module command `go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.1.0`.

`npm test` is the default npm placeholder and currently exits with `Error: no test specified`, so it is not a valid project health gate; the npm metadata only exists to vendor `@blundergoat/goat-flow` for agent tooling.
