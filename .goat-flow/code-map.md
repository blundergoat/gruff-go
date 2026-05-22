# Code Map

## Repository Root

- `README.md` = User-facing project overview: status, install, quick start, commands, flags, output formats, exit codes, config, rule catalog summary, dashboard, CI integration links.
- `CHANGELOG.md` = Keep-a-Changelog release log; `[Unreleased]` and per-version entries.
- `CONTRIBUTING.md` = Dev loop, project layout, test gates, rule-addition / output-format-addition workflow, milestone discipline.
- `SECURITY.md` = Vulnerability reporting channel, supported versions, in-scope/out-of-scope items.
- `LICENSE` = MIT license text.
- `go.mod` = Go module identity for `github.com/blundergoat/gruff-go`; declares `go 1.25.0`.
- `.gruff-go.yaml` = Dogfood scanner config layering project-preferred thresholds and severities on top of the 41-rule registry.
- `Makefile` = Go-oriented local targets; `check` runs format, vet, and test targets over `go list ./...` packages.
- `bin/` = Local build output directory (typically holds `gruff-go` after `go build -o bin/gruff-go ./cmd/gruff-go` for perf scripts).
- `scripts/bump-version.sh` = Updates every in-tree version literal and regenerates CLI golden snapshots; sanity-sweeps for stale references.
- `scripts/test-performance.sh` = Smoke / matrix / sweep / regression-gate performance harness over synthetic corpora.
- `docs/` = Long-form user docs (rules, configuration, output formats, dashboard, CI integration).
- `package.json` = npm package metadata; declares `@blundergoat/goat-flow` for agent tooling. The `npm test` script is a placeholder; the project's real gates are `make check` and the dogfood scan.
- `package-lock.json` = npm lockfile for GOAT Flow and transitive dependencies.
- `CLAUDE.md` = Claude Code hot-path instructions for this target project.
- `AGENTS.md` = Codex hot-path instructions for this target project.
- `.gitignore` = Ignores dependency cache and agent local settings.
- `.goat-flow/` = Shared GOAT Flow project memory, setup docs, and local continuity files.
- `.claude/` = Claude-owned skills, settings, and safety hooks.
- `.agents/` = Shared skill directory used by Codex and Gemini GOAT Flow installs.
- `.codex/` = Codex-owned config, hook registration, and safety hooks.
- `.github/` = GitHub-facing repository guidance.
- `node_modules/` = Installed dependency cache; generated/vendor content, never edit directly.
- `.idea/` = Local IDE metadata; not part of project behavior.

## Claude-Owned Surfaces

- `.claude/settings.json` = Claude permissions and hook registration.
- `.claude/hooks/deny-dangerous.sh` = Bash pre-tool safety hook.
- `.claude/hooks/deny-dangerous.self-test.sh` = Self-test script for the safety hook.
- `.claude/skills/goat/SKILL.md` = GOAT Flow dispatcher skill.
- `.claude/skills/goat-plan/SKILL.md` = Planning and milestone skill.
- `.claude/skills/goat-debug/SKILL.md` = Debugging workflow skill.
- `.claude/skills/goat-review/SKILL.md` = Code review workflow skill.
- `.claude/skills/goat-critique/SKILL.md` = Multi-perspective critique workflow skill.
- `.claude/skills/goat-security/SKILL.md` = Security review workflow skill.
- `.claude/skills/goat-qa/SKILL.md` = QA workflow skill.

## Codex-Owned Surfaces

- `.codex/config.toml` = Codex permission profile and hooks feature flag.
- `.codex/hooks.json` = Codex hook registration for GOAT Flow.
- `.codex/hooks/deny-dangerous.sh` = Bash pre-tool safety hook.
- `.codex/hooks/deny-dangerous.self-test.sh` = Self-test script for the safety hook.
- `.agents/skills/goat/SKILL.md` = GOAT Flow dispatcher skill.
- `.agents/skills/goat-plan/SKILL.md` = Planning and milestone skill.
- `.agents/skills/goat-debug/SKILL.md` = Debugging workflow skill.
- `.agents/skills/goat-review/SKILL.md` = Code review workflow skill.
- `.agents/skills/goat-critique/SKILL.md` = Multi-perspective critique workflow skill.
- `.agents/skills/goat-security/SKILL.md` = Security review workflow skill.
- `.agents/skills/goat-qa/SKILL.md` = QA workflow skill.

## GOAT Flow Shared Context

- `.goat-flow/config.yaml` = GOAT Flow version, agent list, and skill install mode.
- `.goat-flow/architecture.md` = Current system architecture and boundaries.
- `.goat-flow/code-map.md` = This repository map.
- `.goat-flow/glossary.md` = Project terminology for future agents.
- `.goat-flow/security-policy.md` = Installed security policy reference.
- `.goat-flow/dashboard-state.json` = GOAT Flow dashboard state.
- `.goat-flow/footguns/` = Evidence-backed architectural traps.
- `.goat-flow/lessons/` = Durable behavioral lessons from incidents or git history.
- `.goat-flow/patterns/` = Successful repeatable approaches.
- `.goat-flow/decisions/` = Architecture decision records when needed.
- `.goat-flow/tasks/` = Local milestone/task tracking.
- `.goat-flow/scratchpad/` = Local scratch notes.
- `.goat-flow/logs/sessions/` = Local setup and session continuity.
- `.goat-flow/logs/quality/` = Local quality review outputs.
- `.goat-flow/logs/critiques/` = Local critique outputs.
- `.goat-flow/logs/security/` = Local security review outputs.
- `.goat-flow/skill-reference/` = Meta guidance for GOAT Flow skill behavior.
- `.goat-flow/skill-playbooks/` = CLI/MCP availability playbooks.

## GitHub Guidance

- `.github/git-commit-instructions.md` = Project-specific commit guidance for agents.

## Go Application Surface

- `cmd/gruff-go/main.go` = Thin executable entrypoint that exits with the CLI package's Main function.
- `internal/cli/` = CLI command parsing and exit-code mapping for `analyse`, `baseline`, `dashboard`, `help`, `list`, `list-rules`, `report`, and `summary`. Holds the `toolVersion` constant and the golden test fixtures under `internal/cli/testdata/golden/`.
- `internal/source/` = Source discovery, text/config classification, generated-file detection, default ignored-path handling, gitignore-respecting filter (ADR-004/ADR-005), and configured ignore patterns.
- `internal/parser/` = Parser-only unit construction using the standard library Go parser plus parse diagnostics.
- `internal/config/` = Strict `.gruff-go.yaml` discovery/parsing, including rule selection, thresholds, severities, path ignores, accepted abbreviations, and sensitive-data preview allowlists.
- `internal/rule/` = Rule metadata validation, deterministic registry, configured thresholds/enablement, per-unit dispatch, project-level dispatch, composite-finding dispatch, finding ordering, and the 41-rule catalogue (40 default-enabled; ADR-007).
- `internal/finding/` = Severity, confidence, pillar, location, finding payload, and stable fingerprint logic.
- `internal/baseline/` = JSON baseline serialization plus exact rule/file/fingerprint suppression and stale-entry reporting.
- `internal/diff/` = Git diff changed-line parsing and finding filtering.
- `internal/pathfilter/` = Shared relative path glob validation and matching.
- `internal/analysis/` = End-to-end analysis runner, report schema, summary counts, baseline/diff summaries, diagnostics, rule metadata, exit semantics, and the `Tool.Version` literal that flows into JSON/SARIF reports.
- `internal/dashboard/` = Local-only dashboard HTTP server, request handling, scan option mapping, and shutdown behavior.
- `internal/report/` = Text, full JSON, summary JSON, SARIF, GitHub annotation, standalone HTML, dashboard shell, interactive finding filters, and rule-list rendering.
- `internal/scoring/` = Severity/confidence-weighted per-pillar and composite scoring with score-neutral `design.*` annotations and per-pillar coverage labelling.
- `.github/workflows/gruff-go.yml` = GitHub Actions dogfood gate that builds `bin/gruff-go` and runs `./bin/gruff-go analyse .` on PRs and pushes to `main`.
- No deployment config, database assets, trend storage, external linter ingestion, hosted dashboard, or package publication surface exists yet — `go install ...@v0.1.0` becomes the install path once the tag is pushed.
