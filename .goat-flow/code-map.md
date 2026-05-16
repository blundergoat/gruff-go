# Code Map

## Repository Root

- `README.md` = Minimal project title only.
- `go.mod` = Go module identity for `github.com/blundergoat/gruff-go`.
- `.gruff.yaml` = Standalone dogfood scanner config for this repository; mirrors current default-enabled rules and keeps expansion rules disabled.
- `Makefile` = Go-oriented local targets; `check` runs format, vet, and test targets over `go list ./...` packages.
- `package.json` = npm package metadata; declares `@blundergoat/goat-flow` and the placeholder failing `npm test` script.
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
- `internal/cli/` = CLI command parsing and exit-code mapping for `analyse`, `baseline`, `list-rules`, `summary`, `report`, and `dashboard`.
- `internal/source/` = Source discovery, text/config classification, generated-file detection, default ignored-path handling, and configured ignore patterns.
- `internal/parser/` = Parser-only unit construction using the standard library Go parser plus parse diagnostics.
- `internal/config/` = Strict gruff config discovery/parsing for `.gruff.yaml`, `.gruff.yml`, and `.gruff.json`, including rule selection, thresholds, severities, path ignores, accepted abbreviations, and sensitive-data preview allowlists.
- `internal/rule/` = Rule metadata validation, deterministic registry, configured thresholds/enablement, per-unit dispatch, project-level dispatch, composite-finding dispatch, finding ordering, the built-in default rule pack, and default-disabled opt-in expansion rules.
- `internal/finding/` = Severity, confidence, pillar, location, finding payload, and stable fingerprint logic.
- `internal/baseline/` = JSON baseline serialization plus exact rule/file/fingerprint suppression and stale-entry reporting.
- `internal/diff/` = Git diff changed-line parsing and finding filtering.
- `internal/pathfilter/` = Shared relative path glob validation and matching.
- `internal/analysis/` = End-to-end analysis runner, report schema, summary counts, baseline/diff summaries, diagnostics, rule metadata, and exit semantics.
- `internal/dashboard/` = Local-only dashboard HTTP server, request handling, scan option mapping, and shutdown behavior.
- `internal/report/` = Text, full JSON, summary JSON, SARIF, GitHub annotation, standalone HTML, dashboard shell, interactive finding filters, and rule-list rendering.
- `internal/scoring/` = Severity/confidence-weighted per-pillar and composite scoring with score-neutral `design.*` annotations.
- No CI config, deployment config, database assets, trend storage, external linter ingestion, hosted dashboard, or package publication surface exists yet.
