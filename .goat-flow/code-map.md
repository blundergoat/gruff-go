# Code Map

## Repository Root

- `README.md` = User-facing project overview: status, install, quick start, commands, flags, output formats, exit codes, config, rule catalog summary, dashboard, CI integration links.
- `CHANGELOG.md` = Keep-a-Changelog release log; `[Unreleased]` and per-version entries.
- `CONTRIBUTING.md` = Dev loop, project layout, test gates, rule-addition / output-format-addition workflow, milestone discipline.
- `SECURITY.md` = Vulnerability reporting channel, supported versions, in-scope/out-of-scope items.
- `LICENSE` = MIT license text.
- `go.mod` = Go module identity for `github.com/blundergoat/gruff-go`; declares `go 1.25.0` and prefers toolchain `go1.25.13`.
- `.gruff-go.yaml` = Dogfood scanner config layering project-preferred thresholds and severities on top of the 83-rule registry.
- `Makefile` = Go-oriented local targets; `check` runs format, vet, and test targets over `go list ./...` packages.
- `bin/` = Local build output directory (typically holds `gruff-go` after `go build -o bin/gruff-go ./cmd/gruff-go` for perf scripts), plus one tracked file: `bin/gruff-go.sh`, the committed family launcher mirroring the sibling ports' `bin/gruff-<lang>` entrypoints, which rebuilds and execs the gitignored `bin/gruff-go` binary.
- `scripts/preflight-checks.sh` = Primary completion gate across metadata, dependency and vulnerability audits, shell checks, Go formatting/vet/tests, and dogfood; defaults to the `go.mod` toolchain unless `GOTOOLCHAIN` is explicit.
- `scripts/bump-version.sh` = Updates every in-tree version literal, regenerates CLI golden snapshots, and exposes the non-mutating source/published/security reference scanner used by the bump path.
- `scripts/bump-version_test.sh` = Disposable non-Git fixture suite for reference ownership, failure rows, stable ordering, and no-write/no-op guarantees.
- `scripts/test-performance.sh` = Smoke / matrix / sweep / regression-gate performance harness over synthetic corpora.
- `docs/` = Long-form user docs (rules, configuration, output formats, dashboard, CI integration).
- `package.json` = npm package metadata; declares `@blundergoat/goat-flow` for agent tooling. The `npm test` script is a placeholder; the project's real completion gate is `scripts/preflight-checks.sh` and `make check` is the Go edit-time floor.
- `package-lock.json` = npm lockfile for GOAT Flow and transitive dependencies.
- `CLAUDE.md` = Claude Code hot-path instructions for this target project.
- `AGENTS.md` = Codex hot-path instructions for this target project.
- `.gitignore` = Ignores dependency cache and agent local settings.
- `.goat-flow/` = Shared GOAT Flow project memory, setup docs, and local continuity files.
- `.claude/` = Claude-owned skills, settings, and hook registration. The hook scripts themselves are shared and live in `.goat-flow/hooks/`; nothing under `.claude/` is executable.
- `.agents/` = Shared skill directory read by Codex, plus `hooks.json`, which is antigravity's hook registration.
- `.codex/` = Codex-owned config and hook registration; like `.claude/`, it points at the shared scripts rather than holding copies.
- `.github/` = GitHub-facing guidance, CI workflows, and Copilot agent surfaces (instructions, skills, hooks).
- `node_modules/` = Installed dependency cache; generated/vendor content, never edit directly.
- `.idea/` = Local IDE metadata; not part of project behavior.

## Claude-Owned Surfaces

- `.claude/settings.json` = Claude permissions and hook registration.
- `.claude/skills/goat/SKILL.md` = GOAT Flow dispatcher skill.
- `.claude/skills/goat-plan/SKILL.md` = Planning and milestone skill.
- `.claude/skills/goat-debug/SKILL.md` = Debugging workflow skill.
- `.claude/skills/goat-review/SKILL.md` = Code review workflow skill.
- `.claude/skills/goat-critique/SKILL.md` = Multi-perspective critique workflow skill.
- `.claude/skills/goat-security/SKILL.md` = Security review workflow skill.
- `.claude/skills/goat-qa/SKILL.md` = QA workflow skill.

## Codex-Owned Surfaces

- `.codex/config.toml` = Codex permission profile and hooks feature flag.
- `.codex/hooks.json` = Codex hook registration: `deny-dangerous` on `PreToolUse`, `gruff-code-quality` on `PostToolUse`, and `post-turn-safety` on `Stop`.
- `.agents/skills/goat/SKILL.md` = GOAT Flow dispatcher skill.
- `.agents/skills/goat-plan/SKILL.md` = Planning and milestone skill.
- `.agents/skills/goat-debug/SKILL.md` = Debugging workflow skill.
- `.agents/skills/goat-review/SKILL.md` = Code review workflow skill.
- `.agents/skills/goat-critique/SKILL.md` = Multi-perspective critique workflow skill.
- `.agents/skills/goat-security/SKILL.md` = Security review workflow skill.
- `.agents/skills/goat-qa/SKILL.md` = QA workflow skill.

## GOAT Flow Shared Context

- `.goat-flow/config.yaml` = GOAT Flow version, skill install mode, and shared hook toggles.
- `.goat-flow/architecture.md` = Current system architecture and boundaries.
- `.goat-flow/code-map.md` = This repository map.
- `.goat-flow/glossary.md` = Project terminology for future agents.
- `.goat-flow/security-policy.md` = Installed security policy reference.
- `.goat-flow/hooks/` = Shared agent hook scripts: `deny-dangerous.sh` (Bash pre-tool safety; self-test via `--self-test`; policy under `deny-dangerous/`), `gruff-code-quality.sh` (optional post-edit gruff scan), and `post-turn-safety.sh` (optional stop-event changed-content guard; self-test via bare `--self-test`, which is the one script that rejects `--self-test=smoke`). Registration is agent-specific and follows what `goat-flow hooks list --json` reports as supported, so an unregistered hook is a recorded upstream limit rather than a gap. `deny-dangerous.sh` is registered for all four agents (claude, codex, antigravity, copilot). `gruff-code-quality.sh` is registered for claude, codex, and copilot; antigravity is unregistered because its `PostToolUse` can run a command but cannot deliver the scan feedback back to the model. `post-turn-safety.sh` is registered for claude and codex; antigravity is unregistered because no Stop payload has been captured firing, and copilot because its `agentStop` channel has no registration adapter. Derive this matrix from `goat-flow hooks list --json` before citing it rather than trusting the sentence above - it shifts whenever an upstream provider adapter gains verified delivery, and a stale copy reads as a verified limit.
- `.goat-flow/dashboard-state.json` = GOAT Flow dashboard state.
- `.goat-flow/learning-loop/footguns/` = Evidence-backed architectural traps.
- `.goat-flow/learning-loop/lessons/` = Durable behavioral lessons from incidents or git history.
- `.goat-flow/learning-loop/patterns/` = Successful repeatable approaches.
- `.goat-flow/learning-loop/decisions/` = Architecture decision records when needed.
- `.goat-flow/plans/` = Local milestone/plan tracking.
- `.goat-flow/scratchpad/` = Local scratch notes.
- `.goat-flow/logs/sessions/` = Local setup and session continuity.
- `.goat-flow/logs/quality/` = Local quality review outputs.
- `.goat-flow/logs/critiques/` = Local critique outputs.
- `.goat-flow/logs/security/` = Local security review outputs.
- `.goat-flow/skill-docs/` = Meta guidance for GOAT Flow skill behavior.
- `.goat-flow/skill-docs/playbooks/` = CLI/MCP availability and workflow playbooks: `browser-use.md`, `changelog.md`, `code-comments.md`, `gruff-code-quality.md`, `hook-policy-testing.md`, `observability.md`, `page-capture.md`, `release-notes.md`, `skill-playbook-authoring-sync.md`, and `writing-style.md`.
- `.goat-flow/skill-docs/skill-quality-testing/` = Skill-authoring methodology index plus `tdd-iteration.md`, `adversarial-framing.md`, and `deployment.md` topical references.

## Copilot-Owned Surfaces

- `.github/copilot-instructions.md` = Copilot hot-path instructions for this target project.
- `.github/skills/` = Copilot GOAT Flow skills (goat dispatcher + goat-plan/debug/review/critique/security/qa).
- `.github/hooks/hooks.json` = Copilot hook registration for GOAT Flow.
- `.github/git-commit-instructions.md` = GitHub-visible commit guidance (canonical copy: `docs/coding-standards/git-commit-message.md`).

## Go Application Surface

- `cmd/gruff-go/main.go` = Thin executable entrypoint that exits with the CLI package's Main function.
- `internal/cli/` = CLI command parsing and exit-code mapping for `analyse`, `baseline`, `check-ignore`, `completion`, `dashboard`, `help`, `hook`, `init`, `list`, `list-rules`, `report`, and `summary`; `analyze` aliases `analyse`. Holds the `toolVersion` constant and the golden test fixtures under `internal/cli/testdata/golden/`.
- `internal/source/` = Source discovery, text/config classification, generated-file detection, default ignored-path handling, gitignore-respecting filter (ADR-004/ADR-005), and configured ignore patterns.
- `internal/parser/` = Parser-only unit construction using the standard library Go parser plus parse diagnostics.
- `internal/config/` = Strict `.gruff-go.yaml` discovery/parsing, including rule selection, thresholds, severities, path ignores, accepted abbreviations, and sensitive-data preview allowlists.
- `internal/rule/` = Rule metadata validation, deterministic registry, configured thresholds/enablement, per-unit dispatch, project-level dispatch, composite-finding dispatch, finding ordering, and the 83-rule catalogue (70 default-enabled, 13 opt-in).
- `internal/finding/` = Severity, confidence, pillar, location, finding payload, and stable fingerprint logic.
- `internal/baseline/` = JSON baseline serialization plus shared one-to-one classification: exact rule/file/fingerprint pairs first, then remaining contract-stable identities, with legacy exact-only fallback and resolved-entry reporting for analyse and hook consumers.
- `internal/diff/` = Git diff changed-line parsing and finding filtering.
- `internal/pathfilter/` = Shared relative path glob validation and matching.
- `internal/analysis/` = End-to-end analysis runner, report schema, summary counts, baseline/diff summaries, diagnostics, rule metadata, exit semantics, and the `Tool.Version` literal that flows into JSON/SARIF reports.
- `internal/dashboard/` = Local-only dashboard HTTP server, request handling, scan option mapping, and shutdown behavior.
- `internal/report/` = Text, full JSON, summary JSON, SARIF, GitHub annotation, Markdown, standalone HTML, dashboard shell, interactive finding filters, and rule-list rendering.
- `internal/scoring/` = Severity/confidence-weighted per-pillar and composite scoring with score-neutral `design.*` annotations and per-pillar coverage labelling.
- `.github/workflows/gruff-go.yml` = GitHub Actions gate that runs `scripts/preflight-checks.sh` (gofmt, go vet, go test, govulncheck, shellcheck, and the `go run ./cmd/gruff-go summary .` dogfood self-scan) on PRs and pushes to `main`.
- Release distribution is the tagged Go module plus GoReleaser GitHub Release archives: `.goreleaser.yaml` and `.github/workflows/release.yml` build and publish per-OS/arch binaries on a `v*` tag push, and `scripts/publish-go-pkg.sh` drives the tag push plus proxy/install verification. No deployment config, database assets, trend storage, external linter ingestion, hosted dashboard, or package-manager (brew/apt/scoop) distribution exists yet. The public install path is the tagged Go module command `go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.4.0`.
