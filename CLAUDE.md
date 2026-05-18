# gruff-go - Go code-quality scanner (v0.1.0)

`gruff-go` is a parser-only Go static analysis CLI. The Go application lives under `cmd/gruff-go` (entrypoint) and `internal/` (analysis pipeline, rule registry, scoring, report rendering, dashboard). GOAT Flow lives alongside for agent guardrails and project memory under `.goat-flow/`, `.claude/`, and `.agents/`.

## Truth Order
1. The user's explicit request for the current turn.
2. This `CLAUDE.md` instruction file.
3. `.goat-flow/architecture.md`, `.goat-flow/code-map.md`, and `.goat-flow/glossary.md`.
4. `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, and `.goat-flow/decisions/`.
5. Installed `.claude/skills/` and `.goat-flow/skill-*` references.

## Workspace Boundary
This checkout is the target project. Installed GOAT Flow package templates under `node_modules/@blundergoat/goat-flow/` are vendor reference material only; adapt them into target files instead of treating framework internals as project surfaces.

## Autonomy Tiers
**Always:** Read relevant project files before changing them. Run `make check` after touching Go source. Preserve existing user edits.

**Ask First:** Before changing `package.json`, `package-lock.json`, `.claude/hooks/`, `.goat-flow/config.yaml`, schema versions (`SchemaVersion` constants, `gruff-go.*.v0.1`), the rule registry's `Defaults()` policy, or anything that flips the dogfood `go run ./cmd/gruff-go analyse .` from grade A. State the intended edit, the files read, any matching footgun/lesson entries, and the rollback command. For breaking CLI/schema changes, also note the `CHANGELOG.md` entry that will record the break.

**Never:** Do not edit `node_modules/`, `.idea/`, `.git/`, or other agents' instruction surfaces (`AGENTS.md`, `.codex/`, `GEMINI.md`, `.gemini/`) unless the user explicitly widens scope. Do not bypass safety hooks (`--no-verify`, `--no-gpg-sign`).

## Hard Rules
- Skills in `.claude/skills/` are installed verbatim; project-specific knowledge belongs in `.goat-flow/`.
- Keep `CLAUDE.md` concise; move domain and architecture detail to cold-path docs.
- Use `rg`/`rg --files` for search. Open matching learning-loop entries before acting.
- When a goat-* skill is active, its Step 0 satisfies READ/SCOPE; resume this loop at ACT.
- Rules under `internal/rule/` ship `DefaultEnabled: true` per [ADR-007](.goat-flow/decisions/ADR-007-comprehensive-default-rule-pack.md). A new rule that shouldn't fire on default `--min-severity medium` scans should land at `low` severity.
- Version literals live in four places (`internal/cli/cli.go`, `internal/analysis/report.go`, `internal/report/machine_test.go`, `package.json`). Use `scripts/bump-version.sh <new-version>` rather than editing them by hand.

## Key Resources
- Learning loop: `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, `.goat-flow/decisions/`.
- Orientation: `.goat-flow/architecture.md`, `.goat-flow/code-map.md`, `.goat-flow/glossary.md`.
- Skill meta guidance: `.goat-flow/skill-reference/`; read only the relevant file.
- Tool playbooks: `.goat-flow/skill-playbooks/`; read before declaring tool unavailability.

## Essential Commands
- `make check` — gofmt + go vet + go test ./... (primary quality gate).
- `go run ./cmd/gruff-go analyse .` — dogfood scan; must return grade A with zero findings on `main`.
- `UPDATE_GOLDEN=1 go test ./internal/cli/...` — regenerate CLI golden snapshots after a rendered-format change. Always review the diff.
- `scripts/bump-version.sh <new-version>` — update every in-tree version literal in one shot and regenerate goldens.
- `node node_modules/@blundergoat/goat-flow/dist/cli/cli.js audit . --agent claude` — GOAT Flow setup audit.

## Execution Loop: READ → SCOPE → ACT → VERIFY

### READ
MUST read relevant files before changes. For analyser, rule, scoring, or report work, read the matching `internal/<pkg>/*.go` plus its `*_test.go` and any fixture under `internal/rule/testdata/`. For policy decisions, grep `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, and `.goat-flow/decisions/` first. Before declaring any tool or capability unavailable, read the matching playbook in `.goat-flow/skill-playbooks/` and run its "Availability Check" verbatim — project-local CLI tools at `~/.local/bin/` are valid; do not conflate "no harness/MCP tool" with "no tool".

### SCOPE
Declare mode, files allowed to change, non-goals, and max blast radius before writes. Stop and re-scope before crossing into schema versions, the rule registry's default policy, CLI flag surface, or vendored dependencies.

### ACT
MUST declare `State: [MODE] | Goal: [one line] | Exit: [condition]` before substantive work. Make the smallest project-specific change that satisfies the request. Prefer editing existing files; do not copy GOAT Flow setup templates verbatim into project docs.

### VERIFY
Run the narrowest real checks available and report literal pass/fail lines from this session. For Go edits, `make check` is the floor. For `.sh` edits, `shellcheck` when available plus `bash -n` at minimum. For rule or scoring changes, also run `go run ./cmd/gruff-go analyse .` and confirm the dogfood grade is unchanged.

## Definition of Done
- Changed files are listed in the final response.
- `make check` and (if rule/scoring/report changed) the dogfood scan are run, or an explicit blocker/gap is recorded.
- `CHANGELOG.md` carries an entry under `[Unreleased]` for any user-visible change.
- Router Table paths resolve on disk.
- New footgun, lesson, decision, or pattern entries include evidence.

## Artifact Routing
- Footguns: `.goat-flow/footguns/` after reading its `README.md`.
- Lessons: `.goat-flow/lessons/` after reading its `README.md`.
- Decisions: `.goat-flow/decisions/` after reading its `README.md`.
- Patterns: `.goat-flow/patterns/` after reading its `README.md`.
- Session continuity: `.goat-flow/logs/sessions/`.

## Router Table
| Resource | Path |
|----------|------|
| Instruction file | `CLAUDE.md` |
| Architecture | `.goat-flow/architecture.md` |
| Orientation | `.goat-flow/code-map.md`, `.goat-flow/glossary.md` |
| Learning loop | `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, `.goat-flow/decisions/` |
| Skill reference (meta) | `.goat-flow/skill-reference/` |
| Tool playbooks (CLI/MCP availability checks) | `.goat-flow/skill-playbooks/` — read BEFORE declaring a tool unavailable |
| Claude skills/config | `.claude/skills/`, `.claude/settings.json`, `.claude/hooks/` |
| Application entrypoint | `cmd/gruff-go/main.go` |
| Application packages | `internal/{cli,source,parser,rule,config,baseline,diff,finding,scoring,analysis,report,dashboard,pathfilter}/` |
| Dogfood scanner config | `.gruff-go.yaml` |
| User-facing docs | `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/{rules,configuration,output-formats,dashboard,ci-integration}.md` |
| Release tooling | `scripts/bump-version.sh`, `scripts/test-performance.sh`, `Makefile` |
| Project package metadata | `package.json`, `package-lock.json`, `go.mod` |
| Commit guidance | `.github/git-commit-instructions.md` |
| Workspace notes | `.goat-flow/logs/sessions/`, `.goat-flow/tasks/` |
