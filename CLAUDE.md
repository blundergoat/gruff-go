# gruff-go - GOAT Flow 1.6.4

gruff-go is currently a bootstrap GOAT Flow/Claude workspace with npm metadata and no application source. Core invariant: verify files on disk before inferring a Go app, Node app, runtime, or test strategy from the repo name.

## Truth Order
1. The user's explicit request for the current turn.
2. This `CLAUDE.md` instruction file.
3. `.goat-flow/architecture.md`, `.goat-flow/code-map.md`, and `.goat-flow/glossary.md`.
4. `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, and `.goat-flow/decisions/`.
5. Installed `.claude/skills/` and `.goat-flow/skill-*` references.

## Workspace Boundary
This checkout is the target project. Installed GOAT Flow package templates are vendor reference material only; adapt them into target files instead of treating framework internals as project surfaces.

## Autonomy Tiers
**Always:** Read relevant project files before changing them. Update only Claude-owned surfaces (`CLAUDE.md`, `.claude/`) and shared `.goat-flow/` docs during setup work. Preserve existing user edits.

**Ask First:** Before changing `package.json`, `package-lock.json`, `README.md`, `.claude/hooks/`, or `.goat-flow/config.yaml`, state the intended edit, files read, checked footgun/lesson entries, and rollback command. Ask before adding application source because no runtime layout exists yet.

**Never:** Do not edit `node_modules/`, `.idea/`, `.git/`, or other agents' instruction/config surfaces unless the user explicitly widens scope. Do not claim Go or JavaScript application behavior until source files exist.

## Hard Rules
- Skills in `.claude/skills/` are installed verbatim; project-specific knowledge belongs in `.goat-flow/`.
- Keep `CLAUDE.md` concise; move domain and architecture detail to cold-path docs.
- Use `rg`/`rg --files` for search. Open matching learning-loop entries before acting.
- When a goat-* skill is active, its Step 0 satisfies READ/SCOPE; resume this loop at ACT.

## Key Resources
- Learning loop: `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, `.goat-flow/decisions/`.
- Orientation: `.goat-flow/architecture.md`, `.goat-flow/code-map.md`, `.goat-flow/glossary.md`.
- Skill meta guidance: `.goat-flow/skill-reference/`; read only the relevant file.
- Tool playbooks: `.goat-flow/skill-playbooks/`; read before declaring tool unavailability.

## Essential Commands
- `node node_modules/@blundergoat/goat-flow/dist/cli/cli.js audit . --agent claude`
- `node node_modules/@blundergoat/goat-flow/dist/cli/cli.js audit . --agent claude --harness`
- `npm test` is currently the default placeholder and exits 1; do not list it as a passing gate until replaced.

## Execution Loop: READ → SCOPE → ACT → VERIFY

### READ
MUST read relevant files before changes. For setup or architecture work, grep `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, and `.goat-flow/decisions/` before editing. Before declaring any tool or capability unavailable, read the matching playbook in `.goat-flow/skill-playbooks/` (e.g. `browser-use.md`, `page-capture.md`) and run that doc's "Availability Check" section verbatim - project-local CLI tools at `~/.local/bin/` are valid; do not conflate "no harness/MCP tool" with "no tool".

### SCOPE
Declare mode, files allowed to change, non-goals, and max blast radius before writes. Treat this repo as Infrastructure until real application source exists. Stop and re-scope before crossing into package metadata, hooks, or vendored dependencies.

### ACT
MUST declare `State: [MODE] | Goal: [one line] | Exit: [condition]` before substantive work. Make the smallest project-specific change that satisfies the request. Do not copy GOAT Flow setup templates verbatim into project docs.

### VERIFY
Run the narrowest real checks available and report literal pass/fail lines from this session. For `.sh` edits, run `shellcheck` when available and `bash -n` at minimum. For setup changes, run both audit commands in Essential Commands.

## Definition of Done
- Changed files are listed in the final response.
- Verification commands are run, or an explicit blocker/gap is recorded.
- No stale framework-template paths appear in installed project skills or target docs.
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
| Tool playbooks (CLI/MCP availability checks: browser-use, page-capture, skill-quality-testing) | `.goat-flow/skill-playbooks/` - read BEFORE declaring a tool unavailable |
| Claude skills/config | `.claude/skills/`, `.claude/settings.json`, `.claude/hooks/` |
| Project package metadata | `package.json`, `package-lock.json` |
| Project overview | `README.md` |
| Commit guidance | `.github/git-commit-instructions.md` |
| Workspace notes | `.goat-flow/logs/sessions/`, `.goat-flow/tasks/` |
