# Git Commit Instructions

<!-- goat-flow: generated from recent git history; review and edit for project policy -->

## Observed Commit Style

- Conventional commits: 97
- Ticket-prefixed subjects: 0
- Free-form subjects: 3

Use conventional commits because at least 70% of sampled subjects matched that style.

## Format

- Use `type(scope): subject` or `type: subject`.
- Observed types: feat, chore, docs, refactor, fix.
- Keep the subject concrete: name the behavior, file family, or command that changed.
- Avoid weak subjects such as `update things`, `misc changes`, or `fix stuff`.
- Add a body when the subject names more than one axis or the motivation is not obvious.

## Evidence

- Sampled commits: 100
- Subject length p95: 120 characters
- Bodies observed: yes
- Co-authored-by trailers observed: no
- Signed-off-by trailers observed: no
- Example from history: `feat: enhance security rules to improve detection of unpinned GitHub Actions and path traversal vulnerabilities`
