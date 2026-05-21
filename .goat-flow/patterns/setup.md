---
category: setup
last_reviewed: 2026-05-21
---

# Setup Patterns

## Pattern: Re-derive numeric claims from the live registry before writing architecture

**Created:** 2026-05-21

**Evidence:** OBSERVED

**Context:** `.goat-flow/architecture.md` and `.goat-flow/code-map.md` carried a "29-rule default-enabled registry" claim across four lines while `go run ./cmd/gruff-go list-rules --format json` reported 30 rules. The drift went unnoticed because the count is asserted in prose rather than derived.

**Approach:** When an orientation doc states a count (rules, pillars, packages, version literals), re-derive it from the canonical source in the same session before writing or editing the claim. Authoritative sources: `go run ./cmd/gruff-go list-rules --format json` for rules and pillars; `go list ./...` for Go packages; `grep -c '"id"'` is unreliable for nested JSON — prefer `python3 -c "import json; …"` or `jq`. Cite the command used in the commit or PR so the next reader can re-run it.
