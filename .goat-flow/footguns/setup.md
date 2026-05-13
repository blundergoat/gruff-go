---
category: setup
last_reviewed: 2026-05-13
---

# Setup Footguns

## Footgun: `npm test` exists but is a failing placeholder

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

hallucination-risk: high

Evidence:
- `package.json` (search: `"test": "echo \"Error: no test specified\" && exit 1"`)
- Command measured 2026-05-13: `npm test` printed `Error: no test specified` and exited 1.

The package exposes a `test` script, so script detection can look successful. Treating it as a valid health gate will create false failures or instruction files that claim this repo has a working test command.

## Footgun: Repository name implies Go, but no Go source exists

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

hallucination-risk: high

Evidence:
- `README.md` (search: `# gruff-go`)
- `package.json` (search: `"name": "gruff-go"`)
- Command measured 2026-05-13: `rg --files -g '*.go' -g 'go.mod'` returned no matches.

The repo name can make agents assume a Go module, `go test`, or a `cmd/`/`internal/` layout. Current files show only a bootstrap README plus npm metadata for GOAT Flow, so Go-specific commands and architecture claims are unsupported until source files are added.
