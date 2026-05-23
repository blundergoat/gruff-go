---
category: setup
last_reviewed: 2026-05-23
---

# Setup Footguns

## Footgun: `npm test` exists but is a failing placeholder

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

hallucination-risk: high

Evidence:
- `package.json` (search: `"test": "echo \"Error: no test specified\" && exit 1"`)
- Command measured 2026-05-13: `npm test` printed `Error: no test specified` and exited 1.

The package exposes a `test` script, so script detection can look successful. Treating it as a valid health gate will create false failures or instruction files that claim this repo has a working test command.

## Footgun: Scanner CLI exists, but published operational integration is still narrow

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

hallucination-risk: high

Evidence:
- `internal/cli/cli.go` (search: `output format: text, json, summary-json, sarif, github, or html`)
- `internal/config/config.go` (search: `var defaultConfigFiles = []string{".gruff-go.yaml"}`)
- Command measured 2026-05-13: `go run ./cmd/gruff-go list-rules --format json` listed the catalogue and exited 0. [ADR-007](../decisions/ADR-007-comprehensive-default-rule-pack.md) (2026-05-18) subsequently flipped every shipped rule to `defaultEnabled: true` except the deliberate `docs.config-field-comment` carve-out called out in that ADR.

The CLI now supports strict gruff config discovery, baselines, diff filtering, summary JSON, SARIF, GitHub annotations, an HTML report with an opt-in interactive findings UI, a local dashboard server, gitignore-respecting discovery (`--include-ignored` to bypass), and a GitHub Actions dogfood workflow. Per [ADR-007](../decisions/ADR-007-comprehensive-default-rule-pack.md) the current rule catalogue has 41 rules, with 40 default-enabled and one deliberate carve-out: `docs.config-field-comment` stays `defaultEnabled: false` because its empty-default scoping would otherwise fire on every exported struct field. The previous "small opt-in expansion pack" framing is superseded - projects opt *out* of individual rules instead of opting in, and the only rule they need to opt *in* to is `docs.config-field-comment`. Trend storage, hosted dashboard/service surfaces, external linter ingestion, package-manager distribution, and automated release publishing are still not implemented. Do not claim those published integration surfaces until later milestones add them.

## Resolved Entries

## Footgun: Go metadata exists, but no Go packages exist

**Status:** resolved | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

hallucination-risk: high

Evidence:
- `README.md` (search: `# gruff-go`)
- `package.json` (search: `"name": "gruff-go"`)
- `go.mod` (search: `module github.com/blundergoat/gruff-go`)
- `Makefile` (search: `GO_PACKAGES := $(shell go list ./... 2>/dev/null)`)
- Command measured 2026-05-13: `rg --files -g '*.go'` returned no matches.
- Command measured 2026-05-13: `go list ./...` printed `go: warning: "./..." matched no packages` and exited 0.
- Command measured 2026-05-13: `make check` printed `no Go packages` three times and exited 0.

The repo name plus `go.mod` can make agents assume a working Go application, test suite, or conventional runtime layout. Current files prove only module metadata and placeholder Makefile behavior, so Go-specific behavior claims are unsupported until source files are added.

Resolved 2026-05-13 by M02 adding `cmd/gruff-go/` and `internal/` packages.

## Footgun: Scanner foundation exists, but no built-in rules exist yet

**Status:** resolved | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

hallucination-risk: high

Evidence:
- Historical implementation detail: the M02 default registry was empty before M03.
- Command measured 2026-05-13: `go run ./cmd/gruff-go list-rules --format json` printed `"rules": []` and exited 0.
- Command measured 2026-05-13: `go run ./cmd/gruff-go analyse --format json .` printed `"findingsCount": 0` and exited 0.

The CLI can discover files, parse Go, emit diagnostics, and render deterministic reports, but it does not yet enforce code-quality rules. Do not claim quality scanning coverage until M03 adds default-enabled rules and fixtures.

Resolved 2026-05-13 by M03 adding five default-enabled MVP rules and scoring.
