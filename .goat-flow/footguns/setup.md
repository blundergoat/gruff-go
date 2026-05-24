---
category: setup
last_reviewed: 2026-05-24
---

# Setup Footguns

## Footgun: `gruff-go init --reset` wipes hand-tuned `.gruff-go.yaml` policy

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

hallucination-risk: low (this is a behaviour to remember, not a fact to fabricate)

Evidence:
- `internal/cli/init.go` (search: `flags.Bool("reset"`) — `--reset` is the explicit "discard existing tuning" flag, gated behind `--force`.
- `internal/config/render.go` (search: `// preservedIgnorePaths returns`) — the renderer reads `RenderOptions.Existing` and splices preserved scaffolds and per-rule overrides into the output when present.
- `internal/cli/init_test.go` (search: `TestInitForcePreservesExistingTuning`) and (search: `TestInitForceResetDiscardsExistingTuning`) lock in the merge-vs-reset contract.

Current behaviour:
- `gruff-go init` (no flags) — refuses to overwrite an existing `.gruff-go.yaml`. Safe.
- `gruff-go init --force` — parses the existing file and **preserves** `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, and every per-rule `enabled`/`severity`/`threshold`/`thresholds`/`options` override. Adds blocks for rules new to the registry at defaults; drops blocks for rules no longer in the registry. Prints `preserved existing tuning: ...` to stderr listing what carried over. Safe regenerate.
- `gruff-go init --force --reset` — performs the **legacy destructive overwrite**: wipes paths.ignore, allowlists, and per-rule overrides; writes fresh registry defaults. Use only when you genuinely want a clean slate.

Historical wipe (resolved by the merge-preserve refactor):
- Commit `8282478` ("feat: update rule pillars and enable config-field-comment by default") regenerated `.gruff-go.yaml` from the template and wiped the 8-entry `paths.ignore`, `allowlists.acceptedAbbreviations` (`ID, HTTP, JSON, CLI, AST`), the `docs.comment-rubric` strict `options:` block, `docs.exported-symbol-comment.options.ignoreInternalPackages: true`, `naming.identifier-quality.options.placeholderNames` list, and tightened severities/thresholds on six rules. The dogfood scan flipped from grade A to grade F with 25 sensitive-data findings in rule-test fixtures.

How to avoid the residual `--reset` trap:
- Never combine `--force --reset` on a dogfood checkout without first taking a backup or relying on git to revert.
- Before staging any commit that touches `.gruff-go.yaml`, run `git diff --stat .gruff-go.yaml`. A normal tuning edit changes a handful of lines; a `--reset` regenerate touches ~200.
- If a `--reset` regenerate already happened, recover with `git show <commit>^:.gruff-go.yaml` and merge the lost tuning onto the current schema layout, or use `gruff-go init --force` from the old file to merge automatically.

The original destructive default (`init --force` clobbered tuning) is fixed in code; the only remaining way to lose tuning is `--reset`, which is explicit and named. Review still flags large `.gruff-go.yaml` diffs.

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
- Command measured 2026-05-13: `go run ./cmd/gruff-go list-rules --format json` listed the catalogue and exited 0. [ADR-007](../decisions/ADR-007-comprehensive-default-rule-pack.md) (2026-05-18) subsequently flipped every shipped rule to `defaultEnabled: true`; `docs.config-field-comment` is default-enabled but remains path-scoped and no-op until `includePaths` is configured.

The CLI now supports strict gruff config discovery, baselines, diff filtering, summary JSON, SARIF, GitHub annotations, an HTML report with an opt-in interactive findings UI, a local dashboard server, gitignore-respecting discovery (`--include-ignored` to bypass), and a GitHub Actions dogfood workflow. Per [ADR-007](../decisions/ADR-007-comprehensive-default-rule-pack.md) the current rule catalogue has 41 default-enabled rules. The previous "small opt-in expansion pack" framing is superseded - projects opt *out* of individual rules instead of opting in. Two documentation rules are path-scoped no-ops until configured with `includePaths`: `docs.comment-rubric` and `docs.config-field-comment`. Trend storage, hosted dashboard/service surfaces, external linter ingestion, package-manager distribution, and automated release publishing are still not implemented. Do not claim those published integration surfaces until later milestones add them.

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
