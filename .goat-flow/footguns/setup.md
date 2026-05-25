---
category: setup
last_reviewed: 2026-05-25
---

# Setup Footguns

## Footgun: `allowlists.acceptedAbbreviations` has different rule-consumer semantics than sibling gruff ports

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

hallucination-risk: high (the shared key name across gruff-go / gruff-rs / gruff-ts / gruff-py / gruff-php invites assuming shared semantics; the rules that consume the list are different in each port)

Evidence:
- `internal/rule/naming_acronym.go` (search: `AcceptedAbbreviations lists project-specific abbreviations whose lowercase form should not be flagged as a mis-cased initialism`) — the field exempts identifiers whose lowercase form matches a Go initialism the rule would otherwise want cased as `HTTP`/`URL`/`ID`. Entries are normalised via `lowerStringSet` (trim + lowercase) before matching, so case in the config is purely cosmetic for rule behaviour.
- `internal/config/validate.go` (search: `validateAbbreviations`) — rejects blank entries only (as of 2026-05-25). The earlier "must be uppercase" check was relaxed when the cross-port seed was lowercased; see the `acceptedAbbreviations validator required UPPERCASE` entry under `## Resolved Entries` for the trail.
- Sibling-port consumers (cross-checked 2026-05-25):
  - `gruff-rs/src/built_in_rules/naming_rules.rs` (search: `accepted_abbreviations.contains`) — consumed inside `naming.short-variable` as a lowercase 2-char identifier allowlist.
  - `gruff-ts/src/config.ts` (search: `acceptedAbbreviations: new Set`) — lowercased on import; the rule that reads it has not been confirmed in this checkout.
  - `gruff-php/src/Rule/Naming/AbbreviationAllowlistRule.php` (search: `'naming.abbreviation-allowlist'`) — its own rule for 2–3 char lowercase identifiers.
  - `gruff-py/src/gruffpy/rule/naming/abbreviation_rule.py` (search: `accepted_abbreviations`) — same pattern as PHP, rule id `naming.abbreviation`.

What this means in practice: the same 16-entry seed is shared across all five ports, but each port consumes it for a different rule. In gruff-go, `naming.acronym-case` only fires on identifiers that look like mis-cased acronyms (`Url` vs `URL`), so the non-acronym entries from the shared list (`age, app, key, log, max, min, now, raw`) pass validation and lowercase normalisation but are inert here — they never match anything because no naming heuristic in gruff-go cares about those words. They earn their place in the rs/php/py rules.

How to avoid:
- Do not assume removing an inert entry from gruff-go's seed is safe — the entry exists for cross-port symmetry; pruning it here would create a drift another agent will eventually try to "fix" by re-adding it.
- When investigating "why doesn't `naming.acronym-case` flag identifier X in this file", check whether X actually contains an initialism shape — the rule won't fire on regular English words even if they appear in `acceptedAbbreviations`.
- Project-specific Go initialisms (`AST`, `CLI`, `JSON`, `API`, project-domain acronyms) belong in the user's `.gruff-go.yaml` `allowlists.acceptedAbbreviations`, not in `defaultAcceptedAbbreviations` — the latter is the cross-port shared list.

## Footgun: `allowlists.secretPreviews` gates the preview field only - it does not suppress sensitive-data findings

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

hallucination-risk: medium (the field name and sibling configuration invite an incorrect mental model)

Evidence:
- `internal/rule/builtin.go` (search: `pathfilter.MatchesAny(r.PreviewAllowlist`) - the path match decides whether `preview` is attached to the finding metadata; the `findings = append(findings, finding.Finding{...})` call that follows runs unconditionally, so the finding itself is always emitted.
- `internal/config/config.go` (search: `SecretPreviews lists path patterns where the sensitive-data rules may emit the matched preview`) - the doc string is technically accurate but easy to misread.
- `internal/config/config.go` (search: `cfg.SensitiveData.PreviewAllowlist = mergeStringLists(cfg.SensitiveData.PreviewAllowlist, cfg.Allowlists.SecretPreviews)`) - the user-facing `allowlists.secretPreviews` key folds into the preview-attachment allowlist, not into any finding-suppression list.

The field sits next to `allowlists.acceptedAbbreviations`, which IS a suppression-style allowlist for `naming.acronym-case`. The visual parallel plus the name `secretPreviews` (plural noun, "the previews we accept") makes adopters reach for it to silence noisy sensitive-data findings in test fixtures or documented dummies. It does not do that. A file matching `secretPreviews` still produces a sensitive-data finding at the same severity; only the redacted `preview: AKIAIO...MPLE` metadata field appears (when matched) or is omitted (when not).

To actually suppress sensitive-data findings on a path the available levers are:
- `paths.ignore` glob, which skips discovery entirely (loses all rule coverage on that path).
- Inline `#nosec` or `//nolint:gosec` / `//nolint:all` on the matching source line - the secret-scan helpers in `internal/rule/sensitive.go` (search: `hasSecretSuppressionAnnotation`) honour both forms.

There is currently no path-scoped finding-allowlist for the sensitive-data rules. If a reviewer or adopter is reaching for `secretPreviews` to silence a known fixture, the right answer is one of the two suppression mechanisms above, not the preview-allowlist field.

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

The CLI now supports strict gruff config discovery, baselines, diff filtering, summary JSON, SARIF, GitHub annotations, an HTML report with an opt-in interactive findings UI, a local dashboard server, gitignore-respecting discovery (`--include-ignored` to bypass), and a GitHub Actions dogfood workflow. Per [ADR-007](../decisions/ADR-007-comprehensive-default-rule-pack.md) the current rule catalogue has 64 default-enabled rules. The previous "small opt-in expansion pack" framing is superseded - projects opt *out* of individual rules instead of opting in. Two documentation rules are path-scoped no-ops until configured with `includePaths`: `docs.comment-rubric` and `docs.config-field-comment`. Trend storage, hosted dashboard/service surfaces, external linter ingestion, package-manager distribution, and automated release publishing are still not implemented. Do not claim those published integration surfaces until later milestones add them.

## Resolved Entries

## Footgun: `acceptedAbbreviations` validator required UPPERCASE

**Status:** resolved | **Created:** 2026-05-25 | **Evidence:** OBSERVED

Trap: `internal/config/validate.go` originally rejected any entry where `abbreviation != strings.ToUpper(abbreviation)`, returning `acceptedAbbreviations[%d] must be uppercase`. The rule consumer (`internal/rule/naming_acronym.go` `lowerStringSet`) already trims and lowercases entries for matching, so the uppercase check was purely cosmetic but blocked cross-port harmonisation. Sibling ports (gruff-rs / gruff-ts / gruff-py / gruff-php) all accept lowercase.

Measured break (2026-05-25): seeding `defaultAcceptedAbbreviations` with the lowercase universal list to match sibling ports made `TestInitForceOverwritesExistingConfig`, `TestBootstrapPromptCreatesConfigOnYes`, and `TestBootstrapPromptDoesNotCorruptJSONOutput` fail with `acceptedAbbreviations[0] must be uppercase` — `init` emitted lowercase, `Parse` rejected what `init` had just written.

Resolved 2026-05-25 by relaxing `validateAbbreviations` to only reject blank entries (`internal/config/validate.go` search: `must not be blank`). The pre-existing config test `{name: "invalid abbreviation", ..., want: "must be uppercase"}` was rewritten as `{name: "blank abbreviation", yaml: "...''...", want: "must not be blank"}` (`internal/config/config_test.go` search: `blank abbreviation`).

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

Resolved 2026-05-13 by adding `cmd/gruff-go/` and `internal/` packages.

## Footgun: Scanner foundation exists, but no built-in rules exist yet

**Status:** resolved | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

hallucination-risk: high

Evidence:
- Historical implementation detail: the initial default registry was empty before the rule pack landed.
- Command measured 2026-05-13: `go run ./cmd/gruff-go list-rules --format json` printed `"rules": []` and exited 0.
- Command measured 2026-05-13: `go run ./cmd/gruff-go analyse --format json .` printed `"findingsCount": 0` and exited 0.

The CLI can discover files, parse Go, emit diagnostics, and render deterministic reports, but it does not yet enforce code-quality rules. Do not claim quality scanning coverage until default-enabled rules and fixtures land.

Resolved 2026-05-13 by adding five default-enabled MVP rules and scoring.
