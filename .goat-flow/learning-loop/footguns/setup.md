---
category: setup
last_reviewed: 2026-08-22
---

# Setup Footguns

## Footgun: `allowlists.acceptedAbbreviations` has different rule-consumer semantics than sibling gruff ports

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

hallucination-risk: high (the shared key name across gruff-go / gruff-rs / gruff-ts / gruff-py / gruff-php invites assuming shared semantics; the rules that consume the list are different in each port)

Evidence:
- `internal/rule/naming_acronym.go` (search: `AcceptedAbbreviations lists project-specific abbreviations whose lowercase form should not be flagged as a mis-cased initialism`) — the field exempts identifiers whose lowercase form matches a Go initialism the rule would otherwise want cased as `HTTP`/`URL`/`ID`. Entries are normalised via `lowerStringSet` (trim + lowercase) before matching, so case in the config is purely cosmetic for rule behaviour.
- `internal/config/validate.go` (search: `validateAbbreviations`) — rejects blank entries only (as of 2026-05-25). The earlier "must be uppercase" check was relaxed when the cross-port seed was lowercased; see the `acceptedAbbreviations validator required UPPERCASE` entry in the resolved section below for the trail.
- Sibling-port consumers (cross-checked 2026-05-25; these paths live in the sibling repos, not this checkout, so they are recorded as prose rather than verifiable refs):
  - Rust (gruff-rs): consumed inside the `naming.short-variable` rule as a lowercase 2-char identifier allowlist (anchor `accepted_abbreviations.contains` in its built-in naming rules).
  - TypeScript (gruff-ts): lowercased on import in its config loader (the `acceptedAbbreviations` set); the consuming rule was not confirmed in that checkout.
  - PHP (gruff-php): its own `naming.abbreviation-allowlist` rule for 2-3 char lowercase identifiers.
  - Python (gruff-py): same pattern as PHP, rule id `naming.abbreviation` (anchor `accepted_abbreviations`).

What this means in practice: the same 16-entry seed is shared across all five ports, but each port consumes it for a different rule. In gruff-go, `naming.acronym-case` only fires on identifiers that look like mis-cased acronyms (`Url` vs `URL`), so the non-acronym entries from the shared list (`age, app, key, log, max, min, now, raw`) pass validation and lowercase normalisation but are inert here — they never match anything because no naming heuristic in gruff-go cares about those words. They earn their place in the rs/php/py rules.

How to avoid:
- Do not assume removing an inert entry from gruff-go's seed is safe — the entry exists for cross-port symmetry; pruning it here would create a drift another agent will eventually try to "fix" by re-adding it.
- When investigating "why doesn't `naming.acronym-case` flag identifier X in this file", check whether X actually contains an initialism shape — the rule won't fire on regular English words even if they appear in `acceptedAbbreviations`.
- Project-specific Go initialisms (`AST`, `CLI`, `JSON`, `API`, project-domain acronyms) belong in the user's `.gruff-go.yaml` `allowlists.acceptedAbbreviations`, not in `defaultAcceptedAbbreviations` — the latter is the cross-port shared list.

## Footgun: `allowlists.secretPreviews` gates the preview field only - it does not suppress sensitive-data findings

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

hallucination-risk: medium (the field name and sibling configuration invite an incorrect mental model)

Evidence:
- `internal/rule/sensitive_preview.go` (search: `func (p sensitivePreviewPolicy) format`) - every detector calls one policy. Empty/nonmatching lists return `[redacted]`; matching paths may receive only a fixed category marker or an already-public connection scheme.
- `internal/rule/defaults.go` (search: `previews := newSensitivePreviewPolicy`) - the same policy is supplied to all 16 sensitive-data rules, including entropy, PII, PHI, GCP primary/secondary, private-key, JWT, and connection-string paths.
- `internal/config/config.go` (search: `cfg.SensitiveData.PreviewAllowlist = mergeStringLists(cfg.SensitiveData.PreviewAllowlist, cfg.Allowlists.SecretPreviews)`) - the user-facing `allowlists.secretPreviews` key still folds into preview-detail authorization, not into any finding-suppression list.

The field sits next to `allowlists.acceptedAbbreviations`, which IS a suppression-style allowlist for `naming.acronym-case`. The visual parallel plus the name `secretPreviews` (plural noun, "the previews we accept") makes adopters reach for it to silence noisy sensitive-data findings in test fixtures or documented dummies. It does not do that. A matching file still produces the same finding and may show only a marker such as `[redacted:aws-access-key]`; empty/nonmatching policy shows `[redacted]`. No state reveals payload characters.

To actually suppress sensitive-data findings the ratified lever is the top-level `sensitiveExclusions` section (`internal/config/validate.go`, search: `func validateSensitiveExclusions`), which names one rule, one project-relative path, and a required reason, and publishes a counted audit row. The older path-level levers still exist and still lose coverage:
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
- `package.json` (search: `no test specified`)
- Command measured 2026-05-13: `npm test` printed `Error: no test specified` and exited 1.

The package exposes a `test` script, so script detection can look successful. Treating it as a valid health gate will create false failures or instruction files that claim this repo has a working test command.

## Footgun: Scanner CLI exists, but published operational integration is still narrow

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

hallucination-risk: high

Evidence:
- `internal/cli/cli.go` (search: `case "summary-json":`)
- `internal/config/config.go` (search: `var defaultConfigFiles = []string{".gruff-go.yaml"}`)
- Command measured 2026-05-13: `go run ./cmd/gruff-go list-rules --format json` listed the catalogue and exited 0. [ADR-007](../decisions/ADR-007-comprehensive-default-rule-pack.md) (2026-05-18) subsequently flipped every shipped rule to `defaultEnabled: true`; `docs.config-field-comment` is default-enabled but remains path-scoped and no-op until `includePaths` is configured.

The CLI now supports strict gruff config discovery, baselines, diff filtering, summary JSON, SARIF, GitHub annotations, an HTML report with an opt-in interactive findings UI, a local dashboard server, gitignore-respecting discovery (`--include-ignored` to bypass), and a GitHub Actions dogfood workflow. Per [ADR-007](../decisions/ADR-007-comprehensive-default-rule-pack.md) the rule pack moved to an opt-out posture, and [ADR-016](../decisions/ADR-016-default-pack-retune-to-verifiability-mission.md) then retuned it: the current catalogue has 83 rules - 70 default-enabled and 13 opt-in. The previous "small opt-in expansion pack" framing is superseded - the default posture is opt-out, with the 13 opt-in rules (convention-only naming/modernisation, parser-only dead-code, heuristic sensitive-data, and the redundant-test candidate) enabled by exception. Two documentation rules are path-scoped no-ops until configured with `includePaths`: `docs.comment-rubric` and `docs.config-field-comment`. Trend storage, hosted dashboard/service surfaces, external linter ingestion, and package-manager distribution are still not implemented. Do not claim those integration surfaces until later milestones add them.

## Footgun: release docs lag the version literals; committed docs must not link into the gitignored scratchpad

**Status:** active | **Created:** 2026-06-14 | **Evidence:** OBSERVED

`scripts/bump-version.sh` updates the four in-tree version literals plus `package.json`/lock and the CLI goldens, but deliberately leaves `CHANGELOG.md`, `README.md`, and `docs/` (search the script header: "Does NOT touch CHANGELOG.md, README.md"). Its `--check-references` path classifies current references without writing. Three release traps follow:

- **Install pins reflect the latest *published* tag, not the in-tree literal.** README's `go get ...@vX` and "Published `X` package line", plus `docs/ci-integration.md`'s `go install ...@vX`, point at a version a user can actually fetch. Bumping them the instant you bump the literals documents an uninstallable version until `vX` is tagged and pushed to the proxy. Bump install pins (and promote `CHANGELOG.md [Unreleased]` to a dated section, keeping `[Unreleased]` empty per the changelog playbook) at tag time, or only when intentionally shipping the docs ahead of the tag.
- **Committed docs linking into `.goat-flow/scratchpad/` break for cloners.** `CHANGELOG.md` once linked `[release.md](.goat-flow/scratchpad/release.md)`, but `.goat-flow/scratchpad/` is gitignored, so the target is absent in every clone, and the scratchpad is overwritten each release (the v0.2.0 entry pointed at v0.3.0 content). Keep release-narrative cross-references inside committed files; the scratchpad `release.md` is a working draft for the GitHub Release body only.
- **A literal-based exemption can hide a future product version.** The first M16 golden scanner skipped every `"version": "2.1.0"` line to exclude SARIF's document version. That also skipped the gruff-go tool version when a fixture made the product version `2.1.0`. `scripts/bump-version.sh` (search: `scan_golden_versions`) now associates ordinary JSON versions with a preceding `"name": "gruff-go"`, while `semanticVersion` and text mastheads remain direct owners. `scripts/bump-version_test.sh` (search: `test_clean_review_rows`) pins the same-valued SARIF/tool case.

How to avoid: run `scripts/bump-version.sh --check-references --root . --source-version <X.Y.Z>` before the bump. Every `source-current` row must equal the source version; independently resolve every `published-install` row and review `security-support` against that public line. Classify by owner/context, never by exempting a numeric value. Published pins and the changelog date move at tag time unless the release deliberately leads with docs. Never link a committed doc to `.goat-flow/scratchpad/`.

## Footgun: `stats --check` only greps a semantic anchor when the path sits immediately before `(search: ...)`

**Status:** active | **Created:** 2026-08-08 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Write every learning-loop anchor as a backticked path immediately followed by `(search: ...)`. Any other phrasing still reads like evidence to a human but is never checked, so a green `stats --check` is not proof that the entry's anchors resolve.
**Trigger phase:** VERIFY

hallucination-risk: high (`.goat-flow/skill-docs/skill-preamble.md` states that `stats --check` fails on stale refs, and it does - but only for the canonical citation form, so an agent that runs the gate and sees `status: pass` will report anchor health the gate never measured)

The `stale-ref` rule does open cited files and grep the anchor. Its recogniser is form-sensitive: it matches only `` `path` (search: `anchor`) `` with the path adjacent to the search clause. Prose variants are parsed as ordinary text and silently skipped.

Measured 2026-08-08 on a throwaway fixture, one bucket, four entries, one run each:

Each fixture entry cited a real file with an anchor string that appears nowhere in it. Citation forms are described rather than reproduced here, because a literal canonical citation in this entry would itself be parsed as a live claim - see the `Do not backtick nonexistent illustrative paths` lesson.

| Citation form | Result |
|---|---|
| Backticked path, then immediately the search clause in parens | **caught** - `stale-ref` raised |
| Path moved inside the parens, before the colon and anchor | not caught |
| Backticked path, prose words, then the search clause | not caught |
| Path and search clause together in one paren group, comma-separated | not caught |

Two live entries had drifted through exactly this hole before it was found: `.goat-flow/learning-loop/footguns/severity.md` used the parens form to cite an `ADR-009: default is` anchor that no longer existed anywhere in `internal/cli/cli.go` after the flag defaults moved to `internal/cli/analyse_flags.go`, and `.goat-flow/learning-loop/footguns/calibration.md` used the prose form to attribute `scan_module` and `cd "$module_root"` to `scripts/calibrate-scratchpad-corpus.sh`, which had since become a 14-line shim. Both files existed, both anchors returned zero lines, and the gate reported `{"status": "pass", "findings": [], "warnings": []}`.

The gate is not inert - it caught a real regression in this same session when a `.goat-flow/code-map.md` rewrite deleted the `Local build output directory` phrase that `.goat-flow/learning-loop/footguns/build-artifacts.md` cites in canonical form.

How to avoid: use the canonical form so the gate covers you, and repeat the path when one entry cites two anchors in the same file rather than chaining them into one clause. After moving a symbol between files or replacing a script with a shim, grep the learning loop for the old anchor directly - `rg -F '<old-anchor>' .goat-flow/learning-loop/` - because the gate will not do it for non-canonical citations. Re-point a dead anchor at the live symbol rather than deleting it; the recorded claim usually survives the refactor that broke its navigation.

## Footgun: `goat-flow audit --check-content` reports framework dashboard views as project drift; the fix it suggests is a false claim

**Status:** active | **Created:** 2026-08-08 | **Evidence:** OBSERVED
**Decision changed:** Do not satisfy the `code-map-dashboard-view-drift` warning by editing `.goat-flow/code-map.md`; treat it as a permanent unsatisfiable warning of the framework's own layout.
**Trigger phase:** VERIFY

hallucination-risk: high (the warning names `.goat-flow/code-map.md` as the path and supplies a concrete, confident-sounding list of view names to paste in, so an agent chasing a green audit will write framework internals into project docs and believe it fixed real drift)

`node node_modules/@blundergoat/goat-flow/dist/cli/cli.js audit . --agent claude --check-content` exits 1 on gruff-go with a single warning that cannot be cleared:

> Code map lists dashboard views as none, but src/dashboard/views has about, home, hooks, plans, projects, prompts, quality, settings, setup, skills, workspace.

Evidence:
- `node_modules/@blundergoat/goat-flow/dist/cli/audit/check-factual-semantic-drift.js` (search: `Read live dashboard view files with a stable manifest fallback for filesystem stubs`) — the reader globs `src/dashboard/views/*.html` against the target root, and on zero matches falls back to the framework's own bundled manifest view names instead of concluding the target has no such surface. `driftCodeMapDashboardViews` then diffs gruff-go's code map against that fallback.
- gruff-go has no `src/` directory at any depth (`find . -maxdepth 2 -type d -name src -not -path './node_modules/*'` returns nothing), so the glob is always empty and the fallback always fires.
- The 11 reported names are exactly `node_modules/@blundergoat/goat-flow/dist/dashboard/views/*.html` — the GOAT Flow dashboard's views, not this project's.
- gruff-go's dashboard is `internal/dashboard/` (a Go `net/http` server) rendering HTML from `internal/report/`; it has no per-view `.html` files to enumerate. `.goat-flow/code-map.md` already describes both accurately.

Following the suggestion would document vendored framework internals as gruff-go surfaces, which `CLAUDE.md` → Workspace Boundary forbids and which is simply untrue of this repo.

How to avoid: when `--check-content` fails, split findings by rule before fixing any of them. Confirm a drift warning names a surface that exists in this checkout — resolve the cited path on disk first. If it does not resolve, it is framework self-audit leakage: report it, leave the docs correct, and do not count the audit's exit 1 as a project defect. The other content rules (`stale-semantic-anchor`, `skill-playbook-inventory-drift`) do describe real target-project drift and should be fixed normally.

## Footgun: the hand-rolled YAML parser and the strict JSON decoder both fight a list-of-mappings config section

**Status:** active | **Created:** 2026-08-22 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Before adding any config section whose entries are objects rather than scalars, budget for two parser changes in gruff-go, not one - and expect the diagnostic to lose the entry index unless the entry type decodes itself.
**Trigger phase:** SCOPE

hallucination-risk: high (both defects are silent in the shape a reviewer checks first - the section reads fine as YAML, and the strict decoder does reject the bad key, so "it works" survives a shallow read while the entry index the contract requires is simply missing)

`.gruff-go.yaml` is parsed by a deliberately small in-tree parser, not a YAML
library, and every config value is then decoded through one strict JSON decoder.
Adding the ratified `sensitiveExclusions` section (FAMILY-CONTRACT.md,
search: `### 13a. Sensitive exclusions`) hit both layers.

Evidence:

- `internal/config/yaml.go` (search: `func parseYAMLList`) accepted only
  `- scalar` items before this change, so a `- rule: x` item parsed as the
  string `"rule: x"` and the section decoded into a list of strings, failing
  with a type error that named neither the key nor the entry. The repair is
  `yamlListItemOpensMap` plus `parseYAMLListItemMap`, which re-parse the dash
  line and its deeper-indented siblings as one mapping. A quoted item stays a
  scalar, which is what keeps `paths.ignore` and the allowlists unchanged.
- `internal/config/config.go` (search: `func decodeConfigUnvalidated`) sets
  `DisallowUnknownFields`, so a `message_contains` key inside an entry *is*
  rejected - but the error reads `json: unknown field "message_contains"` with
  no entry index, and section 13a requires the diagnostic to name both. The
  repair is `SensitiveExclusion.UnmarshalJSON` (`internal/config/config.go`,
  search: `func (entry *SensitiveExclusion) UnmarshalJSON`), which collects
  offending keys into `UnsupportedKeys` so `validateOneSensitiveExclusion` can
  report `sensitiveExclusions[1] has unsupported key "value"`.
- `internal/cli/hook_base.go` (search: `type hookBaseScan`) is the third-order
  cost: threading one more scan input through the hook's git-base resolver
  pushed it to six parameters, and `go run ./cmd/gruff-go analyse .` dropped
  from zero findings to one `size.parameter-count` warning. Grouping the three
  scan inputs restored grade A. Measured 2026-08-22.

How to avoid:

- Treat "a new config section whose entries are objects" as a parser change plus
  a decoder change plus a dogfood re-check, never as a schema addition.
- Do not rely on `DisallowUnknownFields` when a contract requires a positional
  diagnostic; give the entry type its own `UnmarshalJSON`.
- Re-run the dogfood scan after threading a new value through the CLI, because
  the parameter-count rule fires on the plumbing, not on the feature.

**Portability question this raises for the family.** gruff-go and gruff-ts both
hand-roll their configuration parsers (gruff-ts in `src/config-parse.ts`), and
gruff-ts must add `sensitiveExclusions` with no rule-exclusion section to build
on and no runtime dependency permitted. The question the family has not answered
is whether each hand-rolled parser grows list-of-mapping support independently -
five parsers, five subtly different accepted subsets, five different diagnostics
for one malformed entry - or whether section 13a's entry shape should be
constrained to what every port's existing parser already reads. gruff-go chose
to grow the parser and to keep the growth narrow, but nothing in the contract
pins the accepted subset, so two ports can both conform to 13a while disagreeing
on whether a given file is valid at all. The same gap covers diagnostic wording:
13a mandates that the entry index and offending key appear, not how, so
cross-port conformance can only assert substrings today. M03 should decide
whether the contract owns the parseable subset and the diagnostic shape, or only
the semantics.

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
