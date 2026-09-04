# Changelog

## [Unreleased]

- **BREAKING: every score changes - the family adopts one normalized scoring formula** - A pillar is now `floor + (100 - floor) / (1 + density / densityScale)`, where `density` is the pillar's summed severity-by-confidence weight divided by the number of Go files that were actually evaluated. Scores no longer track project size: duplicating a project leaves its grade unchanged, where before it fell. Two ratified parameter changes move every historical score in the same break - the error weight drops from 30 to 12, and confidence weights become 0.5 / 0.75 / 1.0 - so a project's number will differ from any earlier run even with identical findings. Grade boundaries are unchanged at A>=90, B>=80, C>=70, D>=60, because an even five-way split of the new range reproduces them exactly.
- **BREAKING: the composite is a two-decimal number and can be null** - `score.composite.score` was an integer truncated toward zero and is now a number carrying two decimals, so JSON consumers decoding it as an integer must widen the type. It, `score.composite.grade`, and each `score.pillars[].{score,grade}` are `null` when the run evaluated nothing at all: an empty directory, or one whose every Go file failed to parse, previously reported a perfect `100` and grade `A`.
- **BREAKING: `score.pillars` lists every rule-backed pillar, not only the ones with findings** - Each row now carries an `applicable` flag, so a reachable pillar that reported nothing is visibly distinct from a pillar no rule can reach. Consumers counting rows to learn how many pillars had findings must read `findings` instead.
- **`score.evaluatedFiles` and `score.scoredPillars` are published** - The scoring denominator and the pillar set it was drawn from are now in the envelope, so any consumer can reproduce the composite without guessing which of the file counts it used. `evaluatedFiles` counts Go files that survived the ignore rules and parsed; it is deliberately not `summary.filesScanned`, which also counts raw-text inputs.
- **Per-file scores follow the same curve as the project** - `score.topOffenders[].score` is the ratified curve over that file's own weighted findings, and `penalty` is now the raw weight rather than a rounded integer, so file ranking and project grading can no longer disagree about the same code.
- **BREAKING: machine JSON adopts the family v3 envelopes** - Update analysis consumers to accept `gruff.analysis.v3`, read the composite from `score.composite.{score,grade}`, paths from `paths.{ignoredPaths,details,missingPaths}`, changed-region counts from `summary.suppressedFindings` and `diff.filteredFindings`, and Go-only rule/scanned-path data from the named `go` extensions. `analyse --format summary-json` and `summary --format json` now emit `gruff.summary.v3`, the analysis document with only top-level `findings` removed. Fingerprints, stable identities, score values, baseline matching, and exit decisions are unchanged. This coordinated pre-1.0 family break has no v2 writer or compatibility window so all ports expose one contract at release.
- **Precision limits are available for every medium-confidence rule** - `list-rules --format json` now gives each medium-confidence rule a concrete false-positive shape and mitigation, without changing detector behavior, defaults, scoring, or analysis JSON.
- **BREAKING: default scans use the family fallback policy** - Non-VCS fallbacks now defer to any governing `.gitignore`, committed control metadata stays scannable, and explicit supported files bypass Git and fallback exclusions. Use `paths.ignore` for project-only exclusions; VCS internals remain blocked even with `--include-ignored`.
- **Sensitive-data findings can be excluded, with a reason** - A new top-level `sensitiveExclusions` section in `.gruff-go.yaml` suppresses one sensitive-data rule in one project-relative file. `reason` is required, `symbol` optionally narrows the scope, and message- or value-matching keys are rejected, so a suppression can never be written against a secret's own text. Entries are authored by hand: no reported marker or preview is ever converted into one.
- **Every exclusion is counted** - `analyse --format json` publishes a `suppressions` array with one row per entry — `{index, rule, paths, symbol?, reason, suppressed}` — including entries that matched nothing, and text output prints a `suppressed findings:` total. A suppressed finding leaves the score and exit-code calculation but never the audit.
- **`summary` counts its suppressions out loud** - Text prints the same `suppressed findings:` total as `analyse`, below the composite block. JSON emits `gruff.summary.v3` with the same `suppressions` audit and `summary.suppressedFindings` count as the corresponding analysis run.
- **A malformed exclusion breaks the build** - A wildcard, pillar, unknown, or non-sensitive rule; an absolute, escaping, or glob path; a message-, value-, or preview-matching key; a blank reason; or two entries claiming one scope each exits `2` with a `config:` diagnostic naming the entry index and the offending key.
- **The config parser accepts mapping list items** - `.gruff-go.yaml` now parses dash-introduced `key: value` items, which `sensitiveExclusions` needs. A quoted list item stays a scalar, so existing string lists are unchanged.

## v0.5.0 - 2026-08-16

Sharper security and sensitive-data rules, secret previews redacted by default, a composite that scores every pillar, and baselines that match one-to-one. Three breaking changes: `size.file-length` moves to error severity at 1000 lines, fatal diagnostics exit `2`, and commands reject positional arguments they never used.

- **BREAKING: `size.file-length` is error at 1000 lines** - Comments and blanks stop counting, but `--fail-on=error` can fail on an unchanged file.
- **BREAKING: fatal diagnostics exit `2`** - A crash is distinct from a finding failure, and `none` disables only the failure at exit `1`.
- **BREAKING: unused positional arguments are rejected** - `dashboard`, `list-rules`, and `completion` exit `2` instead of ignoring a path you passed.
- **Flags work after paths** - Subcommands parse flags before, between, or after positional paths. Use `--` before a path starting with a dash.
- **A `-` patch value keeps the global flags after it** - `analyse --diff - --quiet` applies quiet mode instead of rejecting it as undefined; `--since -` and the verbosity, ANSI, and interaction flags recover too.
- **Secret previews are redacted by default** - Every sensitive-data rule and output format emits a redacted marker instead of the matched secret.
- **Passwords containing `@` are reported again** - The split stops at the authority, so `app:p@ssw0rd@db/orders` no longer resolves to a bogus host.
- **Placeholders are not credentials** - A password that is entirely `{{action}}`, `${VAR}`, or `<placeholder>` is exempt; `s3cret{9}` still reports.
- **Replica-set URIs are handled honestly** - `h1:27017,h2:27017` is no longer reduced to a misleading hostname; which URIs report is unchanged.
- **Backslash redirects are caught** - A `//`-trimming loop leaves `/\evil.example` intact, so it proves nothing unless a backslash fold runs first.
- **Computed redirect statuses are caught** - A `WriteHeader` status the parser cannot resolve counts as a redirect; a known non-redirect stays quiet.
- **Fewer redirect false positives** - A `break` bound to a nested loop, or a query appended after normalisation, no longer voids a valid proof.
- **Guards expire when the value changes** - Writing to a field or pointee of a guarded value re-opens the finding that guard had cleared.
- **Token generators flag any buffer name** - `insecure-random-secret` now reports `buf[i] = ...` and `token += string(...)` inside a generator.
- **Split destination guards no longer pass** - A scheme check and a host check from mutually exclusive branches stop counting as one guard.
- **Explicit boolean guards count as validation** - `if validateURL(u) == false` proves the same guard as `!validateURL(u)`, so the explicit style no longer reports a validated URL.
- **A shadowed import is no longer its package** - A local named `http`, `fmt`, `io`, `path`, or `url` stops being read as the imported package, removing false SSRF sinks and false taint propagation.
- **An overwritten request value stops reporting** - A write that must run before the sink clears the taint; a write inside a branch the sink sits outside of, a `+=`, or a later request write still reports. A `goto`, a closure that rewrites the value, or taking its address keeps the finding.
- **The composite scores every pillar** - A clean rule-backed pillar counts as 100 instead of being dropped from the average.
- **Baselines match one-to-one** - Exact findings match first, then stable identities once each, so a second secret on one line is not absorbed.
- **Reviewed findings stay occurrence-specific** - Baseline matching needs a named symbol or metric, so one accepted finding cannot hide another.
- **Duplicate YAML keys are rejected** - `.gruff-go.yaml` fails per mapping, naming both line numbers instead of silently taking the last value.
- **Path filters reject unsafe patterns** - Windows-style and bare `**` patterns are refused, and a trailing slash now matches `/**` consistently.
- **The security gate ceiling is enforced** - A registry test fails the build if a default-enabled `security.*` rule ships at error severity.
- **Gate defaults are documented per command** - `--min-severity` defaults to `advisory` for `analyse`/`summary` and `none` for `report`/`dashboard`.
- **Redirected output stays non-interactive** - Writing to `/dev/null` or a pipe no longer triggers the first-run config prompt or ANSI colour codes.
- **Summary separates its scan surface** - `summary --format text` counts Go files parsed, text files scanned, failed reads, and skips separately.
- **Context parse failures are counted** - A supporting file that fails to parse appears in the summary even when it was used only for context.
- **`size.file-length` anchors to the real line** - The finding points at the line crossing the budget, so diff and changed-region scans keep it.
- **cgo preambles count as code** - C source before `import "C"` reaches the substantive line count, so a large mixed Go/C file no longer bypasses `size.file-length`.
- **CI recipes lead with `--since`** - `docs/ci-integration.md` documents `--since <ref>` as the primary diff flag; `--diff-base` still works.
- **Skip-only tests report once** - A test whose only action is `Skip`, `Skipf`, or `SkipNow` emits `skipped-test` alone, not a stack of findings.
- **TODO marker precision** - Markers that introduce a string-literal line are flagged, while a TODO mentioned in prose stays quiet.
- **Random selection precision** - Sampling directly from an existing collection is exempt, while random values in a security context still report.
- **Go 1.22 range semantics** - Loop-variable rules apply per-iteration semantics, and a module with no Go directive is treated as Go 1.16.
- **Go toolchain pinned to 1.25.13** - Clears three standard-library `govulncheck` findings (GO-2026-6090, 6089, 5972) without suppressing the audit.
- **The Claude profile denies secret edits** - Secret paths and nine `.env` variants gain `Edit` denials; path-scoped `Write` rules never applied.
- **Deletes with a variable path block** - The deny guard rejects an unresolved expansion anywhere in the target, so `rm -rf cache/$TARGET` fails.
- **Post-turn scan limits fall back safely** - A nonnumeric limit reverts to the default instead of skipping every file while reporting clean.
- **GOAT Flow 1.15.1** - Refreshes Claude, Codex, and Copilot skills, safety hooks, and playbooks onto one Node hook launcher.

## v0.4.0 - 2026-06-14

Fewer false positives in the security, sensitive-data, and test-quality rules, plus a steadier agent hook. No schema or config changes from v0.3.0.

- **Generated-file handling** - The skip needs both `generated` and `DO NOT EDIT` and is Go-only, so a banner elsewhere no longer hides findings.
- **Sensitive-data false positives** - The scanner skips comments, `${name}` placeholders, `CHANGEME` examples, and PEM prose; real secrets flag.
- **Test-quality precision** - `no-failure-path` skips benchmarks and knows your own assertion helpers; `sleep-in-test` needs a real polling loop.
- **Explicit-file scans** - `analyse path/to/file.go` reads same-directory siblings for context, so cross-file false positives disappear.
- **SQL detection** - `sql-string-query` accepts queries built only from string literals, including bind parameters, and still flags interpolation.
- **Agent hook resilience** - `hook --diff HEAD` in a repo with no commits returns normal JSON with a warning and scans without diff filtering.
- **Docs and tooling** - `design.hotspot-file` is documented as score-neutral triage and `allowlists.secretPreviews` as preview-only.

## v0.3.0 - 2026-06-09

Codifies gruff's mission as a coding-agent guardrail for AI code a human can verify, and aligns the default pack to it: 83 rules across 11 pillars, 70 default-enabled.

- **BREAKING: `complexity.npath` removed** - Config now rejects the rule ID; drop the block or run `init --force --reset` (ADR-014).
- **BREAKING: `design.god-function` removed** - Correlated per-symbol findings cluster in scoring instead of a whole-function finding (ADR-018).
- **BREAKING: analysis JSON is `gruff.analysis.v2`** - Adds flat `line`/`column` and `stableIdentity`; the nested `location` stays for one release.
- **Agent hook contract** - New `hook --format json` emits the cross-port `gruff.hook.v1` contract for agent hooks, exiting 0 on advisory findings.
- **Diff-aware analysis** - `--changed-ranges`, `--since`, `--diff`, and `--changed-scope` score only what changed while still parsing the project.
- **Authoritative `paths.ignore`** - Ignores apply in every invocation, and new `check-ignore` reports exclusion with git-style exit codes (ADR-015).
- **Three-state baselines** - Every run classifies findings as `new`, `unchanged`, or `resolved`, with an opt-in `--baseline-show` (ADR-012).
- **Request-driven security rules** - Seven default-on rules trace request values into SSRF, path-traversal, redirect, XSS, XXE, and logging sinks.
- **Workflow security rules** - Five default-on rules flag unpinned actions, piped remote shells, broad permissions, and PR-exposed secrets.
- **Go-module and sensitive-data rules** - Two `go.mod` `replace` rules ship default-on, plus opt-in entropy, PII, and PHI detectors.
- **Default pack retuned** - Six convention rules move to opt-in and `complexity.cognitive` tightens to 25 (ADR-016).
- **Canonical text output** - Every command leads with a `gruff-go <version> <subcommand>` masthead and a shared `Composite:` and `Findings:` block.
- **Score clustering** - Correlated findings on one symbol bill the grade once instead of compounding; each finding is still reported (ADR-018).

## v0.2.0 - 2026-05-28

Severity harmonisation across the gruff family, per-command exit-code policy, and Markdown output. Hard-break with no deprecation cycle, per the pre-1.0 no-legacy-compat policy.

- **BREAKING: three severity buckets** - `advisory`, `warning`, and `error` replace the five old names, which are now rejected at load (ADR-009).
- **BREAKING: analysis schema `v0.1` → `v0.2`** - Severity keys become `{Advisory, Warning, Error}` and penalty weights collapse to `1 / 8 / 30`.
- **BREAKING: gate defaults split per command** - `analyse`/`summary` drop to `advisory`; `report`/`dashboard` drop to `none` and never exit 1.
- **BREAKING: `summary --format=json` is `gruff.summary.v2`** - A pillar digest replaces the full payload; use `analyse --format=summary-json`.
- **Per-command severity config** - New `minimumSeverity:` block sets a threshold per command; the CLI flag still wins (ADR-010).
- **`none` threshold value** - Accepted by `--min-severity` and `--fail-on` to report findings and still exit 0, the right default for inspection.
- **Markdown output** - `analyse --format=markdown` renders a CommonMark digest for CI logs and PR comments, with severity totals and top rules.
- **Canonical pillars table** - One 7-column table is shared by `summary` text, HTML, and Markdown, and always lists all ten pillars.
- **`penalty` field on pillars** - Reports the raw unclamped deduction, so you can rank the worst pillar once several have floored at 0.
- **Dashboard honours config** - The server consults `minimumSeverity.dashboard` when `--fail-on` is absent; the flag default previously overrode it.
- **`init --force` is safe on old configs** - Ignores, allowlists, thresholds, and options survive the regenerate instead of being overwritten.
- **Clearer schema-mismatch errors** - Config and baseline version errors name the expected version and the exact command that fixes it.
- **`acceptedAbbreviations` fix** - Only blank entries are rejected, and entries normalise to lowercase so `ID` and `id` are the same key.
- **Release tooling** - `publish-go-pkg.sh` verifies the tag against source metadata and rejects Go-invalid SemVer before creating it.
- **`docs/rules.md` accuracy** - `complexity.nesting-depth` and `complexity.npath` now document their real defaults, `maxDepth: 5` and `1024`.

## v0.1.1 - 2026-05-24

Onboarding, baselines, and 23 new default-enabled parser rules. Backwards-compatible with v0.1.0; schemas unchanged.

- **`gruff-go init`** - Writes a default `.gruff-go.yaml`; `--force` merges your existing overrides, and `--force --reset` overwrites from scratch.
- **First-run config prompt** - `analyse`, `summary`, `report`, and `dashboard` offer to generate a config, skipping the prompt in CI or with `-n`.
- **Fresh-start baselines** - `analyse --generate-baseline gruff-baseline.json .` captures a baseline from a clean scan in one step.
- **23 new default-enabled rules (41 → 64)** - Adds complexity, dead-code, maintainability, security, sensitive-data, and test-quality coverage.
- **Precision fixes** - `permissive-file-mode` ignores calls without `O_CREATE`, and `parallel-range-capture` only reports below Go 1.22.
- **CLI ergonomics** - `--fail-on` aliases `--min-severity` for family parity, and `--silent` aliases `--quiet`.
- **Shell completion** - `gruff-go completion [bash|zsh|fish]` prints a completion script, and a failed write now errors.
- **Dashboard `Options.Ready`** - An optional channel closes once the listener has bound, so tests can synchronise teardown without polling.
- **Release tooling** - `bump-version.sh` updates every version literal, and `preflight-checks.sh` adds `npm audit` and `govulncheck` gates.
- **Documentation** - New `docs/README.md` index and `docs/releasing.md` checklist; `allowlists.secretPreviews` controls redaction only.

## v0.1.0 - 2026-05-23

First public release. Parser-only Go code-quality scanner; six CLI commands; 41 rules across 9 pillars; six output formats; local HTML dashboard.

- **CLI commands** - `analyse`, `baseline`, `dashboard`, `report`, `summary`, and `list-rules`.
- **Rule catalogue** - 41 rules across 9 pillars, 40 of them enabled by default.
- **Configuration** - Strict `.gruff-go.yaml` schema with `.gitignore`-aware file discovery.
- **Workflow features** - Baselines and diff-mode track findings against a known-clean state or a base commit.
- **Output formats** - `text`, `json`, `summary-json`, `sarif`, `github`, and `html`.
- **Local dashboard** - The `dashboard` command serves the HTML report locally.
- **Schemas** - `gruff-go.analysis.v0.1`, `gruff-go.config.v0.1`, and `gruff-go.baseline.v0.1`, stable within `0.1.x`.
- **Install** - `go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.1.0` on Go 1.24+, or a prebuilt binary from the GitHub Release.
- **Known limitations** - Parser-only, with no type or SSA analysis; the dashboard accessibility review is ongoing.
