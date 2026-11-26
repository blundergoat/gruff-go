# Changelog

## v0.6.0 - 2026-11-27

Coordinated family release: `v3` analysis, summary, and baseline schemas, `gruff.hook.v2`, a normalized cross-port scoring curve, measured rule confidence, retired low-precision rules, and default-on callable documentation checks with natural Go prose matching.

Upgrading from `0.5.x`: this release changes every machine-readable contract at once. See [`UPGRADING.md`](UPGRADING.md) for migration commands and how to pin `0.5.x` while keeping your pre-upgrade config and baseline intact.

### Breaking changes

- **BREAKING: Machine JSON moves to `gruff.analysis.v3` and `gruff.summary.v3`** - Update analysis consumers to read `score.composite.{score,grade}`, `paths.{ignoredPaths,details,missingPaths}`, `summary.suppressedFindings`, `diff.filteredFindings`, and Go-only rule and scanned-path data under the `go` extensions. `analyse --format summary-json` and `summary --format json` emit `gruff.summary.v3` (the analysis payload without top-level `findings`); there is no `v2` compatibility writer.
- **BREAKING: Baselines move to `gruff.baseline.v3` and finding identities change once** - Entries store a line-free SHA-256 identity (language, rule ID, project-relative path, and symbol plus declaration ordinal or normalized message) and a count, so edits above a finding no longer expire its review. A `gruff-go.baseline.v0.1` file fails closed; migrate with `gruff-go baseline --migrate-baseline <old> --out <new>`.
- **BREAKING: Sensitive-data findings cannot be baselined** - Generated baselines count secret findings by rule without storing entries, paths, or messages, and hand-written rows cannot hide them. Fix the credential or add a reason-bearing entry under `sensitiveExclusions`.
- **BREAKING: SARIF fingerprints adopt the durable identity, and secrets omit them** - `partialFingerprints.gruffFingerprint` uses the line-free baseline identity (existing alerts re-key once on upgrade, and same-named declarations become separate alerts). `sensitive-data.*` SARIF results omit `partialFingerprints` and `properties.fingerprint` so code scanning never stores a durable name for a secret.
- **BREAKING: Every score changes under the normalized family scoring curve** - Each pillar scores `floor + (100 - floor) / (1 + density / densityScale)` (error weight `30 → 12`, warning weight `8 → 4`; confidence weights `0.5 / 0.75 / 1.0`; grade boundaries unchanged at `A>=90`, `B>=80`, `C>=70`, `D>=60`), so duplicating a codebase no longer lowers its grade.
- **BREAKING: Composite scores carry two decimals and can be `null`** - `score.composite.score` changes from a truncated integer to a two-decimal number. `score.composite.{score,grade}` and `score.pillars[].{score,grade}` are `null` when zero Go files are evaluated (previously empty or unparseable targets reported `100` / grade `A`).
- **BREAKING: `score.pillars` lists every rule-backed pillar** - Each row carries an `applicable` flag separating reachable clean pillars from unreachable ones. Consumers counting finding-bearing pillars should read `findings` instead of array length.
- **BREAKING: Rule confidence follows measured precision** - Every finding carries its rule's catalogue confidence (`high` >= 0.85, `medium` >= 0.70, `low` < 0.70), changing 8 rules' weights (`complexity.cognitive` high→low; `docs.exported-symbol-comment`, `docs.suppression-without-rationale`, `naming.identifier-quality` medium→high; `security.http-client-no-timeout`, `security.tls-insecure-config`, `test-quality.sleep-in-test`, `test-quality.tempdir-misuse` high→medium). Test-file size softening changes severity only; unmeasured rules keep inherited confidence under `Confidence evidence` in `docs/rules.md`.
- **BREAKING: Per-command exit gates move from `minimumSeverity:` to `failOn:`** - A `0.5` config carrying a `minimumSeverity:` map exits `2` naming `failOn` (`analyse`, `summary`, `report`, `dashboard`); `minimumSeverity` is now a scalar display floor (`advisory`, `warning`, or `error`) that never alters exit codes, scores, or baselines. `--min-severity` is refused in `0.6.0` (returns in `0.7.0` as a display filter); migrate configs with `gruff-go migrate-config --config .gruff-go.yaml --output gruff-0.6.yaml`.
- **BREAKING: Secret preview allowlists are removed (`allowlists.secretPreviews`, `sensitiveData.previewAllowlist`)** - Every sensitive-data rule emits unconditional zero-payload markers. Any config carrying `allowlists.secretPreviews` (including the empty list written by `0.5` `gruff-go init`) or `sensitiveData.previewAllowlist` exits `2`; `gruff-go migrate-config` removes those keys automatically.
- **BREAKING: Configs without `schemaVersion` are refused** - Hand-written configs omitting `schemaVersion` exit `2`, matching the other four ports. Run `gruff-go init --force` to add it while preserving local tuning.
- **BREAKING: `summary` exits `0` unless gated** - `summary`'s default gate moves from `advisory` to `none`. Pass `--fail-on <severity>` or set `failOn.summary` in `.gruff-go.yaml` to gate CI on `summary` (`analyse` remains `advisory`).
- **BREAKING: Agent hooks move from `gruff.hook.v1` to `gruff.hook.v2`** - The envelope adds required `run` and `suppressions` keys and ratifies strict `0` (clean), `1` (gated finding under explicit `--fail-on`, `--fail-on-new`, or `--fail-on-diagnostics`), and `2` (run failure) exits.
- **BREAKING: `list-rules` shows built-in defaults and renames `severity` to `defaultSeverity`** - Both text and JSON outputs always report release defaults rather than project config overrides (a broken `.gruff-go.yaml` still exits `2`). JSON output renames `rules[].severity` to `rules[].defaultSeverity`; the analysis report's embedded rule list keeps `severity`.
- **BREAKING: Eight low-precision rules are removed** - Retired rules that scored below 50% accuracy in the 0.6.0 corpus: `design.hotspot-file` (0/25), `maintainability.production-panic` (12/50), `security.sensitive-data-logging` (0/16), `security.sql-string-query` (1/9), `sensitive-data.high-entropy-string` (4/24, along with its built-in lockfile skip), `naming.negated-boolean`, `test-quality.no-failure-path`, and `test-quality.skipped-test` (ADR-021). Configs naming them exit `2` (run `gruff-go migrate-config` or `init --force --reset`); composite scores may dip slightly because the `design` pillar now has no rules.
- **BREAKING: Ten rules move to opt-in** - Disabled by default where corpus samples were small or upper-band precision fell below floor: `dependency.go-mod-local-replace`, `security.insecure-random-secret`, `sensitive-data.aws-access-key`, `sensitive-data.connection-string`, `sensitive-data.gcp-service-account`, `sensitive-data.github-token`, `sensitive-data.google-api-key`, `complexity.cyclomatic` (23/40 upper-band), `security.open-redirect-candidate`, and `security.request-body-without-limit` (ADR-021). Enable any with `rules.<id>.enabled: true`; existing `0.5` `init` configs keep them on.
- **BREAKING: Every `sensitive-data.*` rule defaults to `warning`** - Thirteen secret rules move from `error` to `warning` for family parity (`--fail-on=error` no longer fails on default secret findings; `advisory` and `warning` gates still do, and `severity: error` in `.gruff-go.yaml` restores the previous tier).
- **BREAKING: Size and complexity findings report in two bands** - Units between 1x and 1.5x of their limit emit as `advisory` (`limitBand: lower`); units at 1.5x or above keep their configured severity (`limitBand: upper`). Messages and fingerprints stay unchanged so baselines keep matching.
- **BREAKING: Default discovery adopts the family fallback policy** - Non-VCS fallbacks defer to any governing `.gitignore`; committed control metadata stays scannable; explicit supported files bypass Git and fallback skips; and `vendor`, `vendors`, `third_party`, `third-party`, `bower_components`, `dist`, and `*.min.*` are skipped at any depth even under `.gitignore` (override with `--include-ignored` or an explicit file). `paths.ignore` and VCS internals remain authoritative.
- **BREAKING: Empty `--changed-ranges=` is refused** - Passing `--changed-ranges=` exits `2` with a `changed-region` diagnostic and zero findings on both `analyse` and `hook`, instead of silently running a whole-tree scan.
- **BREAKING: `sensitive-data.secret-pattern` skips Go raw strings** - Backtick literals commonly hold docs, templates, and sample payloads rather than real credentials; interpreted strings, assignments, and all other secret rules are unchanged.
- **BREAKING: Methods on generic types normalize to `Type.Method`** - Receiver methods such as `(*Stack[T]).Push` report consistently as `Stack.Push` everywhere (one-time identity change, including `test-quality.helper-missing-t-helper`), and exported generic methods are now checked by `docs.exported-symbol-comment`.
- **BREAKING: Local dashboard rejects non-loopback `Host` headers** - Local-only `dashboard` binds return `403` for non-loopback `Host` headers; pass `--allow-public` when serving behind another host.
- **BREAKING: Scans reject targets spanning unrelated external projects** - `analyse`, `summary`, `report`, and `hook` exit `2` when given targets from different external project roots rather than scanning under an ambiguous root; scan each project separately.
- **BREAKING: Duplicate canonical and legacy alias rule configs exit `2`** - Listing both a canonical rule ID and its legacy hyphenated alias under `rules:` exits `2` deterministically; keep only the canonical ID.
- **BREAKING: Mixed staged and unstaged `--diff staged` runs exit `2`** - `--diff staged` fails closed when staged files also carry unstaged edits on disk rather than evaluating post-stage bytes; stage or stash remaining edits first.

### Added

- **Canonical display filter flags on `analyse` and `report`** - Adds `--show-rule`, `--hide-rule`, `--show-pillar`, and `--hide-pillar`, keeping full-scan headline totals, scores, and exit codes unchanged; superseded plural flags (`--include-rules`, `--exclude-rules`, `--include-pillars`, `--exclude-pillars`) still work with a stderr warning.
- **Non-destructive config migration (`gruff-go migrate-config`)** - Rewrites `0.5` configs to `0.6` (`schemaVersion`, `failOn`, and removing `allowlists.secretPreviews`, `sensitiveData.previewAllowlist`, bare `sensitiveData`, and retired rules) into a fresh destination file while leaving the original untouched.
- **Non-destructive baseline migration (`baseline --migrate-baseline`)** - Carries identifiable reviewed `0.5` findings into a separate `v3` file without modifying the original, refusing self-overwrite or ambiguous multi-container files.
- **Auto-discovered root baselines with 0.5 overwrite protection** - `analyse` automatically applies a root `gruff-baseline.json` (`source: "default"`, disable with `--no-baseline`) and refuses to overwrite a non-v3 file at that path unless `--force` is passed.
- **Default-on callable documentation checks** - `docs.missing-param-doc` and `docs.missing-return-doc` run by default on documented functions, methods, and package-level function-literal vars (skipping context, HTTP, and testing handles), matching camelCase/snake_case stems, plural acronyms, and natural Go return prose; disable either with `rules.<id>.enabled: false`.
- **Duplicate test group detection (`test-quality.duplicate-test-body`)** - Enabled by default for groups of four or more runnable tests in one file (at least four statements each) differing only in eligible literals, skipping table-driven suites and keeping groups in scope when any member overlaps a changed-region scan; disable with `rules.test-quality.duplicate-test-body.enabled: false`.
- **Reason-bearing `sensitiveExclusions` with audit rows** - Adds a top-level `.gruff-go.yaml` section to suppress one `sensitive-data.*` rule in one project-relative file with a required `reason` (and optional `symbol`), rejecting value/message keys or malformed scopes with exit `2` and recording every entry under `suppressions` in `analyse`, `summary`, HTML, Markdown, SARIF, and `hook`.
- **Cross-tool inline suppression compatibility** - Recognizes well-formed `#nosec` (`G112`, `G402`, `G204`, `G101`, or bare), `//nolint` (`funlen`, `all`, `gosec`, or bare), and `# zizmor: ignore[unpinned-uses|dangerous-triggers]` in Go, YAML, and dotenv comments on the finding line or directly above (never in prose, raw strings, or malformed lists), counted as `source: "inline"` audit rows and SARIF `inSource` suppressions.
- **Expanded machine metadata and release archives** - Publishes `score.evaluatedFiles`, `score.scoredPillars`, `falsePositiveShapes` on `list-rules --format json`, and `generated`/`source` fields on `analyse --baseline` JSON; release archives include `UPGRADING.md`.

### Changed

- **Security and sensitive-data rules skip test, fixture, and example paths** - Every `security.*`, `dependency.go-mod-*`, and `sensitive-data.*` rule skips `test`, `tests`, `__tests__`, `spec`, `testdata`, `fixtures`, and `examples` paths and test-named files, publishing a counted `source: "built-in"` audit row per skip. **Deliberate trade-off:** real credentials or security mistakes committed under those paths are no longer reported.
- **Sample secrets and masked AWS keys stay quiet; `ASIA` tokens report** - Twenty published sample values (AWS example keys, jwt.io sample token, Google reCAPTCHA v2 test key, and 14 test card numbers) and all-`X` masked AWS keys no longer warn; `sensitive-data.aws-access-key` also flags temporary `ASIA` session tokens.
- **Complexity rules skip `_test.go` and stop penalizing flat dispatch** - `complexity.cyclomatic` and `complexity.cognitive` ignore test files, count each `switch`/`select` as a single cyclomatic decision, and drop nesting penalties on flat switch cases and early-exit guards.
- **Size and complexity rules cover keyed literal arguments and package-level function vars** - `size.function-length` counts keyed struct/map literal arguments as one line (`literalArgumentLines` metadata), and `var Mix = func(...)` declarations are measured by size, complexity, and callable-doc rules.
- **Zero-file skip hints and failing-pillar caveats** - `summary` and `analyse` text output prints a recovery hint when ignore rules skip every target path, and `score.coverage.caveat` names any failing (`F`) pillar inside a grade `A` or `B` composite without altering numeric scores.
- **Documentation, dead-code, naming, and empty-test refinements** - `docs.exported-symbol-comment` lists missing function/method doc elements; `dead-code.unused-private-{const,type,var}` suggest next steps; `naming.contextual-generic` counts code lines only; and `test-quality.empty-test` flags tests whose only statement is `t.Parallel()`.
- **Per-file scoring, baseline collisions, and budget accounting** - `score.topOffenders` uses the same normalized curve as project scores; symbol-less identities replace digit runs with `#` so line-count growth keeps matching baselines; baseline collisions stay visible with a `baseline` diagnostic; and budget-skipped Go files are counted separately.
- **Scoped rule execution and external file policy** - Explicit rule includes restrict execution to selected rules, and external single-file scans inherit their enclosing project's config and root policy.
- **Built with Go `1.26.11`** - Updates the Go toolchain to fix `GO-2026-6809` (`crypto/x509`) and `GO-2026-6859` (`net/http` `MaxBytesReader` race, reachable in `dashboard`).

### Fixed

- **`sensitive-data.private-key` false positives** - Isolated PEM headers in `regexp.Compile`/`MustCompile` patterns and PEM normalization calls that strip matching `END` footers or line breaks with empty replacements no longer warn; authored key bodies and non-empty replacements still warn.
- **`dead-code.empty-block` false positives** - Deliberate `for` headers, channel drains (`for range ch {}`), `select {}`, and commented blocks (including single-line `/* ... */`) stay quiet (84 fewer corpus false positives).
- **Workflow and HTTP security false positives** - `security.github-actions-secrets-in-pr` checks `pull_request_target` workflows only (38 → 2 corpus findings), skips unreachable event-guarded jobs/steps, and names the `workflow_run` repo/branch check in its remediation; `security.open-redirect-candidate` skips HTTPS self-upgrades; `security.request-body-without-limit` skips `http.RoundTripper` and test helpers reading program-built requests; and weak-key checks skip numbered decimal buckets.
- **Test-quality false positives** - `test-quality.helper-missing-t-helper` skips benchmarks, 30+ line `testXxx` bodies, interface-asserted `Helper()` calls, and failures scoped to a `t.Run` closure's `t`; `test-quality.sleep-in-test` skips `synctest`, test-double delays, timed sleeps, and additional bounded-poll patterns.
- **Archive traversal and request-taint security accuracy** - `security.archive-path-traversal` rejects bare `filepath.Clean` and discarded containment calls, flags wrapped entry names such as `filepath.Join(dest, filepath.Clean(file.Name))`, recognizes `filepath.IsLocal`/`Localize`/`os.OpenInRoot`, and counts `strings.Contains` only when checking for `..`; `security.request-*` taint tracks `range` loop sources and reassignments.
- **Workflow YAML parsing accuracy** - GitHub Actions workflow rules parse indentless YAML sequences and flow collections (`on: {pull_request_target: ...}` or multi-line `[...]` lists) and ignore column-0 comments inside `on:` without matching nested branch filters.
- **Suppression rationale and unreachable-code accuracy** - `docs.suppression-without-rationale` accepts prose comment blocks and multi-line `/* ... */` rationales above directives while flagging bare `#nosec G101,G204`; `dead-code.unreachable-code` skips locally shadowed `panic` identifiers.
- **Launch-directory independence** - `analyse`, `summary`, `report`, `.gruff-go.yaml` discovery, and relative `--baseline`/`--generate-baseline` paths resolve consistently from any working directory without leaking host paths.
- **Baseline ordinal and symbol edge cases** - Ordinals count all parsed same-named functions so newly warning methods never inherit another method's review; symbols containing `#` degrade to `notEligible` instead of aborting; and SARIF `baselineState: "new"` marks only genuinely new findings.
- **Changed-region diff parsing and anchoring** - Changed-region scans include attached function doc comments under `--changed-scope=symbol`, anchor pure deletions on shifted lines, decode Git-quoted and mnemonic-prefixed diff paths, and reject truncated `--diff=-` hunks.
- **Agent hook base exports and fail-closed errors** - Hook base exports read Git blobs directly so `.gitattributes` `export-ignore` never hides committed files, and hook scans fail closed on invalid baselines or incomplete Git comparisons (`--fail-on-new` fails closed when review status cannot be determined).
- **Parser redaction, SARIF URIs, and safe discovery** - Go parser diagnostics redact quoted source literals so malformed files never leak secrets; SARIF URIs percent-encode special path characters; and source discovery skips walked symlinks and non-regular files.
- **YAML config parsing, machine-error JSON, and `init --force` safety** - YAML parsing handles quoted keys, in-token `#`, plain-scalar apostrophes, and actionable flow-mapping errors; post-parse refusals under `--format json` emit valid `gruff.analysis.v3` envelopes (`missing-path`, `config-error`); out-of-root diagnostics omit `file` instead of failing serialization; and `init --force` preserves the original config on error.

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
