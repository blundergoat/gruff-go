# Upgrading

How to move a project between `gruff-go` lines, what each move breaks, and how to go back.
Every break below is the one this port's own `CHANGELOG.md` records; nothing here is a plan.

## What is stable across `0.5.x`

- Rule identifiers. A released `ruleId` keeps its meaning; it is not renamed or repurposed inside a line.
- The configuration file's name and its documented keys.
- Exit codes for the documented severity gate.
- The analysis envelope's schema version, which changes only on a minor line.

## What changes in `0.6.0`

`0.6.0` is a coordinated family release: the same break lands in all five ports rather than one at a
time, so a project using more than one of them moves once. This port's recorded breaks are:

1. **Configs without `schemaVersion` are refused** — `gruff-php`, `gruff-py`, `gruff-rs`, and `gruff-ts` all exit `2` when `schemaVersion` is missing; `gruff-go` now does the same, naming the key, expected version, and `gruff-go init --force`. Since `init` has always written `schemaVersion`, only hand-written configs are affected, and `gruff-go init --force` repairs them while preserving existing tuning.
2. **`sensitive-data.high-entropy-string` is removed** — It was right on 4 of 24 judged findings in the 0.6.0 precision measurement. Any config, baseline, or `sensitiveExclusions` entry naming it is now refused: delete it, or run `gruff-go init --force --reset`. Provider-pattern secret rules still report (ADR-021).
3. **`sensitive-data.secret-pattern` no longer scans inside Go raw strings** — Backtick literals commonly hold docs, templates, and sample payloads rather than real credentials. Interpreted strings, ordinary assignments, and all other sensitive-data rules are unchanged.
4. **Baselines move to `gruff.baseline.v3` and finding identities change once** — Each entry stores a line-free SHA-256 identity (tool language, rule ID, project-relative path, and either symbol plus declaration ordinal or normalized message) and a count. See `CHANGELOG.md` for full details.
5. **Sensitive-data findings can no longer be baselined** — Generated baselines count them by rule without storing entries, paths, or messages, and hand-written baseline entries cannot suppress them. Fix the secret or add a reason-bearing entry under `sensitiveExclusions`.
6. **SARIF `partialFingerprints.gruffFingerprint` uses the durable identity, and secrets carry none** — Code-scanning alerts now survive edits above the reported line instead of closing and reopening on line shifts. Every existing alert re-keys once on upgrade, and two same-named declarations in one file become separate alerts. See `CHANGELOG.md` for full details.
7. **Scores change under the family's normalized scoring curve** — Each pillar now scores `floor + (100 - floor) / (1 + density / densityScale)`, where `density` divides weighted findings by evaluated Go files. Duplicating a codebase no longer lowers its grade. See `CHANGELOG.md` for full details.
8. **The composite score has two decimals and can be `null`** — `score.composite.score` changed from a truncated integer to a two-decimal number, so JSON consumers decoding an integer must widen the type. `score.composite.{score,grade}` and each `score.pillars[].{score,grade}` are `null` when zero Go files were evaluated (previously an empty or unparseable directory reported `100` / grade `A`).
9. **`score.pillars` lists every rule-backed pillar, not only those with findings** — Each row carries an `applicable` flag distinguishing a reachable clean pillar from an unreachable one. Consumers counting rows with findings should check `findings` instead of array length.
10. **Machine JSON adopts the family v3 envelopes** — Update analysis consumers for `gruff.analysis.v3`: read the composite from `score.composite.{score,grade}`, paths from `paths.{ignoredPaths,details,missingPaths}`, changed-region counts from `summary.suppressedFindings` and `diff.filteredFindings`, and Go-only rule and scanned-path data from the `go` extensions. See `CHANGELOG.md` for full details.
11. **Default scans use the family fallback policy** — Non-VCS fallbacks now defer to any governing `.gitignore`, committed control metadata stays scannable, and explicit supported files bypass Git and fallback exclusions. Use `paths.ignore` for project-only exclusions; VCS internals remain blocked even with `--include-ignored`.
12. **`list-rules --format json` renames `severity` to `defaultSeverity`** — Matches `gruff-php`, `gruff-py`, and `gruff-rs`. Only the rule catalogue changes: the analysis report's embedded rule list still uses `severity`, and `list-rules --format text` is unchanged.

13. **Per-command exit gates move from `minimumSeverity:` to `failOn:`** — A `0.5` config with a per-command `minimumSeverity:` map now exits `2` and directs you to `failOn` (which accepts `analyse`, `summary`, `report`, and `dashboard`). `minimumSeverity` remains a scalar display floor (`advisory`, `warning`, or `error` — never `none`) that hides lower-severity findings without altering exit codes, scores, or baselines (per ratified `gruff-spec/contracts/core/cli.v1.json`). Migrate older configs with `gruff-go migrate-config`, which writes to a new file and leaves the original untouched.
14. **Agent-hook output moves from `gruff.hook.v1` to `gruff.hook.v2`** — `contractVersion` increments and the envelope adds two required keys: `run` (mode, scope, operands, `analysedFiles`, applied baseline) and `suppressions` (one row per applied `sensitiveExclusions` entry, or `[]`). Exit codes are strictly `0` (clean), `1` (gated finding under `--fail-on`, `--fail-on-new`, or `--fail-on-diagnostics`), and `2` (run failure). Consumers validating exact key sets must accept the two new keys (`gruff-spec/contracts/core/hook.v2.json`).
15. **`summary` exits `0` unless gated** — `summary`'s default gate moves from `advisory` to `none`. CI jobs relying on `gruff-go summary` failing on findings must pass `--fail-on <severity>` or set `failOn.summary` in `.gruff-go.yaml` (configs written by an earlier `init` already set `summary: advisory`). `analyse` still defaults to `advisory`.
16. **SARIF results for secrets omit fingerprints** — `sensitive-data.*` SARIF results no longer emit `partialFingerprints` or `properties.fingerprint`, so code scanning tracks them by location only.
17. **Empty `--changed-ranges` is refused instead of scanning the whole tree** — Passing `--changed-ranges=` previously fell back to an unfiltered full scan and exited `0`. It now exits `2` with a `changed-region` diagnostic and zero findings on both `analyse` and `hook`. Callers computing dynamic ranges should skip invoking gruff when the range is empty (the shipped `gruff-code-quality.mjs` hook already does).
18. **The built-in lockfile skip is removed with the entropy rule** — It existed solely for `sensitive-data.high-entropy-string`, so no `builtInLockfile` audit rows are emitted.
19. **`sensitive-data.aws-access-key` also reports AWS session tokens** — In addition to long-term `AKIA` keys, temporary `ASIA` credentials now report. Runs gating on this rule may surface newly caught session tokens.
20. **Sensitive-data rules skip test, fixture, and example files** — Every sensitive-data rule (including `sensitive-data.pii-pattern`) skips files under `test`, `tests`, `__tests__`, `spec`, `testdata`, `fixtures`, or `examples` directories, or named like a test file, publishing each skip as a counted `source: "built-in"` audit row. Real credentials committed under those paths are no longer flagged. See `CHANGELOG.md` for full details.
21. **`security.sensitive-data-logging` is removed** — It was right on 0 of 16 judged findings in the 0.6.0 precision measurement. Any config naming it exits `2`: delete its `rules:` block or run `gruff-go init --force --reset`. Existing baseline rows stop matching (ADR-021).
22. **`security.sql-string-query` is removed** — It was right on 1 of 9 judged findings in the 0.6.0 precision measurement. Any config naming it exits `2`: delete its `rules:` block or run `gruff-go init --force --reset` (ADR-021).
23. **Seven rules move to opt-in** — `dependency.go-mod-local-replace`, `security.insecure-random-secret`, `sensitive-data.aws-access-key`, `sensitive-data.connection-string`, `sensitive-data.gcp-service-account`, `sensitive-data.github-token`, and `sensitive-data.google-api-key` each scored below 50% on fewer than ten findings. Set `rules.<id>.enabled: true` to turn any of them on; configs generated by `gruff-go init` before 0.6.0 already list them as enabled and keep them on (ADR-021).
24. **Two callable documentation rules are on by default** — `docs.missing-param-doc` and `docs.missing-return-doc` read doc-comment prose and flag unmentioned parameters (matching full names or meaningful camelCase/snake_case tokens in singular or plural form) and unexplained return values or error cases (accepting standard return words and idiomatic third-person Go verbs). They run by default — including under a `0.5.x` `init` config that lacks entries for them — while configs from an earlier 0.6.0 build that explicitly set `enabled: false` keep them off. Disable either with `rules.<id>.enabled: false`. On the 12-repo 0.6.0 precision corpus (before prose tightening), enabling both added 6,764 and 6,809 findings (13,155 → 26,998). With both disabled, the only change is that `docs.exported-symbol-comment` messages now list what the new comment should cover; baselines keep matching because function findings key on symbol name.
25. **Three low-precision checks are removed** — `naming.negated-boolean`, `test-quality.no-failure-path`, and `test-quality.skipped-test` no longer ship. Remove their IDs from config and baselines; configs naming them exit `2` as unknown rules (ADR-021).
26. **`security.open-redirect-candidate` moves to opt-in** — It produced only four findings on the 0.6.0 precision corpus before its false-positive fix (it no longer flags HTTPS upgrades to the request's own host and path), too few to verify default-on precision. Enable it with `rules.security.open-redirect-candidate.enabled: true`; earlier `init` configs keep it enabled.
27. **`security.request-body-without-limit` moves to opt-in** — It produced only seven findings on the 0.6.0 precision corpus before its false-positive fix (it no longer flags `http.RoundTripper` or `testing` helpers reading program-built requests), too few to verify default-on precision. Enable it with `rules.security.request-body-without-limit.enabled: true`; earlier `init` configs keep it enabled.
28. **Two rules measured on unseen code are removed** — `design.hotspot-file` was right on 0 of 25 judged findings and `maintainability.production-panic` on 12 of 50, below the 50% floor. Remove both IDs from config and baselines; configs naming either exit `2`. Composite scores may dip slightly because the `design` pillar no longer has a rule to count as clean.

## Upgrade workflow (`0.5.x` → `0.6.0`)

1. Read the list above and decide which breaks touch your project. A project with no committed
   baseline and no hand-written configuration is usually unaffected by all but the rule changes.
2. Upgrade the package:

   ```bash
   go get -tool github.com/blundergoat/gruff-go/cmd/gruff-go@v0.6.0
   ```

3. Migrate a 0.5 configuration to a new file with
   `gruff-go migrate-config --config .gruff-go.yaml --output gruff-0.6.yaml`.
   Review the reported removals, then use the migrated file with `--config` or
   install it as the project config after saving the original. A config that
   only lacks a schema version can still be regenerated with `gruff-go init --force`.
4. Carry a baseline forward rather than regenerating it, so previously reviewed findings stay
   reviewed. Run `gruff-go baseline --migrate-baseline <old path> --out <new path>`; it writes a separate
   file and leaves the old one untouched for a retreat. Review unmatched findings after migration. Only exact fingerprints and unambiguous legacy stable identities carry forward.
5. Re-run `gruff-go summary .` and compare the finding count with the one you had. A rule
   whose default changed will move it; a rule whose identity changed will not.

## Limitations

- A baseline generated before `0.6.0` cannot be read directly. Migrate it; do not hand-edit it.
- Sensitive-data findings are not baselineable in `0.6.0`. A project that had suppressed them through
  a baseline needs a reason-bearing configuration exclusion instead.
- Identities change once, at this release. A finding you had already reviewed will look new until the
  migration has run.

## Retreat

If the upgrade costs more than it is worth today, pin the previous line and come back to it:

```bash
go get -tool github.com/blundergoat/gruff-go/cmd/gruff-go@v0.5.0
```

Keep the pre-upgrade baseline file. It stays readable by the line that produced it, and the migration
command reads it whenever you return.

## Reporting an upgrade regression

Open an issue at <https://github.com/blundergoat/gruff-go/issues> with the version you moved
from, the version you moved to, the command you ran, and the finding that changed. A finding that
moved without a break above it is a regression rather than an upgrade cost.
