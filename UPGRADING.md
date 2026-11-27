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

13. **Per-command exit gates move from `minimumSeverity:` to `failOn:`, and `--min-severity` is refused** - A `0.5` config with a per-command `minimumSeverity:` map now exits `2` and directs you to `failOn` (which accepts `analyse`, `summary`, `report`, and `dashboard`). `minimumSeverity` remains a scalar display floor (`advisory`, `warning`, or `error`, never `none`) that hides lower-severity findings without altering exit codes, scores, or baselines (per ratified `gruff-spec/contracts/core/cli.v1.json`). The CLI flag `--min-severity` is refused with exit `2` across `analyse`, `summary`, `report`, and `hook` in `0.6.0` (replace it with `--fail-on`; `--min-severity` returns in `0.7.0` as a display filter). Migrate older configs with `gruff-go migrate-config`, which writes to a new file and leaves the original untouched.
14. **Secret preview allowlists are removed (`allowlists.secretPreviews`, `sensitiveData.previewAllowlist`)** - Every `sensitive-data.*` rule now emits unconditional zero-payload markers. Any config carrying `allowlists.secretPreviews` (including the empty `[]` written by `0.5` `gruff-go init`) or `sensitiveData.previewAllowlist` now exits `2`; `gruff-go migrate-config` removes those keys automatically.
15. **Agent-hook output moves from `gruff.hook.v1` to `gruff.hook.v2`** - `contractVersion` increments and the envelope adds two required keys: `run` (mode, scope, operands, `analysedFiles`, applied baseline) and `suppressions` (audit rows for configured `sensitiveExclusions`, including zero-match entries, built-in test-path skips, and inline suppressions, or `[]`). Exit codes are strictly `0` (clean), `1` (gated finding under `--fail-on`, `--fail-on-new`, or `--fail-on-diagnostics`), and `2` (run failure). Consumers validating exact key sets must accept the two new keys (`gruff-spec/contracts/core/hook.v2.json`).
16. **`summary` exits `0` unless gated** - `summary`'s default gate moves from `advisory` to `none`. CI jobs relying on `gruff-go summary` failing on findings must pass `--fail-on <severity>` or set `failOn.summary` in `.gruff-go.yaml` (configs written by an earlier `init` already set `summary: advisory`). `analyse` still defaults to `advisory`.
17. **SARIF results for secrets omit fingerprints** - `sensitive-data.*` SARIF results no longer emit `partialFingerprints` or `properties.fingerprint`, so code scanning tracks them by location only.
18. **Empty `--changed-ranges` is refused instead of scanning the whole tree** - Passing `--changed-ranges=` previously fell back to an unfiltered full scan and exited `0`. It now exits `2` with a `changed-region` diagnostic and zero findings on both `analyse` and `hook`. Callers computing dynamic ranges should skip invoking gruff when the range is empty (the shipped `gruff-code-quality.mjs` hook already does).
19. **The built-in lockfile skip is removed with the entropy rule** - It existed solely for `sensitive-data.high-entropy-string`, so no `builtInLockfile` audit rows are emitted.
20. **`sensitive-data.aws-access-key` also reports AWS session tokens** - In addition to long-term `AKIA` keys, temporary `ASIA` credentials now report. Runs gating on this rule may surface newly caught session tokens.
21. **Sensitive-data rules default to `warning` and skip test, fixture, and example paths** - All 15 `sensitive-data.*` rules now default to `warning` (13 moved from `error` to `warning`) for family parity (`--fail-on=error` no longer fails on default secret findings unless `severity: error` is configured). Every sensitive-data rule (and `security.*` / `dependency.go-mod-*` rule) also skips files under `test`, `tests`, `__tests__`, `spec`, `testdata`, `fixtures`, or `examples` directories, or named like a test file, publishing each skip as a counted `source: "built-in"` audit row. Real credentials committed under those paths are no longer flagged. See `CHANGELOG.md` for full details.
22. **Size and complexity findings report in two bands** - Units between 1x and 1.5x of their limit emit as `advisory` (`limitBand: lower`) regardless of configured severity, so `--fail-on=warning` and `--fail-on=error` no longer fail on lower-band notices; units at 1.5x or above keep their configured severity (`limitBand: upper`). Messages and fingerprints stay unchanged so baselines keep matching.
23. **`security.sensitive-data-logging` and `security.sql-string-query` are removed** - They scored 0/16 and 1/9 in the 0.6.0 precision measurement. Any config naming them exits `2`: delete their `rules:` entries or run `gruff-go migrate-config` / `init --force --reset` (ADR-021).
24. **Ten rules move to opt-in** - `dependency.go-mod-local-replace`, `security.insecure-random-secret`, `sensitive-data.aws-access-key`, `sensitive-data.connection-string`, `sensitive-data.gcp-service-account`, `sensitive-data.github-token`, `sensitive-data.google-api-key`, `complexity.cyclomatic` (23/40 upper-band), `security.open-redirect-candidate` (4 findings pre-fix), and `security.request-body-without-limit` (7 findings pre-fix) now default to `DefaultEnabled: false`. Set `rules.<id>.enabled: true` to turn any of them on; configs generated by `gruff-go init` before `0.6.0` already list them as enabled and keep them on (ADR-021).
25. **Callable documentation and duplicate-test rules are on by default** - `docs.missing-param-doc`, `docs.missing-return-doc`, and `test-quality.duplicate-test-body` now ship `DefaultEnabled: true` (including under `0.5.x` `init` configs that lack entries for them). Disable any with `rules.<id>.enabled: false`. On the 12-repo 0.6.0 precision corpus (before prose tightening), enabling both callable-doc rules added 6,764 and 6,809 findings (13,155 → 26,998).
26. **Rule confidence follows measured precision** - Every finding now carries its rule's catalogue confidence, changing 8 rules' weights (`complexity.cognitive` high→low; `docs.exported-symbol-comment`, `docs.suppression-without-rationale`, `naming.identifier-quality` medium→high; `security.http-client-no-timeout`, `security.tls-insecure-config`, `test-quality.sleep-in-test`, `test-quality.tempdir-misuse` high→medium), which affects scores and `--min-confidence` gates. Test-file size softening now changes severity only.
27. **Five more low-precision rules are removed** - `naming.negated-boolean`, `test-quality.no-failure-path`, `test-quality.skipped-test`, `design.hotspot-file` (0/25), and `maintainability.production-panic` (12/50) no longer ship. Remove their IDs from configs and baselines (`gruff-go migrate-config` strips them automatically); configs naming any retired rule exit `2` (ADR-021). Composite scores may dip slightly because the `design` pillar no longer has a rule to count as clean.
28. **Methods on generic types normalize to `Type.Method`** - Receiver methods such as `(*Stack[T]).Push` now report as `Stack.Push` everywhere (one-time identity change), and exported generic methods are now checked by `docs.exported-symbol-comment`. The opt-in `naming.get-prefix` and `naming.receiver-consistency` also name every method `Type.Method`; re-review their findings after `--migrate-baseline`, which reports their 0.5 reviews as new.
29. **Local dashboard rejects non-loopback `Host` headers, and scans reject unrelated external project targets** - Local-only dashboard binds now reject non-loopback `Host` headers with `403` unless `--allow-public` is set, and scanning multiple targets from unrelated external projects now exits `2` (`target-error`); scan each project separately.
30. **Prose and malformed suppression directives no longer suppress findings** - Inline suppression matching now parses real Go, YAML, and dotenv comments and rejects malformed or prose directives; use a supported `#nosec`, `//nolint`, or `# zizmor: ignore[...]` directive.
31. **Duplicate canonical + legacy alias rule configs and mixed staged/unstaged `--diff staged` runs fail closed** - Listing both a canonical rule ID and its legacy hyphenated alias under `rules:` now exits `2` deterministically, and `--diff staged` exits `2` when staged files also carry unstaged edits on disk instead of evaluating post-stage bytes.

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
   `analyse` auto-applies `gruff-baseline.json` and exits `2` while that file is still a 0.5 baseline,
   so move the old file aside and put the migrated one in its place, or pass `--baseline <new path>`.
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
