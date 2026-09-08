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

1. **a config naming no `schemaVersion` is refused** — gruff-php, gruff-py, gruff-rs and gruff-ts all exit 2 on such a file; gruff-go accepted it and ran, so the same configuration got two different answers depending on which port read it. It now exits 2 naming the key, the expected version, and `gruff-go init --force`. `init` has always written the key, so only a hand-written config changes behaviour, and the recovery is one command that preserves existing tuning.
2. **`sensitive-data.high-entropy-string` is enabled by default at `minLength: 32` and `entropy: 4.2`** — It shipped opt-in at 20 and 4.5, so one rule id carried a different bar in every port. This is the ratified family contract: warning severity, medium confidence, enabled, with both thresholds configurable. The rest of this entry is in `CHANGELOG.md`.
3. **`sensitive-data.secret-pattern` no longer scans inside Go raw strings** — A backtick literal holds documentation, templates and sample payloads, so a secret-shaped line in one is an example rather than a credential. Interpreted strings, ordinary assignments and every other sensitive-data rule are unchanged; only this rule's view of backtick literals narrows. A project relying on the previous behaviour to catch secrets embedded in raw strings should keep them out of source instead.
4. **baselines move to the family `gruff.baseline.v3` file, and every finding identity changes once** — A baseline entry now stores one line-free identity and a count: sha256 over the tool language, native rule id, project-relative path, and a subject that is the symbol plus its declaration ordinal, or the message when no symbol is named. The rest of this entry is in `CHANGELOG.md`.
5. **sensitive-data findings can no longer be baselined** — A generated baseline counts them by rule and stores no entry, path, or message for them, and a hand-written entry cannot hide one: a secret stays visible and blocking until it is fixed or excluded with a reason under `sensitiveExclusions`.
6. **SARIF `partialFingerprints.gruffFingerprint` is the ratified identity, and a secret carries none** — Code scanning grouped alerts by the line-bearing fingerprint, so an alert closed and reopened every time code moved above it. It is now the same durable identity baseline matching reads: every existing alert closes and reopens once at this break, and each one then survives an ordinary edit. Two same-named declarations in one file, previously one alert, become two. The rest of this entry is in `CHANGELOG.md`.
7. **every score changes - the family adopts one normalized scoring formula** — A pillar is now `floor + (100 - floor) / (1 + density / densityScale)`, where `density` is the pillar's summed severity-by-confidence weight divided by the number of Go files that were actually evaluated. Scores no longer track project size: duplicating a project leaves its grade unchanged, where before it fell. The rest of this entry is in `CHANGELOG.md`.
8. **the composite is a two-decimal number and can be null** — `score.composite.score` was an integer truncated toward zero and is now a number carrying two decimals, so JSON consumers decoding it as an integer must widen the type. It, `score.composite.grade`, and each `score.pillars[].{score,grade}` are `null` when the run evaluated nothing at all: an empty directory, or one whose every Go file failed to parse, previously reported a perfect `100` and grade `A`.
9. **`score.pillars` lists every rule-backed pillar, not only the ones with findings** — Each row now carries an `applicable` flag, so a reachable pillar that reported nothing is visibly distinct from a pillar no rule can reach. Consumers counting rows to learn how many pillars had findings must read `findings` instead.
10. **machine JSON adopts the family v3 envelopes** — Update analysis consumers to accept `gruff.analysis.v3`, read the composite from `score.composite.{score,grade}`, paths from `paths.{ignoredPaths,details,missingPaths}`, changed-region counts from `summary.suppressedFindings` and `diff.filteredFindings`, and Go-only rule/scanned-path data from the named `go` extensions. The rest of this entry is in `CHANGELOG.md`.
11. **default scans use the family fallback policy** — Non-VCS fallbacks now defer to any governing `.gitignore`, committed control metadata stays scannable, and explicit supported files bypass Git and fallback exclusions. Use `paths.ignore` for project-only exclusions; VCS internals remain blocked even with `--include-ignored`.
12. **`list-rules --format json` names the severity field `defaultSeverity`** — It was `severity`, which gruff-php, gruff-py and gruff-rs already spelled `defaultSeverity`, so one rule listing carried two field names across the family. Only the rule catalogue changes: the analysis report's embedded rule list still names it `severity`. Update any consumer reading `rules[].severity` from `list-rules` output; `list-rules --format text` is unchanged.

13. **the per-command exit gate moves from `minimumSeverity:` to `failOn:`** — A `0.5` config carrying the per-command `minimumSeverity:` map is refused at load time with exit `2`, and the message names `failOn` as the key that gates the exit code. `failOn` accepts `analyse`, `summary`, `report` and `dashboard`. `minimumSeverity` still loads, but only as a scalar display floor that hides findings below one severity without changing the exit code, the score, or a baseline, and it takes `advisory`, `warning` or `error` rather than `none`. This is the ratified family contract (`gruff-spec/contracts/core/cli.v1.json`, ratified 2026-09-06: "minimumSeverity is display, failOn is the gate"). Recover with `gruff-go migrate-config`, which renames the key and leaves the original file untouched.

## Upgrade workflow (`0.5.x` → `0.6.0`)

1. Read the list above and decide which breaks touch your project. A project with no committed
   baseline and no hand-written configuration is usually unaffected by all but the rule changes.
2. Upgrade the package:

   ```bash
   go get -tool github.com/blundergoat/gruff-go/cmd/gruff-go@v0.6.0
   ```

3. Regenerate the configuration if you hand-wrote one: `gruff-go init --force` rewrites it
   with the current schema version and preserves the tuning you already had.
4. Carry a baseline forward rather than regenerating it, so previously reviewed findings stay
   reviewed. The command is in the CHANGELOG entry for the baseline break.
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
