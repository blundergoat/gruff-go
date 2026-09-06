# Configuration

`gruff-go` is configurable through a single project-root file: `.gruff-go.yaml`. The file is **strict** - unknown keys, unknown rule IDs, unknown pillars, and out-of-range thresholds all fail closed with a clear diagnostic. The schema is versioned: `gruff-go.config.v0.1`.

## Discovery

```bash
# Auto-load from project root (the default).
gruff-go analyse .

# Use an explicit file.
gruff-go analyse --config configs/strict.yaml .

# Skip discovery entirely (use only built-in defaults).
gruff-go analyse --no-config .
```

`--config` and `--no-config` are mutually exclusive - pass one or neither, never both.

## Full schema

```yaml
# .gruff-go.yaml
minimumSeverity:    # per-command exit-code threshold; see ADR-010
  analyse: advisory # CI gating command - default `advisory` (fail on anything)
  summary: advisory # CI gating command - default `advisory`
  report: none      # artifact generator - default `none` (never fail on findings)
  dashboard: none   # artifact generator - default `none`

paths:
  ignore: []          # extra path prefixes/globs to skip; merged with built-in ignores

allowlists:
  acceptedAbbreviations: []   # identifiers naming rules treat as words (e.g. ID, HTTP); case-insensitive

sensitiveExclusions: []       # suppress one sensitive-data rule in one file, with a written reason

selection:
  rules: []           # if non-empty, only these rule IDs run (allowlist)
  excludeRules: []    # remove these rule IDs (denylist; layered on top of `rules`)
  pillars: []         # if non-empty, only findings in these pillars run
  excludePillars: []  # remove findings in these pillars

rules:
  # Per-rule overrides. Every key is optional; only specified keys override defaults.
  <rule-id>:
    enabled: true | false
    threshold: <int>            # convenience for single-threshold rules
    thresholds:                 # for rules with named thresholds
      <name>: <int>
    severity: advisory | warning | error
    options:                    # rule-specific opaque map
      <key>: <value>
```

## Section reference

### `minimumSeverity`

Per-command exit-code threshold. Each key is a `gruff-go` subcommand that gates exit codes (`analyse`, `summary`, `report`, `dashboard`); each value is one of `advisory | warning | error | none`. `none` means "report findings, never exit 1" - useful for artifact-generation commands (`report`, `dashboard`) where the consumer wants the HTML/JSON output regardless of whether anything tripped a gate.

```yaml
minimumSeverity:
  analyse: warning      # default `advisory`: fail on anything
  summary: warning      # default `advisory`
  report: none          # default `none`: never fail on findings
  dashboard: advisory   # default `none`: gate this dashboard like CI
```

**Precedence rule** (locked in [ADR-010](../.goat-flow/learning-loop/decisions/ADR-010-per-command-minimum-severity.md)):

```
CLI flag (--min-severity / --fail-on)  >  minimumSeverity.<cmd>  >  binary default
```

The binary defaults (when neither the CLI flag nor the config block supply a value) are:

| Command   | Default    | Reason |
| --------- | ---------- | ------ |
| `analyse` | `advisory` | CI gating; fail on anything |
| `summary` | `advisory` | CI gating |
| `report`  | `none`     | artifact generator; finding gate disabled |
| `dashboard` | `none`   | artifact generator |

The block is additive: omitting any key falls back to the binary default. Omitting the entire block also works.

`none` is the canonical off-switch value. Legacy 5-bucket names (`medium`, `low`, `critical`, `high`, `info`) and alternative off-switch names (`never`, `off`, `disabled`) are rejected at load time per the no-legacy-compat policy.

### `paths.ignore`

A list of additional path prefixes or globs to skip during discovery. VCS internals (`.git/`, `.hg/`, `.svn/`) are always blocked. When no `.gitignore` governs a candidate, the family fallback skips `.fleet/`, `.idea/`, `.vscode/`, `build/`, `coverage/`, `dist/`, `node_modules/`, and `vendor/` at any depth; any `.gitignore` from the scan root through the candidate's parent takes ownership of those non-VCS names. Committed control metadata such as `.agents/`, `.claude/`, `.codex/`, `.github/`, and `.goat-flow/` remains scannable unless Git or this config excludes it. Explicit supported files bypass Git and fallback exclusions, but never VCS internals or `paths.ignore`. Generated Go files whose leading comments contain both `generated` and `DO NOT EDIT` retain their existing generated-file handling.

```yaml
paths:
  ignore:
    - "third_party/"
    - "internal/generated/"
    - "api/*_pb.go"
```

Patterns are repository-relative slash paths; a leading `./` is normalised away. Exact paths and segment globs use Go's `path.Match` semantics, so `*.go` matches a root file but not `pkg/main.go`, and `api/*.go` does not cross another `/`. A single trailing `/**` matches the named directory and every descendant. A trailing slash is exactly equivalent shorthand: `internal/generated/` and `internal/generated/**` make the same decision in directory walks, explicit-file scans, diff modes, `check-ignore`, and secret-preview authorisation.

Config validation rejects empty or escaping patterns, POSIX-absolute paths, Windows drive-qualified or backslash-containing paths, malformed glob classes, and `**` anywhere except one trailing recursive suffix. General recursive-glob forms such as `**/*.go` and `pkg/**/generated.go` are not accepted.

`paths.ignore` is authoritative for every analyse shape: directory walks, explicit file operands, and changed-region scans such as `--diff`, `--since`, and `--changed-ranges`. `--include-ignored` opts into gitignored and non-VCS fallback skips only; it never overrides config `paths.ignore` or the VCS-internals boundary.

In `analyse --format json`, config-ignored paths appear as bare strings under `paths.ignoredPaths` and as detailed objects under `paths.skipped[]` with `reason: "config-ignore"`, `source: "config"`, and the matching `pattern`. The bare list is nested under `paths` in gruff-go to match the Rust and TypeScript ports while preserving the detailed skip objects for existing consumers.

### `allowlists.acceptedAbbreviations`

Identifiers that naming rules will treat as accepted words. `naming.acronym-case` uses this list to suppress configured initialism findings for project-specific terms.

```yaml
allowlists:
  acceptedAbbreviations:
    - ID
    - HTTP
    - JSON
    - URL
    - AST
    - DTO
```

Entries are case-insensitive: `ID` and `id` resolve to the same allowlist key. The validator rejects only blank entries; mixed-case values load successfully and are normalised to lowercase before matching. The same key name appears in sibling gruff ports but is consumed by different rules - see `.goat-flow/learning-loop/footguns/setup.md` for the cross-port consumer matrix.

### Sensitive-data markers are not configurable

A sensitive-data finding carries a marker, never a payload: the bare `[redacted]`, a fixed category such as
`[redacted:aws-access-key]`, `[redacted:private-key]`, `[redacted:email]` or `[redacted:ssn]`, or a connection
marker naming only its already-public scheme (`[redacted:connection-string:postgres]`). Generic-assignment and
entropy findings are always `[redacted]`, because they classify nothing the user can act on.

gruff-go emits the most specific marker its detector already classified, on every path and under every
configuration. FAMILY-CONTRACT.md section 5 ratifies that: every marker is zero-payload by construction, so gating
one behind configuration bought no confidentiality. The 0.5 key `allowlists.secretPreviews` is therefore removed,
and a configuration carrying it — even as an empty list — is refused with that explanation rather than silently
ignored. `gruff-go migrate-config` deletes it.

No marker exposes provider payload characters, JWT segments, private-key bytes, connection user, password, host,
path or query, or PII/PHI identifier characters. GCP primary and secondary fields are marked independently.

### `sensitiveExclusions`

The only way to suppress a sensitive-data finding. It is a separate top-level
section rather than an option on `selection` or `rules` so the ban on matching a
finding's message or value is structural: there is no key to add it back.

```yaml
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key    # exactly one rule ID, sensitive-data pillar only
    path: internal/rule/testdata/aws.env   # exactly one project-relative path
    symbol: Fixtures.AWSSample             # optional; narrows the scope further
    reason: Synthetic key used by the loader fixture; not a live credential.
```

**Entries are written by hand.** No reported marker, preview, remediation, or
matched value is ever converted into an exclusion for you, and none is ever
copied into one. `reason` and `path` come from your configuration, so they are
the only free text an exclusion publishes.

**Scope.** An entry suppresses every occurrence of that one rule in that one
file. The same rule in another file keeps reporting, and another rule in the
same file keeps reporting. Adding `symbol` narrows the scope to findings
carrying that exact symbol; no sensitive-data rule stamps a symbol today, so an
entry carrying one correctly matches nothing.

**An entry that matches nothing is not an error.** It reports `suppressed: 0`,
so fixing the underlying problem never breaks your build.

**Every entry is counted.** `analyse --format json` publishes one row per entry
under `suppressions`, and both text surfaces that apply the exclusions -
`analyse` and `summary` - print the same total:

```json
{"index": 0, "rule": "sensitive-data.aws-access-key", "paths": ["internal/rule/testdata/aws.env"], "symbol": null, "reason": "Synthetic key used by the loader fixture; not a live credential.", "suppressed": 2}
```

```text
suppressed findings: 2 via sensitiveExclusions[0] sensitive-data.aws-access-key: 2 (Synthetic key used by the loader fixture; not a live credential.)
```

A suppressed finding leaves the finding list, the counts, the score, and the
exit code, exactly like the baseline channel - but it is never invisible,
because the audit row survives.

`summary --format json` is the one exception: it applies the exclusions but
publishes no count, because the `gruff.summary.v2` envelope has no suppression
field yet. Use the text summary or `analyse --format json` for the audit.

Each of the following is a fatal `config:` diagnostic naming the entry index and
the offending key, and exits `2`:

- `rule` missing, empty, or carrying a wildcard, glob, or regular-expression metacharacter.
- `rule` naming a pillar or selector (`sensitive-data`, `sensitive-data.*`) rather than one rule ID.
- `rule` naming an unknown rule ID.
- `rule` naming a known rule ID outside the sensitive-data pillar.
- `path` missing, empty, absolute, containing `..`, or containing a glob metacharacter.
- Any key outside `rule`, `path`, `symbol`, and `reason` - in particular `message_contains`, `messageContains`, `value`, and `preview`.
- `reason` missing, empty, or whitespace-only.
- A second entry repeating an earlier entry's `rule`, `path`, and `symbol`, because two entries claiming one scope would split the audit count arbitrarily.

Sensitive-data markers are unrelated to suppression: they control display text
only, and nothing configures them.

### `selection`

Four lists that change which rules execute. `rules` and `pillars` create an allowlist when non-empty; `excludeRules` and `excludePillars` remove rules after that allowlist is applied. Because unselected rules do not run, config selection changes findings, score, and exit code.

```yaml
selection:
  rules: []                           # run only these rule IDs when non-empty
  excludeRules: ["docs.package-comment"] # disable these rule IDs
  pillars: ["security", "complexity"] # run only these pillars when non-empty
  excludePillars: ["test-quality"]    # disable these pillars
```

The CLI flags `--include-rules`, `--exclude-rules`, `--include-pillars`, and `--exclude-pillars` are different: they are display-only filters. They hide rendered findings after analysis, but score and exit code still use the full unfiltered finding set.

### `rules.<rule-id>`

Per-rule overrides. Every field is optional:

- `enabled` - toggle a rule on or off. Most built-in rules are enabled by default; opt-in rules start disabled and can be enabled with `true`.
- `threshold` - shorthand for rules with a single named threshold (most metric rules use `maxComplexity`, `maxLength`, `maxParameters`, etc.; see [`docs/rules.md`](rules.md) for each rule's threshold key).
- `thresholds` - for rules with multiple thresholds, name them explicitly.
- `severity` - one of `advisory`, `warning`, or `error`. The vocabulary collapsed from the previous five-bucket scale in v0.2.0 (ADR-009); old names (`critical`, `high`, `medium`, `low`, `info`, `notice`, `warn`) are rejected at load.
- `options` - opaque per-rule map for rules with bespoke options.

Default size rules have one built-in calibration: when a size rule's default severity is warning or error, findings in `_test.go` files are still emitted with the same threshold, message, metadata, and fingerprint identity, but report as `advisory` severity / `medium` confidence. This keeps long table-driven or integration tests visible without making them equivalent to production size debt. Advisory defaults are already softened, and any configured `severity` applies to test files as configured and disables the downranking for the overridden rule.

Examples:

```yaml
rules:
  # Tighten cyclomatic complexity and bump severity.
  complexity.cyclomatic:
    threshold: 12
    severity: error

  # Disable the package comment rule for this repo.
  docs.package-comment:
    enabled: false

  # Disable a rule that does not fit this project.
  naming.package-underscore:
    enabled: false

  # Raise shell-routed command execution to a hard-error gate.
  security.shell-command:
    enabled: true
    severity: error

  # Require doc comments for module-private exported symbols too.
  docs.exported-symbol-comment:
    enabled: true
    options:
      ignoreInternalPackages: false

  # Enforce a stricter maintainer-comment rubric on selected files.
  # Threshold defaults to 1 (one-line package summary OK); set to 2 for the older two-line floor.
  # minWordsBeyondSymbol is opt-in: when set, comments that only restate the symbol name are rejected.
  # _test.go files: requireConstComments and requireVarComments are automatically scoped away even
  # when ignoreTests is false. Function, named-type, and package-summary checks still apply.
  docs.comment-rubric:
    enabled: true
    threshold: 2
    severity: advisory
    options:
      includePaths:
        - internal/analysis/report.go
      minWordsBeyondSymbol: 3
      requirePackageSummary: true
      requireFunctionComments: true
      requireNamedTypeComments: true
      requireConstComments: true
      requireVarComments: true

  # Require doc comments on every exported field of configuration-style struct types.
  # No-op until includePaths selects the config/schema files to enforce.
  docs.config-field-comment:
    enabled: true
    severity: advisory
    options:
      includePaths:
        - internal/config/config.go
```

If a rule ID doesn't exist, the loader rejects the file with `config: unknown rule "x.y"`. Run `gruff-go list-rules` to print the current registry.

## Strict validation

The built-in parser accepts the mapping and scalar-list shapes used by the schema above, plus the dash-introduced mapping items `sensitiveExclusions` needs; anything richer is outside this intentionally small YAML subset. A quoted list item stays a scalar even when it contains a colon, so existing string lists are unaffected. Mapping keys must be unique within their own scope at every nesting depth. The same key may appear in separate mappings, but a repeated key in one mapping fails instead of silently replacing its earlier value.

Duplicate-key diagnostics report only the parsed key and the original 1-based lines of its first and repeated definitions. Blank and comment-only lines still count toward those source line numbers. Neither duplicate diagnostics nor structural indentation/list/key errors echo the YAML value or raw source line, so a malformed secret-bearing configuration does not copy that value into stderr or hook output.

The loader rejects:

- Duplicate mapping keys within the same root or nested mapping.
- Unknown top-level keys.
- Unknown nested keys (`rules.<id>.bogus`, `selection.unexpected`).
- Unknown rule IDs in `selection.rules` or `selection.excludeRules`.
- Unknown pillar names in `selection.pillars` or `selection.excludePillars`.
- Non-integer or negative threshold values.
- A rule config that combines `threshold` and `thresholds`.
- Severity values outside `advisory / warning / error`. The pre-v0.2.0 names (`critical`, `high`, `medium`, `low`, `info`, `notice`, `warn`) are rejected with `unknown severity "<name>"`.
- Blank entries in `allowlists.acceptedAbbreviations`. Case is no longer enforced - the validator only rejects empty / whitespace-only entries.
- Any `sensitiveExclusions` entry that breaks the rule, path, key-set, rationale, or uniqueness contract listed under that section above.

Any of these failures emits a `config:` diagnostic and exits the scan with code `2`. Treat config errors as build breaks, not silent warnings.

## Backwards-compatible rule IDs

`gruff-go` emits **dotted** rule IDs (`size.file-length`, `complexity.cyclomatic`). Older configs that use legacy hyphenated IDs (`size-file-length`) or `documentation.*` aliases are still accepted and canonicalised on load. New configs should use the dotted form.

## Where defaults live

The default rule pack, default thresholds, and default severities live under `internal/rule/`; the built-in discovery ignore list lives under `internal/source/`. Run `gruff-go list-rules --format json` to inspect the resolved registry, including any overrides applied by your config.
