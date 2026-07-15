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
  secretPreviews: []          # authorise fixed category/scheme markers; never payload bytes

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

A list of additional path prefixes or globs to skip during discovery. `gruff-go` already skips VCS directories (`.git/`), non-application metadata directories (`.agents/`, `.claude/`, `.codex/`, `.github/`, `.goat-flow/`), dependency caches (`vendor/`, `node_modules/`), and generated Go files whose leading comments contain both `generated` and `DO NOT EDIT`. The entries you add are layered on top.

```yaml
paths:
  ignore:
    - "third_party/"
    - "internal/generated/"
    - "api/*_pb.go"
```

Patterns are repository-relative slash paths; a leading `./` is normalised away. Exact paths and segment globs use Go's `path.Match` semantics, so `*.go` matches a root file but not `pkg/main.go`, and `api/*.go` does not cross another `/`. A single trailing `/**` matches the named directory and every descendant. A trailing slash is exactly equivalent shorthand: `internal/generated/` and `internal/generated/**` make the same decision in directory walks, explicit-file scans, diff modes, `check-ignore`, and secret-preview authorisation.

Config validation rejects empty or escaping patterns, POSIX-absolute paths, Windows drive-qualified or backslash-containing paths, malformed glob classes, and `**` anywhere except one trailing recursive suffix. General recursive-glob forms such as `**/*.go` and `pkg/**/generated.go` are not accepted.

`paths.ignore` is authoritative for every analyse shape: directory walks, explicit file operands, and changed-region scans such as `--diff`, `--since`, and `--changed-ranges`. `--include-ignored` opts into gitignored and built-in default skips only; it never overrides config `paths.ignore`.

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

### `allowlists.secretPreviews`

Path globs that authorise additional non-secret structure in sensitive-data
preview metadata. Authorisation is deny-by-default: an empty list and a path
that does not match both emit the constant `[redacted]`. A matching path may
emit only a fixed category marker (for example `[redacted:aws-access-key]`,
`[redacted:private-key]`, `[redacted:email]`, or `[redacted:ssn]`) or a
connection marker containing only its already-public scheme (for example
`[redacted:connection-string:postgres]`). Generic and entropy findings stay
`[redacted]` even on matching paths.

No state exposes provider payload characters, JWT segments, private-key body or
header bytes, connection user/password/host/path/query, or PII/PHI identifier
characters. Primary and secondary GCP previews are authorised independently by
the same path decision and render as `[redacted:gcp-service-account]` plus
`[redacted:private-key]` only on a match.

This is an output-control allowlist only: it does not suppress findings, change
scoring, or mark sample secrets as safe. Use `selection.excludeRules`,
`paths.ignore`, or an inline suppression when a finding should intentionally be
hidden.

```yaml
allowlists:
  secretPreviews:
    - "docs/**"
    - "internal/rule/testdata/**"
```

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

Default size rules have one built-in calibration: when a size rule uses warning severity, findings in `_test.go` files are still emitted with the same threshold, message, metadata, and fingerprint identity, but report as `advisory` severity / `medium` confidence. This keeps long table-driven or integration tests visible without making them equivalent to production size debt. Advisory defaults such as `size.file-length` are already softened, and a non-warning configured `severity` applies to test files too and disables warning downranking for the overridden rule.

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

The built-in parser accepts the mapping and scalar-list shapes used by the schema above; mapping-valued list items are outside this intentionally small YAML subset. Mapping keys must be unique within their own scope at every nesting depth. The same key may appear in separate mappings, but a repeated key in one mapping fails instead of silently replacing its earlier value.

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

Any of these failures emits a `config:` diagnostic and exits the scan with code `2`. Treat config errors as build breaks, not silent warnings.

## Backwards-compatible rule IDs

`gruff-go` emits **dotted** rule IDs (`size.file-length`, `complexity.cyclomatic`). Older configs that use legacy hyphenated IDs (`size-file-length`) or `documentation.*` aliases are still accepted and canonicalised on load. New configs should use the dotted form.

## Where defaults live

The default rule pack, default thresholds, and default severities live under `internal/rule/`; the built-in discovery ignore list lives under `internal/source/`. Run `gruff-go list-rules --format json` to inspect the resolved registry, including any overrides applied by your config.
