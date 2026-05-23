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
paths:
  ignore: []          # extra path prefixes/globs to skip; merged with built-in ignores

allowlists:
  acceptedAbbreviations: []   # uppercase identifiers naming rules treat as words (e.g. ID, HTTP)
  secretPreviews: []          # literal strings that look like secrets but are documented dummies

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
    severity: info | low | medium | high | critical | notice | warning | warn | error
    options:                    # rule-specific opaque map
      <key>: <value>
```

## Section reference

### `paths.ignore`

A list of additional path prefixes or globs to skip during discovery. `gruff-go` already skips VCS directories (`.git/`), non-application metadata directories (`.agents/`, `.claude/`, `.codex/`, `.github/`, `.goat-flow/`), dependency caches (`vendor/`, `node_modules/`), and generated Go files (`//go:generate`-emitted with the standard `Code generated … DO NOT EDIT.` header). The entries you add are layered on top.

```yaml
paths:
  ignore:
    - "third_party/"
    - "internal/generated/"
    - "**/*_pb.go"
```

Patterns are matched against the project-relative path. Trailing slashes mark directory prefixes; glob characters (`*`, `**`, `?`) follow standard `path/filepath.Match` semantics.

### `allowlists.acceptedAbbreviations`

Uppercase identifiers that naming rules will treat as accepted words. `naming.acronym-case` uses this list to suppress configured initialism findings for project-specific terms.

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

Entries must be uppercase. Mixed-case values are rejected with a `config:` diagnostic.

### `allowlists.secretPreviews`

Literal strings the `sensitive-data.secret-pattern` rule should not flag. Use this for documented sample tokens, public test keys, and CI placeholder values that the rule's pattern detection would otherwise call out.

```yaml
allowlists:
  secretPreviews:
    - "ghp_exampletokenforreadmes"
    - "AKIAIOSFODNN7EXAMPLE"
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

- `enabled` - toggle a rule on or off. All built-in rules are enabled by default except `docs.config-field-comment`; set `false` to disable a default-enabled rule or `true` to opt into the config-field rule.
- `threshold` - shorthand for rules with a single named threshold (most metric rules use `maxComplexity`, `maxLength`, `maxParameters`, etc.; see [`docs/rules.md`](rules.md) for each rule's threshold key).
- `thresholds` - for rules with multiple thresholds, name them explicitly.
- `severity` - canonical severities `info`, `low`, `medium`, `high`, or `critical`. Config also accepts gruff-family aliases: `notice` maps to `low`, `warning` / `warn` map to `medium`, and `error` maps to `high`.
- `options` - opaque per-rule map for rules with bespoke options.

Default size rules have one built-in calibration: when `size.file-length` or `size.function-length` uses medium severity, findings in `_test.go` files are still emitted with the same threshold, message, metadata, and fingerprint identity, but report as `low` severity / `medium` confidence. This keeps long table-driven or integration tests visible without making them equivalent to production size debt. A non-medium configured `severity` applies to test files too and disables that default downranking for the overridden rule.

Examples:

```yaml
rules:
  # Tighten cyclomatic complexity and bump severity.
  complexity.cyclomatic:
    threshold: 12
    severity: high

  # Disable the package comment rule for this repo.
  docs.package-comment:
    enabled: false

  # Disable a rule that does not fit this project.
  naming.package-underscore:
    enabled: false

  # Raise shell-routed command execution to a high-severity gate.
  security.shell-command:
    enabled: true
    severity: high

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
    severity: low
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
  # Default-disabled; enable per-path via includePaths so general struct fields stay un-enforced.
  docs.config-field-comment:
    enabled: true
    severity: low
    options:
      includePaths:
        - internal/config/config.go
```

If a rule ID doesn't exist, the loader rejects the file with `config: unknown rule "x.y"`. Run `gruff-go list-rules` to print the current registry.

## Strict validation

The loader rejects:

- Unknown top-level keys.
- Unknown nested keys (`rules.<id>.bogus`, `selection.unexpected`).
- Unknown rule IDs in `selection.rules` or `selection.excludeRules`.
- Unknown pillar names in `selection.pillars` or `selection.excludePillars`.
- Non-integer or negative threshold values.
- A rule config that combines `threshold` and `thresholds`.
- Severity values outside `info / low / medium / high / critical` and their accepted aliases (`notice`, `warning`, `warn`, `error`).
- Lowercase abbreviations in `allowlists.acceptedAbbreviations`.

Any of these failures emits a `config:` diagnostic and exits the scan with code `2`. Treat config errors as build breaks, not silent warnings.

## Backwards-compatible rule IDs

`gruff-go` emits **dotted** rule IDs (`size.file-length`, `complexity.cyclomatic`). Older configs that use legacy hyphenated IDs (`size-file-length`) or `documentation.*` aliases are still accepted and canonicalised on load. New configs should use the dotted form.

## Where defaults live

The default rule pack, default thresholds, and default severities live under `internal/rule/`; the built-in discovery ignore list lives under `internal/source/`. Run `gruff-go list-rules --format json` to inspect the resolved registry, including any overrides applied by your config.
