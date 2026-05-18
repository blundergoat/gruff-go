# Configuration

`gruff-go` is configurable through a single project-root file: `.gruff-go.yaml`. The file is **strict** — unknown keys, unknown rule IDs, unknown pillars, and out-of-range thresholds all fail closed with a clear diagnostic. The schema is versioned: `gruff-go.config.v0.1`.

## Discovery

```bash
# Auto-load from project root (the default).
gruff-go analyse .

# Use an explicit file.
gruff-go analyse --config configs/strict.yaml .

# Skip discovery entirely (use only built-in defaults).
gruff-go analyse --no-config .
```

`--config` and `--no-config` are mutually exclusive — pass one or neither, never both.

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
    severity: info | low | medium | high | critical
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
  excludePillars: ["modernisation"]   # disable these pillars
```

The CLI flags `--include-rules`, `--exclude-rules`, `--include-pillars`, and `--exclude-pillars` are different: they are display-only filters. They hide rendered findings after analysis, but score and exit code still use the full unfiltered finding set.

### `rules.<rule-id>`

Per-rule overrides. Every field is optional:

- `enabled` — turn a default-disabled rule on (or a default-enabled rule off).
- `threshold` — shorthand for rules with a single named threshold (most metric rules use `maxComplexity`, `maxLength`, `maxParameters`, etc.; see [`docs/rules.md`](rules.md) for each rule's threshold key).
- `thresholds` — for rules with multiple thresholds, name them explicitly.
- `severity` — `info`, `low`, `medium`, `high`, or `critical`.
- `options` — opaque per-rule map for rules with bespoke options.

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

  # Turn on an opt-in expansion rule.
  naming.package-underscore:
    enabled: true

  # Custom shell-command rule allowlist.
  security.shell-command:
    enabled: true
    options:
      allowList:
        - "git"
        - "go"

  # Require doc comments for module-private exported symbols too.
  docs.exported-symbol-comment:
    enabled: true
    options:
      ignoreInternalPackages: false

  # Enforce a stricter maintainer-comment rubric on selected files.
  docs.comment-rubric:
    enabled: true
    threshold: 2
    severity: low
    options:
      includePaths:
        - internal/analysis/report.go
      requirePackageSummary: true
      requireFunctionComments: true
      requireNamedTypeComments: true
      requireConstComments: true
      requireVarComments: true
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
- Severity values outside `info / low / medium / high / critical`.
- Lowercase abbreviations in `allowlists.acceptedAbbreviations`.

Any of these failures emits a `config:` diagnostic and exits the scan with code `2`. Treat config errors as build breaks, not silent warnings.

## Backwards-compatible rule IDs

`gruff-go` emits **dotted** rule IDs (`size.file-length`, `complexity.cyclomatic`). Older configs that use legacy hyphenated IDs (`size-file-length`) or `documentation.*` aliases are still accepted and canonicalised on load. New configs should use the dotted form.

## Where defaults live

The default rule pack, default thresholds, default severities, and the built-in ignore list are all sourced from `internal/rule/builtin.go` and `internal/source/source.go`. Run `gruff-go list-rules --format json` to inspect the resolved registry, including any overrides applied by your config.
