# Rule Catalog

`gruff-go` v0.1 ships **12 rules** across **8 pillars**. Five are enabled by default; the rest are opt-in so existing repositories can phase them in without baseline churn.

Print the live registry any time with `gruff-go list-rules` (text) or `gruff-go list-rules --format json` (full metadata including thresholds and severities).

## Default-enabled rules

These run unless explicitly disabled via `selection.excludeRules` or `rules.<id>.enabled: false`.

| Rule ID | Pillar | Severity | Default threshold | Description |
|---------|--------|----------|-------------------|-------------|
| [`complexity.cyclomatic`](#complexitycyclomatic) | complexity | medium | `maxComplexity: 20` | Functions whose branch count exceeds the threshold. |
| [`docs.package-comment`](#docspackage-comment) | documentation | low | — | Packages with no package-level comment in any file. |
| [`sensitive-data.secret-pattern`](#sensitive-datasecret-pattern) | sensitive-data | high | — | High-risk secret-like key/value assignments. |
| [`size.file-length`](#sizefile-length) | size | medium | `maxLines: 400` | Files exceeding the line-count threshold. |
| [`size.function-length`](#sizefunction-length) | size | medium | `maxLines: 80` | Functions exceeding the line-count threshold. |

## Opt-in expansion rules

These are off by default. Turn them on per project via `rules.<id>.enabled: true` once the codebase is ready.

| Rule ID | Pillar | Severity | Default threshold | Description |
|---------|--------|----------|-------------------|-------------|
| [`complexity.nesting-depth`](#complexitynesting-depth) | complexity | medium | `maxDepth: 4` | Functions whose nesting depth exceeds the threshold. |
| [`dead-code.empty-block`](#dead-codeempty-block) | dead-code | low | — | Empty control-flow blocks that usually indicate unfinished code. |
| [`docs.exported-symbol-comment`](#docsexported-symbol-comment) | documentation | low | — | Exported declarations missing a doc comment. |
| [`naming.package-underscore`](#namingpackage-underscore) | naming | low | — | Package names containing underscores. |
| [`security.shell-command`](#securityshell-command) | security | medium | — | `exec.Command` invocations that route through a shell interpreter. |
| [`size.parameter-count`](#sizeparameter-count) | size | low | `maxParameters: 5` | Functions whose parameter list exceeds the threshold. |
| [`test-quality.skipped-test`](#test-qualityskipped-test) | test-quality | low | — | Tests that call `t.Skip*`. |

## Severity tiers

Every rule has a default severity; configs can override per rule. The five-tier scale used internally maps to a three-tier visual treatment in the HTML report and the score weight model:

| Severity | Default penalty weight | HTML colour | Use it for |
|----------|------------------------|-------------|------------|
| `critical` | 30 | red | Almost certainly broken; block merges. |
| `high` | 15 | red | Strong signal; investigate. |
| `medium` | 8 | amber | Worth fixing in the next clean-up pass. |
| `low` | 3 | muted | Informational; trend over time. |
| `info` | 1 | muted | Background signal; not actionable per finding. |

The `--min-severity` flag (default `medium`) sets the threshold at which findings flip the exit code from `0` to `1`.

## Per-rule reference

### `complexity.cyclomatic`

- **Pillar:** complexity
- **Default severity:** medium
- **Default-enabled:** yes
- **Threshold:** `maxComplexity` (default `20`)
- **Confidence:** high

Flags Go functions whose branch count exceeds the configured cyclomatic complexity threshold. The metric counts `if`, `for`, `range`, `case` (when the case has labels), `select` cases, and `&&` / `||` short-circuit operators.

Each finding's metadata carries the measured `complexity` and the active `threshold` — the HTML reporter uses these to populate the cyclomatic distribution histogram.

**Remediation.** Split independent decisions, move branches into named helpers, or return early on guard conditions.

### `complexity.nesting-depth`

- **Pillar:** complexity
- **Default severity:** medium
- **Default-enabled:** no (opt-in)
- **Threshold:** `maxDepth` (default `4`)
- **Confidence:** high

Flags functions whose maximum control-flow nesting depth exceeds the threshold. Function literals reset the depth counter so callbacks aren't double-counted as part of their enclosing function.

**Remediation.** Extract nested branches into named helpers or return early on guard conditions.

### `dead-code.empty-block`

- **Pillar:** dead-code
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** medium

Flags empty control-flow blocks (`if {}`, `for {}`, `switch {}`, etc.) that usually indicate unfinished or accidentally orphaned code.

**Remediation.** Remove the empty block or add the intended implementation.

### `docs.exported-symbol-comment`

- **Pillar:** documentation
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** medium

Flags exported top-level Go declarations (functions, methods on exported types, types, vars, consts) that have no doc comment.

> **Note for `internal/` packages.** This rule currently flags every exported symbol regardless of whether the package is internal. Tuning options (`ignoreInternalPackages`, allowlists) are tracked in the backlog before any default-enable consideration.

**Remediation.** Add a Go-style doc comment that begins with the symbol name.

### `docs.package-comment`

- **Pillar:** documentation
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** high

Flags Go packages that have no package-level comment in any file. Package comments are the standard `godoc` entry point and are cheap to add.

**Remediation.** Add a package comment that explains the package's responsibility, scope, and the public surface.

### `naming.package-underscore`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** high
- **Tags:** `go-style`, `opt-in`

Flags Go package names that use underscores instead of short lowercase words (the Go convention favours `oauth2`, not `o_auth_2`).

**Remediation.** Rename the package to a short lowercase name without underscores. Use a package-relative import alias at the call sites if the change ripples wider than expected.

### `security.shell-command`

- **Pillar:** security (secondary: sensitive-data)
- **Default severity:** medium
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Tags:** `opt-in`, `security`

Flags `exec.Command` calls that invoke a shell interpreter (`sh`, `bash`, `zsh`, etc.) with a command string argument. Shell-routed exec is the classic injection vector when any portion of the command is user-controlled.

**Remediation.** Call the target executable directly with `exec.Command("ls", args...)` and pass arguments as separate parameters rather than interpolating them into a shell string.

### `sensitive-data.secret-pattern`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** yes
- **Confidence:** medium

Flags high-risk secret-like literal assignments in Go source and text/config files. Matches assignments like `apiKey := "AKIA…"`, `password = "p@ssw0rd"`, etc.

Add documented dummies to `allowlists.secretPreviews` so example values in tests and READMEs aren't flagged.

**Remediation.** Move secrets to a secret manager or environment-specific runtime configuration. Never commit production secrets to source control.

### `size.file-length`

- **Pillar:** size
- **Default severity:** medium
- **Default-enabled:** yes
- **Threshold:** `maxLines` (default `400`)
- **Confidence:** high

Flags Go files that exceed the configured line-count threshold. Long files frequently mix unrelated responsibilities.

**Remediation.** Split the file by responsibility or move focused behaviour into a smaller sibling file.

### `size.function-length`

- **Pillar:** size
- **Default severity:** medium
- **Default-enabled:** yes
- **Threshold:** `maxLines` (default `80`)
- **Confidence:** high

Flags Go functions that exceed the configured line-count threshold.

**Remediation.** Extract cohesive helper functions or split independent branches.

### `size.parameter-count`

- **Pillar:** size
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Threshold:** `maxParameters` (default `5`)
- **Confidence:** high
- **Tags:** `opt-in`

Flags functions and methods whose parameter list exceeds the threshold (the method receiver is excluded from the count).

**Remediation.** Group related parameters into a struct, accept an options type, or split the function.

### `test-quality.skipped-test`

- **Pillar:** test-quality
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Tags:** `opt-in`, `tests`

Flags Go tests that call `t.Skip`, `t.Skipf`, or `t.SkipNow`. Skipped tests are easy to forget and often hide real regressions.

**Remediation.** Remove the skip or document and track the skip condition outside the test body (issue link, build-tag rationale, environment requirement).

## Configuring rules

Every rule above accepts the same override shape. See [`configuration.md`](configuration.md) for the full schema. Common patterns:

```yaml
rules:
  # Tighten a default-enabled rule.
  complexity.cyclomatic:
    threshold: 12
    severity: high

  # Disable a default-enabled rule.
  docs.package-comment:
    enabled: false

  # Enable an opt-in expansion rule.
  size.parameter-count:
    enabled: true
    threshold: 4

  # Per-rule options (rule-specific opaque map).
  security.shell-command:
    enabled: true
    options:
      allowList: ["git", "go"]
```
