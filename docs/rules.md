# Rule Catalog

`gruff-go` v0.1 ships **25 rules** across **9 pillars**. Five are enabled by default; the rest are opt-in so existing repositories can phase them in without baseline churn.

Print the live registry any time with `gruff-go list-rules` (text) or `gruff-go list-rules --format json` (full metadata including thresholds, severities, and capability labels).

## Default-enabled rules

These run unless explicitly disabled via `selection.excludeRules` or `rules.<id>.enabled: false`.

| Rule ID | Pillar | Severity | Capability | Default threshold | Description |
|---------|--------|----------|------------|-------------------|-------------|
| [`complexity.cyclomatic`](#complexitycyclomatic) | complexity | medium | parser | `maxComplexity: 20` | Functions whose branch count exceeds the threshold. |
| [`docs.package-comment`](#docspackage-comment) | documentation | low | parser | — | Packages with no package-level comment in any file. |
| [`sensitive-data.secret-pattern`](#sensitive-datasecret-pattern) | sensitive-data | high | parser | — | High-risk secret-like key/value assignments. |
| [`size.file-length`](#sizefile-length) | size | medium | parser | `maxLines: 500` | Files exceeding the line-count threshold. |
| [`size.function-length`](#sizefunction-length) | size | medium | parser | `maxLines: 80` | Functions exceeding the line-count threshold. |

Default size thresholds are production-oriented and stay unchanged for `_test.go` files. Under the built-in medium severity, `_test.go` size findings still emit with the same threshold, message, and fingerprint identity, but are reported as `low` severity / `medium` confidence so table-driven and integration-test bulk does not carry the same score and exit-code weight as production code. Non-medium severity overrides in config apply to test files too.

## Opt-in expansion rules

These are off by default. Turn them on per project via `rules.<id>.enabled: true` once the codebase is ready.

Composite `design.*` rules are score-neutral annotations: they appear in findings, counts, SARIF, GitHub annotations, JSON, and HTML, but they do not add a second scoring penalty on top of the underlying findings that created them.

| Rule ID | Pillar | Severity | Capability | Default threshold | Description |
|---------|--------|----------|------------|-------------------|-------------|
| [`complexity.nesting-depth`](#complexitynesting-depth) | complexity | medium | parser | `maxDepth: 4` | Functions whose nesting depth exceeds the threshold. |
| [`dead-code.empty-block`](#dead-codeempty-block) | dead-code | low | parser | — | Empty control-flow blocks that usually indicate unfinished code. |
| [`design.god-function`](#designgod-function) | design | low | parser | — | Functions that already have both size and complexity findings. |
| [`design.hotspot-file`](#designhotspot-file) | design | low | parser | `minFindings: 3`, `minPillars: 2` | Files with findings across multiple quality pillars. |
| [`docs.comment-rubric`](#docscomment-rubric) | documentation | low | parser | `minPackageCommentLines: 2` | Opt-in maintainer comments for package summaries and declarations. |
| [`docs.exported-symbol-comment`](#docsexported-symbol-comment) | documentation | low | parser | — | Exported declarations missing a doc comment. |
| [`naming.acronym-case`](#namingacronym-case) | naming | low | parser | — | Identifiers that spell Go initialisms with mixed casing. |
| [`naming.get-prefix`](#namingget-prefix) | naming | low | parser | — | Accessor-style receiver methods with a discouraged `Get` prefix. |
| [`naming.identifier-quality`](#namingidentifier-quality) | naming | low | parser | — | Local identifiers matching a placeholder name list. |
| [`naming.package-underscore`](#namingpackage-underscore) | naming | low | parser | — | Package names containing underscores. |
| [`naming.receiver-consistency`](#namingreceiver-consistency) | naming | low | parser | — | Methods on the same type with inconsistent receiver names or pointer/value forms. |
| [`security.shell-command`](#securityshell-command) | security | medium | parser | — | `exec.Command` invocations that route through a shell interpreter. |
| [`sensitive-data.aws-access-key`](#sensitive-dataaws-access-key) | sensitive-data | high | parser | — | AWS access key id (AKIA…) literals. |
| [`sensitive-data.connection-string`](#sensitive-dataconnection-string) | sensitive-data | high | parser | — | Database/queue URLs with embedded passwords. |
| [`sensitive-data.jwt-token`](#sensitive-datajwt-token) | sensitive-data | high | parser | — | JWT-shaped literals (`eyJ…`). |
| [`sensitive-data.private-key`](#sensitive-dataprivate-key) | sensitive-data | critical | parser | — | PEM-encoded private keys embedded in source. |
| [`size.parameter-count`](#sizeparameter-count) | size | low | parser | `maxParameters: 5` | Functions whose parameter list exceeds the threshold. |
| [`test-quality.empty-test`](#test-qualityempty-test) | test-quality | low | parser | — | `Test…` / `Benchmark…` / `Fuzz…` functions with empty bodies. |
| [`test-quality.no-failure-path`](#test-qualityno-failure-path) | test-quality | low | parser | — | Test functions that contain code but never reach a failure call. |
| [`test-quality.skipped-test`](#test-qualityskipped-test) | test-quality | low | parser | — | Tests that call `t.Skip*`. |

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
- **Capability:** parser

Flags Go functions whose branch count exceeds the configured cyclomatic complexity threshold. The metric counts `if`, `for`, `range`, `case` (when the case has labels), `select` cases, and `&&` / `||` short-circuit operators.

Each finding's metadata carries the measured `complexity` and the active `threshold`. The score object's `complexityDistribution` is finding-only: it bins over-threshold `complexity.cyclomatic` findings, not every parsed function. All-zero bins mean no over-threshold complexity findings were reported.

**Remediation.** Split independent decisions, move branches into named helpers, or return early on guard conditions.

### `complexity.nesting-depth`

- **Pillar:** complexity
- **Default severity:** medium
- **Default-enabled:** no (opt-in)
- **Threshold:** `maxDepth` (default `4`)
- **Confidence:** high
- **Capability:** parser

Flags functions whose maximum control-flow nesting depth exceeds the threshold. Function literals reset the depth counter so callbacks aren't double-counted as part of their enclosing function.

**Remediation.** Extract nested branches into named helpers or return early on guard conditions.

### `dead-code.empty-block`

- **Pillar:** dead-code
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser

Flags empty control-flow blocks (`if {}`, `for {}`, `switch {}`, etc.) that usually indicate unfinished or accidentally orphaned code.

**Remediation.** Remove the empty block or add the intended implementation.

### `design.god-function`

- **Pillar:** design (secondary: size, complexity)
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** high
- **Capability:** parser
- **Tags:** `composite`, `opt-in`
- **Scoring:** score-neutral

Flags functions that already have at least one size finding and at least one complexity finding on the same file and symbol. The composite finding has no source line so its fingerprint remains stable when the function body shifts but the file and symbol identity stay the same.

**Remediation.** Split the function around cohesive responsibilities, then re-run the size and complexity rules to confirm both signals cleared.

### `design.hotspot-file`

- **Pillar:** design
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Thresholds:** `minFindings` (default `3`), `minPillars` (default `2`)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `composite`, `opt-in`
- **Scoring:** score-neutral

Flags files with at least `minFindings` findings across at least `minPillars` distinct non-design pillars. Composite findings do not feed other composite rules, so a god-function finding will not itself create a hotspot-file finding.

**Remediation.** Triage the file as a unit: separate unrelated responsibilities before tuning individual rule thresholds.

### `docs.comment-rubric`

- **Pillar:** documentation
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Threshold:** `minPackageCommentLines` (default `2`)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `comments`, `documentation`, `opt-in`, `rubric`
- **Options:** `includePaths []string`, `excludePaths []string`, `requirePackageSummary bool`, `requireFunctionComments bool`, `requireNamedTypeComments bool`, `requireStructComments bool`, `requireInterfaceComments bool`, `requireConstComments bool`, `requireVarComments bool`, `ignoreTests bool`

Flags files that opt into a stricter maintainer-comment rubric. The rule can require a package summary with enough non-empty lines, plus directly attached comments for functions, named type declarations, package-scope constants, and package-scope variables. Local `const` and `var` declarations are not enforced.

Use `includePaths` to keep the rule scoped to files where the project wants the stricter standard. `excludePaths` removes fixture or generated paths from that scoped set. `ignoreTests: true` skips `_test.go` files.

```yaml
rules:
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

**Remediation.** Add maintainer-oriented package summaries and directly attached comments for the selected declaration kinds.

### `docs.exported-symbol-comment`

- **Pillar:** documentation
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser
- **Options:** `ignoreInternalPackages bool` — default `true`

Flags exported top-level Go declarations (functions, methods on exported types, types, vars, consts) that have no doc comment.

Set `ignoreInternalPackages: false` when internal package exports should follow the same documentation bar as public API packages.

**Remediation.** Add a Go-style doc comment that begins with the symbol name.

### `docs.package-comment`

- **Pillar:** documentation
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser

Flags Go packages that have no package-level comment in any file. Package comments are the standard `godoc` entry point and are cheap to add. `_test.go`-only external test packages such as `package foo_test` are skipped because they normally document black-box tests, not a production package API.

**Remediation.** Add a package comment that explains the package's responsibility, scope, and the public surface.

### `naming.acronym-case`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `go-style`, `naming`, `opt-in`
- **Options:** `acronyms []string` — default `[HTTP, URL, JSON, ID, XML, API, JWT, AWS, OAUTH, CSS, HTML, YAML, SARIF, ASCII, SQL, CLI, TCP, UDP, TLS, SSL, DNS, IP, GPU, CPU, OS]`; `allow []string` — exact identifiers to skip

Flags type names, function and method names, variable and constant names, struct fields, and function parameters that spell configured initialisms with mixed casing, such as `HttpClient`, `UrlParser`, `JsonReport`, or `IdGenerator`. Correct all-caps forms such as `HTTPClient`, `URLParser`, `JSONReport`, and `IDGenerator` pass; lowercase initialisms in unexported names such as `urlParser` also pass.

`allowlists.acceptedAbbreviations` suppresses findings for matching tokens project-wide. Use the rule-local `allow` list only for exact third-party or generated API names that must stay as-is.

```yaml
allowlists:
  acceptedAbbreviations:
    - UUID

rules:
  naming.acronym-case:
    enabled: true
    options:
      acronyms: ["HTTP", "URL", "JSON", "ID", "UUID"]
      allow: ["ThirdPartyHttpName"]
```

**Remediation.** Use all-caps initialisms in exported names and consistently cased initialisms in unexported names.

### `naming.get-prefix`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `go-style`, `naming`, `opt-in`
- **Options:** `excludePaths []string`, `excludeNames []string`

Flags receiver methods named like `GetUser()` or `GetCacheStats()` when they have no parameters and return either one result or `(T, error)`. Methods with lookup parameters, such as `GetUserByID(id string)`, are not flagged because the verb carries useful action context. Package-level functions are not flagged.

```yaml
rules:
  naming.get-prefix:
    enabled: true
    options:
      excludePaths: ["**/*.pb.go"]
      excludeNames: ["GetLegacyName"]
```

**Remediation.** Rename accessor-style methods from `GetThing` to `Thing` unless parameters make the lookup action explicit.

### `naming.identifier-quality`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `opt-in`, `naming`
- **Options:** `placeholderNames []string` — default `[foo, bar, baz, tmp, temp, obj, todo, thing, stuff]`

Flags local `:=` assignments, `var` declarations, and `const` declarations in non-test files whose name matches a configurable list of placeholder tokens. Test files are skipped because disposable identifier names are often appropriate there.

```yaml
rules:
  naming.identifier-quality:
    enabled: true
    options:
      # Override the default placeholder list.
      placeholderNames: ["foo", "bar", "baz", "tmp"]
```

**Remediation.** Rename the identifier to something that names its role, or remove it if it is no longer needed. Override the option list when your project has additional placeholder terms to enforce or legitimate uses for one of the built-in placeholders.

### `naming.package-underscore`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** high
- **Capability:** parser
- **Tags:** `go-style`, `opt-in`

Flags Go package names that use underscores instead of short lowercase words (the Go convention favours `oauth2`, not `o_auth_2`).

**Remediation.** Rename the package to a short lowercase name without underscores. Use a package-relative import alias at the call sites if the change ripples wider than expected.

### `naming.receiver-consistency`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `go-style`, `naming`, `opt-in`
- **Options:** `allowMixed []string` — receiver type names allowed to mix pointer/value receiver forms; `inspectGroup string` — `both` (default), `name`, or `pointer`

Flags methods on the same receiver type that use inconsistent receiver names or pointer/value forms. The rule groups methods across the scanned project by receiver type name, strips leading `*`, and reports methods that use the minority receiver name or form.

```yaml
rules:
  naming.receiver-consistency:
    enabled: true
    options:
      inspectGroup: both
      allowMixed: ["Registry"]
```

**Remediation.** Use one receiver name and one receiver pointer/value form per type, or explicitly allow a deliberate mixed form.

### `security.shell-command`

- **Pillar:** security (secondary: sensitive-data)
- **Default severity:** medium
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `opt-in`, `security`

Flags `exec.Command` calls that invoke a shell interpreter (`sh`, `bash`, `zsh`, etc.) with a command string argument. Shell-routed exec is the classic injection vector when any portion of the command is user-controlled.

**Remediation.** Call the target executable directly with `exec.Command("ls", args...)` and pass arguments as separate parameters rather than interpolating them into a shell string.

### `sensitive-data.aws-access-key`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** no (opt-in)
- **Confidence:** high
- **Capability:** parser
- **Tags:** `opt-in`, `secrets`

Flags AWS access-key identifier literals (`AKIA[0-9A-Z]{16}`) embedded in source or text files. The finding's `preview` metadata is redacted via the shared `redact()` helper; the raw key never reaches text / JSON / SARIF / GitHub / HTML output (asserted by `internal/report/sensitive_redaction_test.go`).

**Remediation.** Rotate the key, then load credentials from the AWS SDK default provider chain rather than embedding them.

### `sensitive-data.connection-string`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `opt-in`, `secrets`

Flags database / queue / cache connection URIs that embed a username and password in the URL — `postgres://user:pass@host`, `mysql://`, `mongodb://`, `mongodb+srv://`, `redis://`, `amqp://`, `amqps://`. Preview is redacted in every output format.

**Remediation.** Pull the password from environment-specific runtime configuration; keep only the scheme and host in source-controlled strings.

### `sensitive-data.jwt-token`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `opt-in`, `secrets`

Flags JWT-shaped literals — three base64url segments separated by dots, the first segment starting with `eyJ` (the literal base64 prefix for `{"`). Tokens can be signing keys, session tokens, or API credentials; the rule does not distinguish.

**Remediation.** Move the token to a secret manager or runtime-only configuration; never check signed tokens into source control. If the literal is a public test vector documented in code, set the preview into `allowlists.secretPreviews` so it stops triggering.

### `sensitive-data.private-key`

- **Pillar:** sensitive-data
- **Default severity:** **critical**
- **Default-enabled:** no (opt-in)
- **Confidence:** high
- **Capability:** parser
- **Tags:** `opt-in`, `secrets`

Flags PEM-encoded private-key headers (`-----BEGIN ... PRIVATE KEY-----`) embedded in source or text files. The most severe of the sensitive-data rules — a leaked private key is almost always a real incident.

**Remediation.** Remove the key, rotate it, and load it from a secret manager or environment-specific runtime configuration.

### `sensitive-data.secret-pattern`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser

Flags high-risk secret-like literal assignments in Go source and text/config files. Matches assignments like `apiKey := "AKIA…"`, `password = "p@ssw0rd"`, `bearer = "…"`, and `authorization = "Bearer …"`.

Add documented dummies to `allowlists.secretPreviews` so example values in tests and READMEs aren't flagged.

**Remediation.** Move secrets to a secret manager or environment-specific runtime configuration. Never commit production secrets to source control.

### `size.file-length`

- **Pillar:** size
- **Default severity:** medium
- **Default-enabled:** yes
- **Threshold:** `maxLines` (default `500`)
- **Confidence:** high
- **Capability:** parser

Flags Go files that exceed the configured line-count threshold. Long files frequently mix unrelated responsibilities. `_test.go` findings use the same threshold and fingerprint identity as production findings, but the built-in default reports them as `low` severity / `medium` confidence unless you explicitly configure a non-medium rule severity.

**Remediation.** Split the file by responsibility or move focused behaviour into a smaller sibling file.

### `size.function-length`

- **Pillar:** size
- **Default severity:** medium
- **Default-enabled:** yes
- **Threshold:** `maxLines` (default `80`)
- **Confidence:** high
- **Capability:** parser

Flags Go functions that exceed the configured line-count threshold. `_test.go` findings use the same threshold and fingerprint identity as production findings, but the built-in default reports them as `low` severity / `medium` confidence unless you explicitly configure a non-medium rule severity.

**Remediation.** Extract cohesive helper functions or split independent branches.

### `size.parameter-count`

- **Pillar:** size
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Threshold:** `maxParameters` (default `5`)
- **Confidence:** high
- **Capability:** parser
- **Tags:** `opt-in`

Flags functions and methods whose parameter list exceeds the threshold (the method receiver is excluded from the count).

**Remediation.** Group related parameters into a struct, accept an options type, or split the function.

### `test-quality.empty-test`

- **Pillar:** test-quality
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** high
- **Capability:** parser
- **Tags:** `opt-in`, `tests`

Flags top-level `Test…` / `Benchmark…` / `Fuzz…` functions whose body contains no executable statements. An empty test is either an unfinished scaffold left behind by IDE generators or a stub waiting for content — both should be removed or filled in before the build is considered green.

**Remediation.** Add an assertion that exercises the behaviour the test name claims, or remove the empty test entirely.

### `test-quality.no-failure-path`

- **Pillar:** test-quality
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `opt-in`, `tests`

Flags `Test…` / `Benchmark…` / `Fuzz…` functions that contain executable statements but never reach a failure call — `t.Error`, `t.Errorf`, `t.Fatal`, `t.Fatalf`, `t.Fail`, `t.FailNow`. A test that cannot fail is asserting nothing and provides false confidence.

The rule walks the function body looking for those methods on the test function's `*testing.T`, `*testing.B`, or `*testing.F` parameter. It does not currently model helper-function indirection, so a test whose only assertion lives in a separate helper will be flagged. When that happens, either inline the assertion or document the convention in the helper's name (a future iteration may grow option-driven helper allowlists).

**Remediation.** Add an assertion, or document why the test cannot fail (e.g. it only exercises compilation).

### `test-quality.skipped-test`

- **Pillar:** test-quality
- **Default severity:** low
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser
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
