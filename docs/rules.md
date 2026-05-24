# Rule Catalog

`gruff-go` v0.1 ships **41 rules** across **11 pillars**. **All rules are enabled by default.** Projects can disable any rule via `selection.excludeRules` or `rules.<id>.enabled: false`.

Print the live registry any time with `gruff-go list-rules` (text) or `gruff-go list-rules --format json` (full metadata including thresholds, severities, and capability labels). Add `--no-config` to see the built-in release defaults without project `.gruff-go.yaml` overrides.

## Rule reference

Composite `design.*` rules are score-neutral annotations: they appear in findings, counts, SARIF, GitHub annotations, JSON, and HTML, but they do not add a second scoring penalty on top of the underlying findings that created them.

`docs.comment-rubric` is path-scoped: it fires only on files listed in its `includePaths` option. Without configured paths it inspects nothing, so its default-on status is a no-op until you opt selected files in.

`docs.config-field-comment` enforces doc comments on exported struct fields. Use `includePaths` for user-facing configuration types when you want every knob documented without applying the check to every struct in the project.

| Rule ID | Pillar | Severity | Capability | Default threshold | Description |
|---------|--------|----------|------------|-------------------|-------------|
| [`complexity.cyclomatic`](#complexitycyclomatic) | complexity | medium | parser | `maxComplexity: 20` | Functions whose branch count exceeds the threshold. |
| [`complexity.nesting-depth`](#complexitynesting-depth) | complexity | medium | parser | `maxDepth: 5` | Functions whose nesting depth exceeds the threshold. |
| [`dead-code.empty-block`](#dead-codeempty-block) | dead-code | low | parser | - | Empty control-flow blocks that usually indicate unfinished code. |
| [`design.god-function`](#designgod-function) | design | low | parser | - | Functions that already have both size and complexity findings. |
| [`design.hotspot-file`](#designhotspot-file) | maintainability | low | parser | `minFindings: 3`, `minPillars: 2` | Files with findings across multiple quality pillars. |
| [`docs.comment-rubric`](#docscomment-rubric) | documentation | low | parser | `minPackageCommentLines: 1` | Path-scoped maintainer comments for package summaries and declarations. |
| [`docs.config-field-comment`](#docsconfig-field-comment) | documentation | low | parser | - | Doc comments on exported struct fields, optionally scoped with `includePaths`. |
| [`docs.exported-symbol-comment`](#docsexported-symbol-comment) | documentation | low | parser | - | Exported declarations missing a doc comment. |
| [`docs.package-comment`](#docspackage-comment) | documentation | low | parser | - | Packages with no package-level comment in any file. |
| [`naming.acronym-case`](#namingacronym-case) | naming | low | parser | - | Identifiers that spell Go initialisms with mixed casing. |
| [`naming.contextual-generic`](#namingcontextual-generic) | naming | low | parser | `minBodyLines: 15`, `minFunctionLines: 50` | Generic names used only when the surrounding loop or function is large enough that context is weak. |
| [`naming.get-prefix`](#namingget-prefix) | modernisation | low | parser | - | Accessor-style receiver methods with a discouraged `Get` prefix. |
| [`naming.identifier-quality`](#namingidentifier-quality) | naming | low | parser | - | Local identifiers matching a placeholder name list. |
| [`naming.misspelling`](#namingmisspelling) | naming | low | parser | - | Identifiers, doc comments, and struct tags containing common programming misspellings. |
| [`naming.negated-boolean`](#namingnegated-boolean) | naming | low | parser | - | Boolean identifiers using negation prefixes (No/Not/Disable…) that force double-negation at call sites. |
| [`naming.package-stutter`](#namingpackage-stutter) | naming | low | parser | - | Exported identifiers whose lowercase form starts with their own package name (`config.ConfigOptions`). |
| [`naming.package-underscore`](#namingpackage-underscore) | naming | low | parser | - | Package names containing underscores. |
| [`naming.receiver-consistency`](#namingreceiver-consistency) | naming | low | parser | - | Methods on the same type with inconsistent receiver names or pointer/value forms. |
| [`security.archive-path-traversal`](#securityarchive-path-traversal) | security | low | parser | - | Archive entry paths joined into extraction destinations without containment evidence. |
| [`security.insecure-random-secret`](#securityinsecure-random-secret) | security | low | parser | - | `math/rand` calls used in token, nonce, session, key, or other secret-looking contexts. |
| [`security.shell-command`](#securityshell-command) | security | medium | parser | - | `exec.Command` invocations that route through a shell interpreter. |
| [`security.sql-string-query`](#securitysql-string-query) | security | low | parser | - | SQL execution calls with query arguments built by formatting or concatenation. |
| [`security.tls-insecure-config`](#securitytls-insecure-config) | security | medium | parser | - | `tls.Config` literals that disable verification or allow obsolete TLS versions. |
| [`security.weak-crypto`](#securityweak-crypto) | security | low | parser | - | MD5/SHA1 in security contexts, DES/RC4 construction, or RSA keys below 2048 bits. |
| [`sensitive-data.anthropic-api-key`](#sensitive-dataanthropic-api-key) | sensitive-data | high | parser | - | Anthropic API key literals (`sk-ant-…`). |
| [`sensitive-data.aws-access-key`](#sensitive-dataaws-access-key) | sensitive-data | high | parser | - | AWS access key id (AKIA…) literals. |
| [`sensitive-data.connection-string`](#sensitive-dataconnection-string) | sensitive-data | high | parser | - | Database/queue URLs with embedded passwords. |
| [`sensitive-data.gcp-service-account`](#sensitive-datagcp-service-account) | sensitive-data | critical | parser | - | Files containing both `"type": "service_account"` and a PEM private-key header (GCP service-account JSON keys). |
| [`sensitive-data.github-token`](#sensitive-datagithub-token) | sensitive-data | high | parser | - | GitHub PAT / OAuth / user / server / refresh tokens (`gh[pousr]_…`). |
| [`sensitive-data.google-api-key`](#sensitive-datagoogle-api-key) | sensitive-data | high | parser | - | Google API key literals (`AIza…`). |
| [`sensitive-data.jwt-token`](#sensitive-datajwt-token) | sensitive-data | high | parser | - | JWT-shaped literals (`eyJ…`). |
| [`sensitive-data.private-key`](#sensitive-dataprivate-key) | sensitive-data | critical | parser | - | PEM-encoded private keys embedded in source. |
| [`sensitive-data.secret-pattern`](#sensitive-datasecret-pattern) | sensitive-data | high | parser | - | High-risk secret-like key/value assignments. |
| [`sensitive-data.slack-token`](#sensitive-dataslack-token) | sensitive-data | high | parser | - | Slack bot / user / app / refresh tokens (`xox[bpar]-…`). |
| [`sensitive-data.stripe-key`](#sensitive-datastripe-key) | sensitive-data | high | parser | - | Stripe live secret / publishable / restricted keys (`(sk|pk|rk)_live_…`). |
| [`size.file-length`](#sizefile-length) | size | medium | parser | `maxLines: 500` | Files exceeding the line-count threshold. |
| [`size.function-length`](#sizefunction-length) | size | medium | parser | `maxLines: 80` | Functions exceeding the code-line threshold. |
| [`size.parameter-count`](#sizeparameter-count) | size | low | parser | `maxParameters: 8` | Functions whose parameter list exceeds the threshold. |
| [`test-quality.empty-test`](#test-qualityempty-test) | test-quality | low | parser | - | `Test…` / `Benchmark…` / `Fuzz…` functions with empty bodies. |
| [`test-quality.no-failure-path`](#test-qualityno-failure-path) | test-quality | low | parser | - | Test functions that contain code but never reach a failure call or recognised assertion helper. |
| [`test-quality.skipped-test`](#test-qualityskipped-test) | test-quality | low | parser | - | Unconditional or debt-marked tests that call `t.Skip*`. |

Default size thresholds are production-oriented and stay unchanged for `_test.go` files. Under the built-in medium severity, `_test.go` size findings still emit with the same threshold, message, and fingerprint identity, but are reported as `low` severity / `medium` confidence so table-driven and integration-test bulk does not carry the same score and exit-code weight as production code. Non-medium severity overrides in config apply to test files too.

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
- **Default-enabled:** yes
- **Threshold:** `maxDepth` (default `5`)
- **Confidence:** high
- **Capability:** parser

Flags functions whose maximum control-flow nesting depth exceeds the threshold. Function literals reset the depth counter so callbacks aren't double-counted as part of their enclosing function.

**Remediation.** Extract nested branches into named helpers or return early on guard conditions.

### `dead-code.empty-block`

- **Pillar:** dead-code
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser

Flags empty control-flow blocks (`if {}`, `for {}`, `switch {}`, etc.) that usually indicate unfinished or accidentally orphaned code.

**Remediation.** Remove the empty block or add the intended implementation.

### `design.god-function`

- **Pillar:** design (secondary: size, complexity)
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `composite`
- **Scoring:** score-neutral

Flags functions that already have at least one size finding and at least one complexity finding on the same file and symbol. The composite finding has no source line so its fingerprint remains stable when the function body shifts but the file and symbol identity stay the same.

**Remediation.** Split the function around cohesive responsibilities, then re-run the size and complexity rules to confirm both signals cleared.

### `design.hotspot-file`

- **Pillar:** maintainability
- **Default severity:** low
- **Default-enabled:** yes
- **Thresholds:** `minFindings` (default `3`), `minPillars` (default `2`)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `composite`
- **Scoring:** score-neutral

Flags files with at least `minFindings` findings across at least `minPillars` distinct non-design pillars. Composite findings do not feed other composite rules, so a god-function finding will not itself create a hotspot-file finding.

**Remediation.** Triage the file as a unit: separate unrelated responsibilities before tuning individual rule thresholds.

### `docs.comment-rubric`

- **Pillar:** documentation
- **Default severity:** low
- **Default-enabled:** yes
- **Threshold:** `minPackageCommentLines` (default `1`)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `comments`, `documentation`, `rubric`
- **Options:** `includePaths []string`, `excludePaths []string`, `minWordsBeyondSymbol int` (default `0`), `requirePackageSummary bool`, `requireFunctionComments bool`, `requireNamedTypeComments bool`, `requireStructComments bool`, `requireInterfaceComments bool`, `requireConstComments bool`, `requireVarComments bool`, `ignoreTests bool`

Flags files that opt into a stricter maintainer-comment rubric. The rule can require a package summary with enough non-empty lines, plus directly attached comments for functions, named type declarations, package-scope constants, and package-scope variables. Local `const` and `var` declarations are not enforced.

Use `includePaths` to keep the rule scoped to files where the project wants the stricter standard. `excludePaths` removes fixture or generated paths from that scoped set. `ignoreTests: true` skips `_test.go` files entirely.

**Default package summary threshold.** `minPackageCommentLines` defaults to `1`: a single-line `// Package foo …` summary passes when `requirePackageSummary: true` and no threshold is configured. Projects that want the stricter two-line floor opt in via `threshold: 2`.

**Test-file scoping.** On `*_test.go` files the rule does not enforce `requireConstComments` or `requireVarComments`, even when `ignoreTests` is false. Test-scope const and var declarations rarely earn the required comment. Function, named-type, and package-summary checks continue to fire on test files unless `ignoreTests: true`.

**Quality floor (`minWordsBeyondSymbol`).** When this option is positive, every required comment must add at least N unique tokens that are NOT part of the symbol's own identifier tokens. Both inputs are tokenised via the same camel-case-aware splitter the acronym-case rule uses, then lowercased and de-duplicated. The check runs after the existing "comment normalises differently from the symbol" gate; both must pass. At `0` (default) behaviour is identical to today's rule. Use this option to reject "name + filler" boilerplate like `// Definition is.` on a `Definition()` method while still accepting substantive docs on short-named symbols.

```yaml
rules:
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
```

**Remediation.** Add maintainer-oriented package summaries and directly attached comments for the selected declaration kinds. When `minWordsBeyondSymbol` is set, replace name-restatement summaries with substantive context.

### `docs.config-field-comment`

- **Pillar:** documentation
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `comments`, `documentation`, `struct-fields`
- **Options:** `includePaths []string`, `excludePaths []string`

Flags exported fields on struct types declared inside configured `includePaths` that have no useful doc comment. The "useful comment" check is shared with `docs.comment-rubric`: the comment must exist (at least one non-empty line) and must normalise differently from the field name itself. Embedded fields (no `Names` on the `*ast.Field`) and unexported fields are out of scope and never produce findings.

The rule is default-enabled and intended for user-facing configuration schema types where every knob deserves documentation. When `includePaths` is unset the rule applies to every Go file; scope it via `includePaths` when broad struct-field enforcement is too noisy.

```yaml
rules:
  docs.config-field-comment:
    enabled: true
    severity: low
    options:
      includePaths:
        - internal/config/config.go
        - internal/analysis/report.go
```

**Remediation.** Add a doc comment to every exported field of structs declared in the configured `includePaths`.

### `docs.exported-symbol-comment`

- **Pillar:** documentation
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Options:** `ignoreInternalPackages bool` - default `true`

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

- **Pillar:** modernisation
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `go-style`, `naming`
- **Options:** `acronyms []string` - default `[HTTP, URL, JSON, ID, XML, API, JWT, AWS, OAUTH, CSS, HTML, YAML, SARIF, ASCII, SQL, CLI, TCP, UDP, TLS, SSL, DNS, IP, GPU, CPU, OS]`; `allow []string` - exact identifiers to skip

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

### `naming.contextual-generic`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `naming`
- **Thresholds:** `minBodyLines: 15`, `minFunctionLines: 50`
- **Options:**
  - `genericNames []string` - range value names to check. Default: `[item, value, entry, elem, v]`
  - `accumulatorNames []string` - accumulator names to check. Default: `[out, result]`
  - `requireMultiple bool` - require at least two matching accumulator declarations in a long function before flagging. Default: `true`

Flags generic range value names only when the loop body exceeds `minBodyLines`. Short loops such as `for _, item := range items { ... }` pass because the range expression provides enough context; longer loops ask for a more specific role name. Test files and generated files are skipped.

The optional accumulator branch flags `:=` declarations of names such as `out` or `result` only in functions longer than `minFunctionLines`. By default, the function also needs multiple matching accumulator declarations so ordinary small builders do not produce noise.

```yaml
rules:
  naming.contextual-generic:
    enabled: true
    thresholds:
      minBodyLines: 20
      minFunctionLines: 60
    options:
      genericNames: ["item", "entry", "record"]
      accumulatorNames: ["out", "result", "buffer"]
      requireMultiple: true
```

**Remediation.** Rename long-loop values and long-function accumulators to describe the data role they carry, such as `finding`, `skippedPath`, `scoreRow`, or `rendered`.

### `naming.get-prefix`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `go-style`, `naming`
- **Options:** `excludePaths []string`, `excludeNames []string`

Flags receiver methods named like `GetUser()` or `GetCacheStats()` when they have no parameters and return either one result or `(T, error)`. Package-level helpers, including context accessors such as `GetLogger(ctx)`, are not flagged because the verb often describes lookup semantics rather than field-style access. Methods with lookup parameters, such as `GetUserByID(id string)`, are not flagged because the verb carries useful action context.

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
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `naming`
- **Options:** `placeholderNames []string` - default `[foo, bar, baz, tmp, temp, obj, todo, thing, stuff]`

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

### `naming.misspelling`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `naming`
- **Options:**
  - `extra map[string]string` - additional `wrong → right` pairs to add to the built-in dictionary
  - `ignore []string` - tokens to suppress (lowercased)

Flags identifiers (`func`, `type`, `var`, `const`, struct field names), doc comments, and struct tags containing tokens from a conservative built-in dictionary of common programming misspellings (`recieve`, `seperate`, `lenght`, `occured`, `enviroment`, etc., ~40 entries). Tokens are extracted with camelCase / snake_case / non-letter splitting, lowercased, and matched exactly against the dictionary.

```yaml
rules:
  naming.misspelling:
    enabled: true
    options:
      extra:
        # Project-specific additions, also expressed as wrong → right.
        privledge: privilege
      ignore:
        # Real proper nouns that look like misspellings.
        - "thier"
```

**Remediation.** Replace the misspelled token with the suggested correction the finding includes. Add legitimate proper nouns or vendor-specific terms to the `ignore` option.

### `naming.negated-boolean`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `go-style`, `naming`
- **Options:**
  - `prefixes []string` - default `[No, Not, Disable, Disallow, Without, Suppress]`
  - `allowList []string` - default `[NoOp, Notify, Notice, Now, NoCopy, Notation, Notebook]` (English words that begin with a prefix but are not negations)
  - `scope string` - default `"exported"`; alternatives `"all"` and `"locals"`

Flags boolean identifiers (struct fields, function parameters, function results, `var`/`const` declarations) whose names begin with a negation prefix followed by an uppercase letter. Negated names force double-negation at call sites (`if state.Baseline != "" && state.NoBaseline != "1"`) and obscure the actual intent.

Type-aware: only flags identifiers whose syntactic type is `bool`, so `NoOp func()` and `Notify chan struct{}` are correctly ignored. The default `scope: exported` checks struct fields and exported declarations; switch to `"locals"` to additionally flag local `var` declarations inside function bodies, or `"all"` for both.

```yaml
rules:
  naming.negated-boolean:
    enabled: true
    options:
      # Extend the prefix list.
      prefixes: ["No", "Not", "Disable", "Without", "Skip"]
      # Whitelist a project-specific identifier that collides with a prefix.
      allowList: ["NoOp", "Notify", "NoticeBoard"]
      # Also check locals.
      scope: "locals"
```

**Remediation.** Rename to the positive form: `NoConfig` → `SkipConfig` if the boolean still means "skip", or `EnableConfig` with inverted truth values if you want callers to read positive logic. CLI flag names like `--no-config` can stay as the public surface; only rename the internal Go field.

### `naming.package-stutter`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `go-style`, `naming`
- **Options:**
  - `allowStutter []string` - identifiers (PascalCase form) to exempt from the stutter check. Default: `[Config, Finding]`.

Flags exported top-level types, non-method functions, and exported package-scope variables/constants whose lowercase form starts with their own package name. Stuttering is caught two ways: (a) exact match (`type Rule` in `package rule`, unless allowlisted) and (b) prefix match with an uppercase letter following the package name (`type RuleRegistry` in `package rule`, `type HttpServerOptions` in `package httpserver`). Plain extensions of the package word like `type Rules` in `package rule` (next char is lowercase, the word continues) do *not* fire.

Method names are not checked: a receiver makes the call site unambiguous (`r.RuleApply()` already reads cleanly).

```yaml
rules:
  naming.package-stutter:
    enabled: true
    options:
      # Extend the default allowlist with project-specific accepted stutters.
      allowStutter: ["Config", "Finding", "ParserParser"]
```

**Remediation.** Rename so call sites read without repetition: `rule.RuleRegistry` → `rule.Registry`, `config.ConfigOptions` → `config.Options`. Add genuine single-noun stutters that the community accepts to `allowStutter`.

### `naming.package-underscore`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `go-style`

Flags Go package names that use underscores instead of short lowercase words (the Go convention favours `oauth2`, not `o_auth_2`). Idiomatic external test packages such as `package api_test` in `_test.go` files are exempt; package names like `bad_pkg_test` still fire because the production-name portion contains an underscore.

**Remediation.** Rename the package to a short lowercase name without underscores. Use a package-relative import alias at the call sites if the change ripples wider than expected.

### `naming.receiver-consistency`

- **Pillar:** naming
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `go-style`, `naming`
- **Options:** `allowMixed []string` - receiver type names allowed to mix pointer/value receiver forms; `inspectGroup string` - `both` (default), `name`, or `pointer`

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

### `security.archive-path-traversal`

- **Pillar:** security
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `archive`, `security`

Flags Go files that import `archive/zip` or `archive/tar` and join an archive entry `Name` into an extraction destination without obvious containment evidence. The parser-only check recognises direct entry names such as `file.Name`, locals assigned from `header.Name`, and `filepath.Join` / `path.Join` calls. It suppresses when the same function contains obvious containment or sanitisation evidence such as `filepath.Clean`, `filepath.Rel`, `strings.HasPrefix`, or helper names containing `safe`, `sanitize`, `within`, or `contains`.

Each finding's metadata carries the archive entry expression and the missing check kind.

**Remediation.** Clean the joined path and verify it remains inside the extraction root before creating files.

### `security.insecure-random-secret`

- **Pillar:** security
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `random`, `security`

Flags Go files that import `math/rand` and use package-level random APIs in secret-looking contexts such as token, nonce, session, password, key, CSRF, salt, OTP, or OAuth state generation. The parser-only check looks at the enclosing function name, assignment target, and call arguments, so ordinary sampling, shuffling, simulation, benchmark, and test-randomness names are ignored unless the surrounding symbol clearly carries a production-secret term. `crypto/rand` is not flagged.

Each finding's metadata carries the random API and context word.

**Remediation.** Use `crypto/rand` for security-sensitive random values and keep `math/rand` for sampling, tests, and simulations.

### `security.shell-command`

- **Pillar:** security (secondary: sensitive-data)
- **Default severity:** medium
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `security`

Flags `exec.Command` and `exec.CommandContext` calls that invoke a shell interpreter (`sh`, `bash`, `zsh`, `cmd.exe`, `powershell.exe`, etc.) with a command string argument. The matcher recognises aliased `os/exec` imports and path-qualified shell binaries such as `/bin/sh` or `C:\Windows\System32\cmd.exe` without flagging direct executable calls such as `exec.Command("git", "status")`. Shell-routed exec is the classic injection vector when any portion of the command is user-controlled.

**Remediation.** Call the target executable directly with `exec.Command("ls", args...)` and pass arguments as separate parameters rather than interpolating them into a shell string.

### `security.sql-string-query`

- **Pillar:** security
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `security`, `sql`

Flags SQL execution calls (`Query`, `QueryRow`, `Exec` and `*Context` forms) whose query argument is built with `fmt.Sprintf`, string concatenation, or a same-function variable initialized from those forms. The constructed expression must contain SQL statement keyword evidence, so non-SQL `Exec` calls and literal parameterized queries are ignored. The rule handles both standard `database/sql` argument positions and pgx-style calls where a context value appears before the query. `_test.go` files and `testutil` helpers may build `CREATE SCHEMA ` statements from fixed `test_*_%d` names using `time.Now().UnixNano()` without firing; arbitrary schema variables still fire.

Each finding's metadata carries the call name and construction kind.

**Remediation.** Use parameterized queries or a prepared/query-builder API instead of interpolating SQL text.

### `security.tls-insecure-config`

- **Pillar:** security
- **Default severity:** medium
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `security`, `tls`

Flags `tls.Config` composite literals that explicitly disable certificate verification with `InsecureSkipVerify: true` or set `MinVersion` to obsolete protocol constants: `tls.VersionSSL30`, `tls.VersionTLS10`, or `tls.VersionTLS11`. The rule intentionally does not flag an absent `MinVersion`; that is a hardening preference rather than concrete parser-only vulnerability evidence.

Each finding's metadata carries the unsafe `field` and `value`.

**Remediation.** Keep certificate verification enabled and require TLS 1.2 or newer for minimum protocol versions.

### `security.weak-crypto`

- **Pillar:** security
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `crypto`, `security`

Flags weak cryptographic primitives when the parser-only evidence is concrete: `crypto/md5` or `crypto/sha1` calls in password, token, signature, key, session, CSRF, or other security-looking contexts; direct DES, 3DES, or RC4 cipher construction; and `rsa.GenerateKey(..., bits)` with a literal key size below 2048. Plain checksum-style MD5/SHA1 use is ignored unless the surrounding function, target, comment, or call argument carries a security context word.

Each finding's metadata carries the primitive and reason.

**Remediation.** Use modern primitives such as SHA-256 or HMAC-SHA-256 for security hashes, AES-GCM or ChaCha20-Poly1305 for encryption, and RSA keys of at least 2048 bits.

### `sensitive-data.anthropic-api-key`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags Anthropic API key literals (`sk-ant-` prefix plus an alphanumeric body). A leaked Anthropic key bills model usage against the owning organisation and exposes any data the caller had access to send through the API.

**Remediation.** Revoke the key in the Anthropic console, then load credentials from a secret manager.

### `sensitive-data.aws-access-key`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags AWS access-key identifier literals (`AKIA[0-9A-Z]{16}`) embedded in source or text files. The finding's `preview` metadata is redacted via the shared `redact()` helper; the raw key never reaches text / JSON / SARIF / GitHub / HTML output (asserted by `internal/report/sensitive_redaction_test.go`).

**Remediation.** Rotate the key, then load credentials from the AWS SDK default provider chain rather than embedding them.

### `sensitive-data.connection-string`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `secrets`

Flags database / queue / cache connection URIs that embed a username and password in the URL - `postgres://user:pass@host`, `mysql://`, `mongodb://`, `mongodb+srv://`, `redis://`, `amqp://`, `amqps://`. Preview is redacted in every output format.

Obvious dev/test placeholders are skipped only when both halves match: the host is local-style (`localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, `db`, `database`, `postgres`) and the embedded password contains a placeholder token such as `change_me`, `placeholder`, `dummy`, `dev_password`, or `test_password`. Real-looking credentials at local hosts still fire.

**Remediation.** Pull the password from environment-specific runtime configuration; keep only the scheme and host in source-controlled strings.

### `sensitive-data.gcp-service-account`

- **Pillar:** sensitive-data
- **Default severity:** **critical**
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags files containing both a `"type": "service_account"` field and a PEM private-key header (`-----BEGIN ... PRIVATE KEY-----`) - the documented shape of a GCP service-account JSON key file. Neither marker alone triggers the rule: `"type": "service_account"` in a doc snippet is harmless, and an isolated PEM key is already covered by `sensitive-data.private-key`. The co-occurrence is the signal.

The finding is located at the line of the `"type"` marker. Both markers are redacted in the preview metadata; the raw private-key body never reaches any output format.

**Overlap with `sensitive-data.private-key`.** Both rules fire independently on a real GCP key file, producing two `critical` findings on the same file: one for the GCP shape, one for the PEM. This matches ADR-007's stance that every rule should emit on its own evidence.

**Remediation.** Rotate the service-account key, delete the JSON file from source-control history, and re-issue credentials through a secret manager or Workload Identity.

### `sensitive-data.github-token`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags GitHub personal-access (`ghp_`), OAuth (`gho_`), user-to-server (`ghu_`), server-to-server (`ghs_`), and refresh (`ghr_`) tokens embedded in source or text files. The single character class `gh[pousr]_` covers all five variants, followed by a 36-255 alphanumeric body matching GitHub's published format.

**Remediation.** Revoke the token in GitHub's settings, then load credentials from a secret manager or environment-specific runtime configuration.

### `sensitive-data.google-api-key`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags Google API keys (`AIza` prefix plus exactly 35 base64url characters) embedded in source or text files. The fixed-width suffix prevents a bare `AIza` prefix from triggering a false positive on unrelated identifiers.

**Remediation.** Delete or restrict the key in the Google Cloud console, then load credentials from a secret manager.

### `sensitive-data.jwt-token`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `secrets`

Flags JWT-shaped literals - three base64url segments separated by dots, the first segment starting with `eyJ` (the literal base64 prefix for `{"`). Tokens can be signing keys, session tokens, or API credentials; the rule does not distinguish.

**Remediation.** Move the token to a secret manager or runtime-only configuration; never check signed tokens into source control. If the literal is a public test vector documented in code, set the preview into `allowlists.secretPreviews` so it stops triggering.

### `sensitive-data.private-key`

- **Pillar:** sensitive-data
- **Default severity:** **critical**
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags PEM-encoded private-key headers (`-----BEGIN ... PRIVATE KEY-----`) embedded in source or text files. The most severe of the sensitive-data rules - a leaked private key is almost always a real incident.

**Remediation.** Remove the key, rotate it, and load it from a secret manager or environment-specific runtime configuration.

### `sensitive-data.secret-pattern`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser

Flags high-risk secret-like literal assignments in Go source and text/config files. Matches assignments like `apiKey := "AKIA…"`, `password = "p@ssw0rd"`, `bearer = "…"`, and `authorization = "Bearer …"`.

All `sensitive-data.*` rules skip Go lines that are entirely comments and honor same-line suppression annotations already common in Go tooling: `#nosec`, `//nolint:gosec`, and `//nolint:all`.

Add documented dummies to `allowlists.secretPreviews` so example values in tests and READMEs aren't flagged.

**Remediation.** Move secrets to a secret manager or environment-specific runtime configuration. Never commit production secrets to source control.

### `sensitive-data.slack-token`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags Slack bot (`xoxb-`), user (`xoxp-`), app (`xoxa-`), and refresh (`xoxr-`) tokens embedded in source or text files. The three-segment body (numeric / numeric / alphanumeric) matches Slack's documented format and avoids matching unrelated `xox`-prefixed identifiers.

**Remediation.** Revoke the token in Slack's app management console, then load credentials from a secret manager.

### `sensitive-data.stripe-key`

- **Pillar:** sensitive-data
- **Default severity:** high
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags Stripe secret (`sk_live_`), publishable (`pk_live_`), and restricted (`rk_live_`) keys against the live (production) environment, followed by ≥24 alphanumeric characters. Test-mode keys (`*_test_`) are intentionally not flagged: they expose only sandbox state.

**Remediation.** Roll the key in the Stripe dashboard, then load credentials from a secret manager.

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

Flags Go functions that exceed the configured code-line threshold. Blank lines, comment-only lines, and lines inside block comments are excluded via `go/scanner`; the finding metadata still includes `rawLines` for the original span. In `_test.go` functions, multiline table fixture literals such as `tests := []struct{ ... }{ ... }` are discounted from the executable line count so case matrices do not dominate the signal. A directly attached `//nolint:funlen` or `//nolint:all` doc comment suppresses one function.

`_test.go` findings use the same threshold and fingerprint identity as production findings, but the built-in default reports them as `low` severity / `medium` confidence unless you explicitly configure a non-medium rule severity.

**Remediation.** Extract cohesive helper functions or split independent branches.

### `size.parameter-count`

- **Pillar:** size
- **Default severity:** low
- **Default-enabled:** yes
- **Threshold:** `maxParameters` (default `8`)
- **Confidence:** high
- **Capability:** parser

Flags functions and methods whose parameter list exceeds the threshold (the method receiver is excluded from the count).

**Remediation.** Group related parameters into a struct, accept an options type, or split the function.

### `test-quality.empty-test`

- **Pillar:** test-quality
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `tests`

Flags top-level `Test…` / `Benchmark…` / `Fuzz…` functions whose body contains no executable statements. An empty test is either an unfinished scaffold left behind by IDE generators or a stub waiting for content - both should be removed or filled in before the build is considered green.

**Remediation.** Add an assertion that exercises the behaviour the test name claims, or remove the empty test entirely.

### `test-quality.no-failure-path`

- **Pillar:** test-quality
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `tests`

Flags `Test…` / `Benchmark…` / `Fuzz…` functions that contain executable statements but never reach a failure call - `t.Error`, `t.Errorf`, `t.Fatal`, `t.Fatalf`, `t.Fail`, `t.FailNow`. A test that cannot fail is asserting nothing and provides false confidence.

The rule walks the function body looking for those methods on the test function's `*testing.T`, `*testing.B`, or `*testing.F` parameter. It also accepts assertion helpers whose function name starts with `Assert`, `Require`, `Expect`, `Must`, or `Check` when a testing receiver is passed as one of the call arguments, such as `testutil.AssertStatus(t, got)`. Locally allocated `*testing.T/B/F` values used to self-test assertion helpers are recognised too. A `MustX()` call that does not receive a testing receiver is still treated as a non-assertion helper.

**Remediation.** Add an assertion, or document why the test cannot fail (e.g. it only exercises compilation).

### `test-quality.skipped-test`

- **Pillar:** test-quality
- **Default severity:** low
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `tests`

Flags Go tests that call `t.Skip`, `t.Skipf`, or `t.SkipNow` unconditionally. Conditional skips inside `if`, `for`, `switch`, `range`, or `select` bodies are treated as legitimate environment guards unless their string-literal message carries a debt marker (`TODO`, `FIXME`, `XXX`, `HACK`, or `WIP`, case-insensitive). Skipped tests are easy to forget and often hide real regressions.

**Remediation.** Remove the skip or document and track the skip condition outside the test body (issue link, build-tag rationale, environment requirement).

## Configuring rules

Every rule above accepts the same override shape. See [`configuration.md`](configuration.md) for the full schema. Common patterns:

```yaml
rules:
  # Tighten a default-enabled rule.
  complexity.cyclomatic:
    threshold: 12
    severity: high

  # Disable a rule for this repo.
  docs.package-comment:
    enabled: false

  # Tune a rule's threshold.
  size.parameter-count:
    threshold: 6

  # Raise a medium default rule to high severity.
  security.shell-command:
    enabled: true
    severity: high
```
