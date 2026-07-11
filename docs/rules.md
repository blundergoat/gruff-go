# Rule Catalog

`gruff-go` ships **83 rules** across **11 pillars**. **70 rules are enabled by default** and 13 rules are opt-in. Projects can disable default rules via `selection.excludeRules` or `rules.<id>.enabled: false`, and can enable opt-in rules with `rules.<id>.enabled: true`.

Opt-in rules: `dead-code.unused-private-const`, `dead-code.unused-private-type`, `dead-code.unused-private-var`, `modernisation.ioutil-deprecated`, `naming.acronym-case`, `naming.get-prefix`, `naming.package-stutter`, `naming.package-underscore`, `naming.receiver-consistency`, `sensitive-data.high-entropy-string`, `sensitive-data.pii-pattern`, `sensitive-data.phi-pattern`, and `test-quality.static-analysis-redundant-test`.

Print the live registry any time with `gruff-go list-rules` (text) or `gruff-go list-rules --format json` (full metadata including thresholds, severities, and capability labels). Add `--no-config` to see the built-in release defaults without project `.gruff-go.yaml` overrides.

## Rule reference

Composite `design.*` rules are score-neutral annotations: they appear in findings, counts, SARIF, GitHub annotations, JSON, and HTML, but they do not add a second scoring penalty on top of the underlying findings that created them.

Generated Go files are skipped by default when their leading comments contain both `generated` and `DO NOT EDIT`, case-insensitive. `--include-ignored` opts those files back into scanning, and rule-level generated-file guards respect that run setting.

`docs.comment-rubric` is path-scoped: it fires only on files listed in its `includePaths` option. Without configured paths it inspects nothing, so its default-on status is a no-op until you opt selected files in.

`docs.config-field-comment` is path-scoped: it enforces doc comments on exported struct fields only for files listed in its `includePaths` option. Without configured paths it inspects nothing, so its default-on status is a no-op until you opt selected configuration schema files in.

| Rule ID | Pillar | Severity | Capability | Default threshold | Description |
|---------|--------|----------|------------|-------------------|-------------|
| [`complexity.cognitive`](#complexitycognitive) | complexity | warning | parser | `maxComplexity: 25` | Functions whose nested control flow and boolean decisions exceed the threshold. |
| [`complexity.cyclomatic`](#complexitycyclomatic) | complexity | warning | parser | `maxComplexity: 20` | Functions whose branch count exceeds the threshold. |
| [`complexity.nesting-depth`](#complexitynesting-depth) | complexity | warning | parser | `maxDepth: 5` | Functions whose nesting depth exceeds the threshold. |
| [`dead-code.empty-block`](#dead-codeempty-block) | dead-code | warning | parser | - | Empty control-flow blocks that usually indicate unfinished code. |
| [`dead-code.unreachable-code`](#dead-codeunreachable-code) | dead-code | advisory | parser | - | Statements after terminal control flow in the same block. |
| [`dead-code.unused-private-const`](#dead-codeunused-private-const) | dead-code | advisory | parser | - | Opt-in candidate for package-private constants that are not referenced in their parsed package. |
| [`dead-code.unused-private-function`](#dead-codeunused-private-function) | dead-code | advisory | parser | - | Package-private top-level functions that are not referenced in their parsed package. |
| [`dead-code.unused-private-type`](#dead-codeunused-private-type) | dead-code | advisory | parser | - | Opt-in candidate for package-private named types that are not referenced in their parsed package. |
| [`dead-code.unused-private-var`](#dead-codeunused-private-var) | dead-code | advisory | parser | - | Opt-in candidate for package-private variables that are not referenced in their parsed package. |
| [`dependency.go-mod-local-replace`](#dependencygo-mod-local-replace) | security | advisory | parser | - | go.mod replace directives that redirect a module to a local filesystem path. |
| [`dependency.go-mod-remote-replace`](#dependencygo-mod-remote-replace) | security | advisory | parser | - | go.mod replace directives that redirect a module to a different remote module. |
| [`design.hotspot-file`](#designhotspot-file) | design | advisory | parser | `minFindings: 3`, `minPillars: 2` | Score-neutral composite triage for files with findings across multiple quality pillars. |
| [`docs.comment-rubric`](#docscomment-rubric) | documentation | warning | parser | `minPackageCommentLines: 1` | Path-scoped maintainer comments for package summaries and declarations. |
| [`docs.config-field-comment`](#docsconfig-field-comment) | documentation | warning | parser | - | Doc comments on exported struct fields, optionally scoped with `includePaths`. |
| [`docs.exported-symbol-comment`](#docsexported-symbol-comment) | documentation | advisory | parser | - | Exported declarations missing a doc comment. |
| [`docs.package-comment`](#docspackage-comment) | documentation | advisory | parser | - | Packages with no package-level comment in any file. |
| [`docs.suppression-without-rationale`](#docssuppression-without-rationale) | documentation | advisory | parser | - | `nolint` and `nosec` suppression comments that do not explain why the suppression is intentional. |
| [`maintainability.context-todo-production`](#maintainabilitycontext-todo-production) | maintainability | advisory | parser | - | `context.TODO()` calls in production files. |
| [`maintainability.defer-in-loop`](#maintainabilitydefer-in-loop) | maintainability | advisory | parser | - | `defer` statements directly inside loops, where cleanup is delayed until the enclosing function returns. |
| [`maintainability.ignored-error`](#maintainabilityignored-error) | maintainability | advisory | parser | - | Error-looking values assigned directly to the blank identifier. |
| [`maintainability.log-fatal-library`](#maintainabilitylog-fatal-library) | maintainability | advisory | parser | - | `log.Fatal*` and `os.Exit` calls outside command entrypoints and tests. |
| [`maintainability.loop-variable-address`](#maintainabilityloop-variable-address) | maintainability | advisory | parser | - | Storing, returning, or appending the address of a range variable copy. |
| [`maintainability.production-panic`](#maintainabilityproduction-panic) | maintainability | advisory | parser | - | Literal panic calls in reusable production code. |
| [`modernisation.ioutil-deprecated`](#modernisationioutil-deprecated) | modernisation | advisory | parser | - | Deprecated `io/ioutil` APIs with direct `io` or `os` replacements. |
| [`naming.acronym-case`](#namingacronym-case) | naming | advisory | parser | - | Identifiers that spell Go initialisms with mixed casing. |
| [`naming.contextual-generic`](#namingcontextual-generic) | naming | advisory | parser | `minBodyLines: 15`, `minFunctionLines: 50` | Generic names used only when the surrounding loop or function is large enough that context is weak. |
| [`naming.get-prefix`](#namingget-prefix) | modernisation | advisory | parser | - | Accessor-style receiver methods with a discouraged `Get` prefix. |
| [`naming.identifier-quality`](#namingidentifier-quality) | naming | advisory | parser | - | Local identifiers matching a placeholder name list. |
| [`naming.misspelling`](#namingmisspelling) | naming | advisory | parser | - | Identifiers, doc comments, and struct tags containing common programming misspellings. |
| [`naming.negated-boolean`](#namingnegated-boolean) | naming | advisory | parser | - | Boolean identifiers using negation prefixes (No/Not/Disable…) that force double-negation at call sites. |
| [`naming.package-stutter`](#namingpackage-stutter) | naming | advisory | parser | - | Exported identifiers whose lowercase form starts with their own package name (`config.ConfigOptions`). |
| [`naming.package-underscore`](#namingpackage-underscore) | naming | advisory | parser | - | Package names containing underscores. |
| [`naming.receiver-consistency`](#namingreceiver-consistency) | naming | advisory | parser | - | Methods on the same type with inconsistent receiver names or pointer/value forms. |
| [`security.archive-path-traversal`](#securityarchive-path-traversal) | security | advisory | parser | - | Archive entry paths joined into extraction destinations without containment evidence. |
| [`security.github-actions-broad-permissions`](#securitygithub-actions-broad-permissions) | security | advisory | parser | - | Workflows granting blanket write access (permissions: write-all or bare write). |
| [`security.github-actions-pull-request-target`](#securitygithub-actions-pull-request-target) | security | advisory | parser | - | pull_request_target workflows that also check out or run code. |
| [`security.github-actions-remote-shell`](#securitygithub-actions-remote-shell) | security | advisory | parser | - | Workflow run steps piping a remote download into a shell. |
| [`security.github-actions-secrets-in-pr`](#securitygithub-actions-secrets-in-pr) | security | advisory | parser | - | Pull-request workflows referencing a named secret other than GITHUB_TOKEN. |
| [`security.github-actions-unpinned-action`](#securitygithub-actions-unpinned-action) | security | advisory | parser | - | Third-party actions pinned to a mutable branch ref instead of a tag or SHA. |
| [`security.http-client-no-timeout`](#securityhttp-client-no-timeout) | security | advisory | parser | - | `http.Client` literals in production files without `Timeout`. |
| [`security.http-server-no-timeout`](#securityhttp-server-no-timeout) | security | advisory | parser | - | Production `http.Server` literals and `ListenAndServe` helpers without explicit timeout controls. |
| [`security.insecure-random-secret`](#securityinsecure-random-secret) | security | advisory | parser | - | `math/rand` calls used in token, nonce, session, key, or other secret-looking contexts. |
| [`security.open-redirect-candidate`](#securityopen-redirect-candidate) | security | advisory | parser | - | Request-derived values used as a redirect target without validation. |
| [`security.path-traversal-file-access`](#securitypath-traversal-file-access) | security | advisory | parser | - | Request-derived paths reaching filesystem sinks without containment evidence. |
| [`security.permissive-file-mode`](#securitypermissive-file-mode) | security | advisory | parser | - | File and directory calls using world-writable or overly permissive literal modes. |
| [`security.request-body-without-limit`](#securityrequest-body-without-limit) | security | advisory | parser | - | Full reads of `http.Request.Body` without local size-limit evidence. |
| [`security.request-controlled-url`](#securityrequest-controlled-url) | security | advisory | parser | - | Request-derived values used as an outbound HTTP request URL without allowlist/validation (SSRF). |
| [`security.sensitive-data-logging`](#securitysensitive-data-logging) | security | advisory | parser | - | Logging calls whose arguments carry secret-named values, secret env reads, or request auth headers/cookies. |
| [`security.shell-command`](#securityshell-command) | security | error | parser | - | `exec.Command` invocations that route through a shell interpreter. |
| [`security.sql-string-query`](#securitysql-string-query) | security | advisory | parser | - | SQL execution calls with query arguments built by formatting or concatenation. |
| [`security.template-injection-xss`](#securitytemplate-injection-xss) | security | advisory | parser | - | Request-derived values reaching an HTML response without escaping (text/template, unsafe `template.HTML`, raw writes). |
| [`security.tls-insecure-config`](#securitytls-insecure-config) | security | warning | parser | - | `tls.Config` literals that disable verification or allow obsolete TLS versions. |
| [`security.unsafe-deserialization`](#securityunsafe-deserialization) | security | advisory | parser | - | Decoding request-controlled input via `encoding/gob` or `gopkg.in/yaml`. |
| [`security.weak-crypto`](#securityweak-crypto) | security | advisory | parser | - | MD5/SHA1 in security contexts, DES/RC4 construction, or RSA keys below 2048 bits. |
| [`security.xxe-candidate`](#securityxxe-candidate) | security | advisory | parser | - | `xml.Decoder` configured with a custom entity map (possible XXE); stdlib XML is safe by default. |
| [`sensitive-data.anthropic-api-key`](#sensitive-dataanthropic-api-key) | sensitive-data | error | parser | - | Anthropic API key literals (`sk-ant-…`). |
| [`sensitive-data.aws-access-key`](#sensitive-dataaws-access-key) | sensitive-data | error | parser | - | AWS access key id (AKIA…) literals. |
| [`sensitive-data.connection-string`](#sensitive-dataconnection-string) | sensitive-data | error | parser | - | Database/queue URLs with embedded passwords. |
| [`sensitive-data.gcp-service-account`](#sensitive-datagcp-service-account) | sensitive-data | error | parser | - | Files containing both `"type": "service_account"` and a PEM private-key header (GCP service-account JSON keys). |
| [`sensitive-data.github-token`](#sensitive-datagithub-token) | sensitive-data | error | parser | - | GitHub PAT / OAuth / user / server / refresh tokens (`gh[pousr]_…`). |
| [`sensitive-data.gitlab-token`](#sensitive-datagitlab-token) | sensitive-data | error | parser | - | GitLab personal, trigger, runner, and application token literals. |
| [`sensitive-data.google-api-key`](#sensitive-datagoogle-api-key) | sensitive-data | error | parser | - | Google API key literals (`AIza…`). |
| [`sensitive-data.high-entropy-string`](#sensitive-datahigh-entropy-string) | sensitive-data | warning | parser | `minLength: 20`, `entropy: 4.5` | Opt-in. Long high-entropy tokens no provider rule covers. |
| [`sensitive-data.jwt-token`](#sensitive-datajwt-token) | sensitive-data | error | parser | - | JWT-shaped literals (`eyJ…`). |
| [`sensitive-data.npm-token`](#sensitive-datanpm-token) | sensitive-data | error | parser | - | npm access token literals (`npm_…` / `npm_pat_…`). |
| [`sensitive-data.phi-pattern`](#sensitive-dataphi-pattern) | sensitive-data | warning | parser | - | Opt-in. US SSN, Medicare MBI, and labelled MRN identifiers. |
| [`sensitive-data.pii-pattern`](#sensitive-datapii-pattern) | sensitive-data | warning | parser | - | Opt-in. Email, phone, and Luhn-valid payment-card numbers. |
| [`sensitive-data.private-key`](#sensitive-dataprivate-key) | sensitive-data | error | parser | - | PEM-encoded private keys embedded in source. |
| [`sensitive-data.secret-pattern`](#sensitive-datasecret-pattern) | sensitive-data | error | parser | - | High-risk secret-like key/value assignments. |
| [`sensitive-data.slack-token`](#sensitive-dataslack-token) | sensitive-data | error | parser | - | Slack bot / user / app / refresh tokens (`xox[bpar]-…`). |
| [`sensitive-data.stripe-key`](#sensitive-datastripe-key) | sensitive-data | error | parser | - | Stripe live secret / publishable / restricted keys (`(sk\|pk\|rk)_live_…`). |
| [`size.file-length`](#sizefile-length) | size | advisory | parser | `maxLines: 500` | Files exceeding the line-count threshold. |
| [`size.function-length`](#sizefunction-length) | size | warning | parser | `maxLines: 80` | Functions exceeding the code-line threshold. |
| [`size.parameter-count`](#sizeparameter-count) | size | advisory | parser | `maxParameters: 8` | Functions whose parameter list exceeds the threshold. |
| [`test-quality.empty-test`](#test-qualityempty-test) | test-quality | warning | parser | - | `Test…` / `Benchmark…` / `Fuzz…` functions with empty bodies. |
| [`test-quality.fatal-in-goroutine`](#test-qualityfatal-in-goroutine) | test-quality | advisory | parser | - | `t.Fatal`, `t.Fatalf`, and `t.FailNow` calls inside goroutines. |
| [`test-quality.helper-missing-t-helper`](#test-qualityhelper-missing-t-helper) | test-quality | advisory | parser | - | Failing test helpers that never call `t.Helper()`. |
| [`test-quality.no-failure-path`](#test-qualityno-failure-path) | test-quality | advisory | parser | - | Test functions that contain code but never reach a failure call or recognised assertion helper. |
| [`test-quality.parallel-range-capture`](#test-qualityparallel-range-capture) | test-quality | advisory | parser | - | Parallel subtests in pre-Go 1.22 modules that capture range variables without an explicit shadow copy. |
| [`test-quality.skipped-test`](#test-qualityskipped-test) | test-quality | advisory | parser | - | Unconditional or debt-marked tests that call `t.Skip*`. |
| [`test-quality.sleep-in-test`](#test-qualitysleep-in-test) | test-quality | advisory | parser | - | `time.Sleep` calls in tests. |
| [`test-quality.static-analysis-redundant-test`](#test-qualitystatic-analysis-redundant-test) | test-quality | advisory | parser | - | Opt-in candidate for test assertions that restate parser-visible code-shape facts. |
| [`test-quality.tempdir-misuse`](#test-qualitytempdir-misuse) | test-quality | advisory | parser | - | `os.MkdirTemp("", …)` and `ioutil.TempDir("", …)` in tests where `t.TempDir()` is available. |

Default size thresholds are production-oriented and stay unchanged for `_test.go` files. Warning-severity size findings in `_test.go` files still emit with the same threshold, message, and fingerprint identity, but are reported as `advisory` severity / `medium` confidence so table-driven and integration-test bulk does not carry the same score and exit-code weight as production code. Advisory defaults such as `size.file-length` are already softened, and non-warning severity overrides in config apply to test files too.

## Severity tiers

Every rule has a default severity; configs can override per rule. ADR-009 collapsed the internal scale to three buckets that match the cross-port canonical model used by gruff-rs / gruff-ts / gruff-py / gruff-php:

| Severity | Default penalty weight | HTML colour | Use it for |
|----------|------------------------|-------------|------------|
| `error` | 30 | red | Almost certainly broken; block merges. |
| `warning` | 8 | amber | Worth fixing in the next clean-up pass. |
| `advisory` | 1 | muted | Informational; trend over time. |

The `--min-severity` flag (default `advisory`) sets the threshold at which findings flip the exit code from `0` to `1`. The previous five-bucket vocabulary (`critical`, `high`, `medium`, `low`, `info`) and its aliases (`notice`, `warn`) are no longer accepted by config or CLI parsing - see [CHANGELOG `[0.2.0]`](../CHANGELOG.md#020---2026-05-27) for the mapping.

## Per-rule reference

### `complexity.cognitive`

- **Pillar:** complexity
- **Default severity:** warning
- **Default-enabled:** yes
- **Threshold:** `maxComplexity` (default `25`)
- **Confidence:** high
- **Capability:** parser
- **Tags:** `metric`

Flags Go functions whose parser-only cognitive complexity exceeds the configured threshold. The metric adds one point for each `if`, loop, `switch`, type switch, and `select`, adds the current nesting level for nested control flow, and adds one point for each `&&` / `||` operator inside conditions. Function literals reset the count.

This is intentionally separate from `complexity.cyclomatic`: cyclomatic counts independent branch paths, while cognitive complexity emphasizes nesting and review difficulty.

**Remediation.** Flatten nested branches, return early on guard conditions, or extract cohesive helper functions.

### `complexity.cyclomatic`

- **Pillar:** complexity
- **Default severity:** warning
- **Default-enabled:** yes
- **Threshold:** `maxComplexity` (default `20`)
- **Confidence:** high
- **Capability:** parser

Flags Go functions whose branch count exceeds the configured cyclomatic complexity threshold. The metric counts `if`, `for`, `range`, `case` (when the case has labels), `select` cases, and `&&` / `||` short-circuit operators.

Each finding's metadata carries the measured `complexity` and the active `threshold`. The score object's `complexityDistribution` is finding-only: it bins over-threshold `complexity.cyclomatic` findings, not every parsed function. All-zero bins mean no over-threshold complexity findings were reported.

**Remediation.** Split independent decisions, move branches into named helpers, or return early on guard conditions.

### `complexity.nesting-depth`

- **Pillar:** complexity
- **Default severity:** warning
- **Default-enabled:** yes
- **Threshold:** `maxDepth` (default `5`)
- **Confidence:** high
- **Capability:** parser

Flags functions whose maximum control-flow nesting depth exceeds the threshold. Function literals reset the depth counter so callbacks aren't double-counted as part of their enclosing function.

**Remediation.** Extract nested branches into named helpers or return early on guard conditions.

### `dead-code.empty-block`

- **Pillar:** dead-code
- **Default severity:** warning
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser

Flags empty control-flow blocks (`if {}`, `for {}`, `switch {}`, etc.) that usually indicate unfinished or accidentally orphaned code.

**Remediation.** Remove the empty block or add the intended implementation.

### `dead-code.unreachable-code`

- **Pillar:** dead-code
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `control-flow`

Flags statements that follow `return`, `panic`, `break`, `continue`, or `goto` in the same lexical block. It also treats an `if`/`else`, `switch`, type switch, or `select` as terminal when every syntactic branch exits. Switch and type-switch checks require a `default` case and skip `fallthrough` shapes so reachable-after-branch code is not mislabelled. Labels reset the same-block check because a `goto` may target the label.

**Remediation.** Remove the unreachable statement or move it before the terminating control-flow statement.

### `dead-code.unused-private-const`

- **Pillar:** dead-code
- **Default severity:** advisory
- **Default-enabled:** no
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `candidate`, `cross-file`, `dead-code`

Opt-in candidate for package-private top-level constants whose names are not referenced anywhere else in the same parsed package. Test files, generated files, vendor paths, reflection-heavy packages, iota groups, and multi-name const specs are excluded to keep parser-only evidence precision-first.

**Remediation.** Delete the constant if it is abandoned, or leave the candidate disabled where grouped constants or build tags make parser-only certainty too weak.

### `dead-code.unused-private-function`

- **Pillar:** dead-code
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `cross-file`, `dead-code`

Flags package-private top-level functions whose names are not referenced anywhere else in the same parsed package. Methods, `init`, `main`, external `_test` packages, and packages that import `reflect` are excluded so reflection-heavy or entrypoint-driven code does not produce parser-only false positives.

**Remediation.** Remove the unused helper, make the missing call explicit, or rename/export it only when another package is expected to call it.

### `dead-code.unused-private-type`

- **Pillar:** dead-code
- **Default severity:** advisory
- **Default-enabled:** no
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `candidate`, `cross-file`, `dead-code`

Opt-in candidate for package-private top-level types whose names are not referenced anywhere else in the same parsed package. Test files, generated files, vendor paths, and reflection-heavy packages are excluded, and name collisions elsewhere in the package suppress the finding because the rule does not resolve bindings.

**Remediation.** Delete the type if it is abandoned, or keep the rule opt-in until reflective and build-tagged references are ruled out for the package.

### `dead-code.unused-private-var`

- **Pillar:** dead-code
- **Default severity:** advisory
- **Default-enabled:** no
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `candidate`, `cross-file`, `dead-code`

Opt-in candidate for package-private top-level variables whose names are not referenced anywhere else in the same parsed package. Test files, generated files, vendor paths, reflection-heavy packages, blank identifiers, and common registration tables are excluded to avoid noisy parser-only false positives.

**Remediation.** Delete the variable if it is abandoned, or keep the rule opt-in where indirect registration or build-tagged references are part of the package contract.

### `dependency.go-mod-local-replace`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `dependency`, `security`, `supply-chain`

Flags `go.mod` replace directives whose replacement target is a local filesystem path (`./…`, `../…`, an absolute path, or a Windows drive path), in both the single-line and block (`replace ( … )`) forms. Local replacements do not reproduce for other clones or CI and usually indicate in-progress local development that should not ship. Scanned as text; no `go list` or proxy queries.

Each finding's metadata carries the replacement target.

**Remediation.** Remove the local replace before shipping and depend on a published module version, or vendor the dependency explicitly.

### `dependency.go-mod-remote-replace`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `dependency`, `security`, `supply-chain`

Flags `go.mod` replace directives whose replacement target is a different remote module path or version. Remote replacements silently swap a dependency's source and warrant a supply-chain review. Scanned as text; no `go list` or proxy queries.

Each finding's metadata carries the replacement target.

**Remediation.** Confirm the replacement module and version are trusted and intentional, and prefer pinning the original module to a vetted release where possible.

### `design.hotspot-file`

- **Pillar:** design
- **Default severity:** advisory
- **Default-enabled:** yes
- **Threshold:** `minFindings` (default `3`), `minPillars` (default `2`)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `composite`

Emits score-neutral composite triage for files with at least `minFindings` findings across at least `minPillars` distinct non-design pillars. Composite findings do not feed other composite rules: design-pillar findings (including hotspot-file's own output) are excluded from the evidence the rule counts. Treat this as a grouping hint over the underlying findings, not a separate fix target.

**Remediation.** Triage the file as a cluster, then fix the underlying findings. Once the underlying findings are handled, the composite disappears; there is no separate hotspot-only edit to make.

### `docs.comment-rubric`

- **Pillar:** documentation
- **Default severity:** warning
- **Default-enabled:** yes
- **Threshold:** `minPackageCommentLines` (default `1`)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `comments`, `documentation`, `rubric`

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
```

**Remediation.** Add maintainer-oriented package summaries and directly attached comments for the selected declaration kinds. When `minWordsBeyondSymbol` is set, replace name-restatement summaries with substantive context.

### `docs.config-field-comment`

- **Pillar:** documentation
- **Default severity:** warning
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `comments`, `documentation`, `struct-fields`

Flags exported fields on struct types declared inside configured `includePaths` that have no useful doc comment. The "useful comment" check is shared with `docs.comment-rubric`: the comment must exist (at least one non-empty line) and must normalise differently from the field name itself. Embedded fields (no `Names` on the `*ast.Field`) and unexported fields are out of scope and never produce findings.

The rule is default-enabled and intended for user-facing configuration schema types where every knob deserves documentation. When `includePaths` is unset the rule is a no-op; add the config/schema files you want enforced.

```yaml
rules:
  docs.config-field-comment:
    enabled: true
    severity: advisory
    options:
      includePaths:
        - internal/config/config.go
        - internal/analysis/report.go
```

**Remediation.** Add a doc comment to every exported field of structs declared in the configured `includePaths`.

### `docs.exported-symbol-comment`

- **Pillar:** documentation
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser

Flags exported top-level Go declarations (functions, methods on exported types, types, vars, consts) that have no doc comment.

Set `ignoreInternalPackages: false` when internal package exports should follow the same documentation bar as public API packages.

**Remediation.** Add a Go-style doc comment that begins with the symbol name.

### `docs.package-comment`

- **Pillar:** documentation
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser

Flags Go packages that have no package-level comment in any file. Package comments are the standard `godoc` entry point and are cheap to add. `_test.go`-only external test packages such as `package foo_test` are skipped because they normally document black-box tests, not a production package API.

**Remediation.** Add a package comment that explains the package's responsibility, scope, and the public surface.

### `docs.suppression-without-rationale`

- **Pillar:** documentation
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `comments`, `documentation`

Flags `//nolint` and `#nosec` suppression comments that contain only the directive, rule list, or punctuation. Suppressions with explicit rationale markers such as `-- reason`, `// reason`, or a nearby `reason:` comment pass. Go files are inspected through parsed comment groups so raw string fixtures and prose that merely mention suppression syntax are ignored; text/config files are scanned only when the line itself starts with a suppression directive.

**Remediation.** Add a short reason that explains why the suppression is intentional, or remove the suppression if it is no longer needed.

### `maintainability.context-todo-production`

- **Pillar:** maintainability
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `context`

Flags `context.TODO()` calls in production files. Test files, `testdata`, and example paths are skipped. The rule reports static evidence only: it does not claim cancellation is broken, only that ownership is still expressed as a TODO placeholder in production code.

**Remediation.** Accept a caller-provided context or use a documented bootstrap context where cancellation is intentionally unavailable.

### `maintainability.defer-in-loop`

- **Pillar:** maintainability
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `lifecycle`

Flags `defer` statements directly inside `for` and `range` loop bodies. Deferred cleanup runs when the enclosing function returns, not at the end of the current iteration, so loop-scoped resources can stay open longer than intended. Defers inside function literals launched or called from the loop are treated as their own function scope and are not reported.

**Remediation.** Move the loop body into a helper function, call cleanup explicitly at the end of the iteration, or use `t.Cleanup` in tests when test lifecycle semantics are intended.

### `maintainability.ignored-error`

- **Pillar:** maintainability
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `errors`

Flags direct assignments of error-looking values to the blank identifier, such as `_ = err`, `_ = runErr`, or `_ = fmt.Errorf(...)`. The rule deliberately does not flag arbitrary `_ = call()` shapes because parser-only analysis cannot prove return types without type information.

Each finding's metadata carries the ignored expression and the parser-only evidence kind.

**Remediation.** Handle the error, return it to the caller, or document why ignoring it is safe.

### `maintainability.log-fatal-library`

- **Pillar:** maintainability
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `errors`, `lifecycle`

Flags `log.Fatal`, `log.Fatalf`, `log.Fatalln`, and `os.Exit` calls outside command entrypoints, `package main`, tests, and generated files. Reusable packages should return errors to callers rather than terminating the whole process.

**Remediation.** Return an error and let the command or service bootstrap layer decide whether process termination is appropriate.

### `maintainability.loop-variable-address`

- **Pillar:** maintainability
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `loops`

Flags storing, returning, sending, or appending the address of a range key/value variable when the loop retains shared-variable semantics. Assignment-form loops (`for key, value = range items`) always reuse preexisting variables, so their escaping addresses flag for every Go version and even without module metadata.

Declaration-form loops (`for key, value := range items`) flag only when the nearest `go.mod` selects a language version before Go 1.22. Go 1.22 introduced a new key/value variable for each declaration-form iteration, so those loops are silent in modules declaring Go 1.22 or newer. A found `go.mod` without a `go` directive has Go's implicit 1.16 semantics and flags; when no `go.mod` is resolvable between the file and scan root, the version-dependent declaration case stays silent rather than guessing. The gate is applied to each range statement, so a modern module can suppress a `:=` loop while still reporting an `=` loop in the same file.

Taking an indexed element address such as `&slice[i]` remains accepted, as does a range-variable address used only within the current iteration without a known escaping store.

**Remediation.** Prefer declaration-form iteration variables in Go 1.22+ modules, take the address of the indexed element, copy the value into a deliberately scoped local before taking its address, or change the data structure to store values instead of pointers.

### `maintainability.production-panic`

- **Pillar:** maintainability
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `errors`

Flags direct `panic` calls with literal message evidence in reusable production code. Test files, `package main`, `cmd/` paths, `init`, `main`, `Defaults`, and `Must*` functions are exempt. `panic(err)` is not reported because this parser-only rule cannot distinguish impossible invariant failures from ordinary error flow.

**Remediation.** Return an error or fail during command/bootstrap setup instead of panicking from reusable production code.

### `modernisation.ioutil-deprecated`

- **Pillar:** modernisation
- **Default severity:** advisory
- **Default-enabled:** no
- **Confidence:** high
- **Capability:** parser
- **Tags:** `go-style`

Flags `io/ioutil` selectors that have direct modern replacements: `io.ReadAll`, `os.ReadFile`, `os.WriteFile`, `io.NopCloser`, `io.Discard`, `os.MkdirTemp`, and `os.CreateTemp`.

Each finding's metadata carries the deprecated API and replacement API.

**Remediation.** Replace `io/ioutil` calls with the matching `io` or `os` package API.

### `naming.acronym-case`

- **Pillar:** naming
- **Default severity:** advisory
- **Default-enabled:** no
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `go-style`, `naming`

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
- **Default severity:** advisory
- **Default-enabled:** yes
- **Threshold:** `minBodyLines` (default `15`), `minFunctionLines` (default `50`)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `naming`
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

- **Pillar:** modernisation
- **Default severity:** advisory
- **Default-enabled:** no
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `go-style`, `naming`

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
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `naming`

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
- **Default severity:** advisory
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
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `go-style`, `naming`
- **Options:**
  - `prefixes []string` - default `[No, Not, Disable, Disallow, Without, Suppress]`
  - `allowList []string` - default `[NoOp, Notify, Notice, Now, NoCopy, Notation, Notebook, NoConfig, NoBaseline, NoInteraction]` (English words and CLI/config flag vocabulary that begin with a prefix but are not negations)
  - `scope string` - default `"exported"`; alternatives `"all"` and `"locals"`

Flags boolean identifiers (struct fields, function parameters, function results, `var`/`const` declarations) whose names begin with a negation prefix followed by an uppercase letter. Negated names force double-negation at call sites (`if !state.NoCache`) and obscure the actual intent. Public CLI/config vocabulary that mirrors flags such as `--no-config`, `--no-baseline`, and `--no-interaction` is accepted by default.

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

**Remediation.** Rename to the positive form: `NoCache` → `SkipCache` if the boolean still means "skip", or `EnableCache` with inverted truth values if you want callers to read positive logic. CLI/config flag names like `--no-config` can stay as the public surface.

### `naming.package-stutter`

- **Pillar:** naming
- **Default severity:** advisory
- **Default-enabled:** no
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
- **Default severity:** advisory
- **Default-enabled:** no
- **Confidence:** high
- **Capability:** parser
- **Tags:** `go-style`

Flags Go package names that use underscores instead of short lowercase words (the Go convention favours `oauth2`, not `o_auth_2`). Idiomatic external test packages such as `package api_test` in `_test.go` files are exempt; package names like `bad_pkg_test` still fire because the production-name portion contains an underscore.

**Remediation.** Rename the package to a short lowercase name without underscores. Use a package-relative import alias at the call sites if the change ripples wider than expected.

### `naming.receiver-consistency`

- **Pillar:** naming
- **Default severity:** advisory
- **Default-enabled:** no
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `go-style`, `naming`

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
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `archive`, `security`

Flags Go files that import `archive/zip` or `archive/tar` and join an archive entry `Name` into an extraction destination without obvious containment evidence. The parser-only check recognises direct entry names such as `file.Name`, locals assigned from `header.Name`, and `filepath.Join` / `path.Join` calls. It suppresses when the same function contains obvious containment or sanitisation evidence such as `filepath.Clean`, `filepath.Rel`, `strings.HasPrefix`, or helper names containing `safe`, `sanitize`, `within`, or `contains`.

Each finding's metadata carries the archive entry expression and the missing check kind.

**Remediation.** Clean the joined path and verify it remains inside the extraction root before creating files.

### `security.github-actions-broad-permissions`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `ci`, `github-actions`, `security`

Flags GitHub Actions workflows that grant blanket write access with `permissions: write-all` or a bare `permissions: write`. Scoped grants such as a `permissions:` block with `contents: write` underneath are not flagged. Workflow YAML under `.github/workflows` is scanned as text.

**Remediation.** Grant the least-privilege permission scopes the workflow needs (for example `contents: read`) instead of blanket write access.

### `security.github-actions-pull-request-target`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `ci`, `github-actions`, `security`

Flags workflows triggered by `pull_request_target` that also check out or run code. `pull_request_target` runs with repository secrets in the context of a fork's pull request, so executing PR-controlled code can leak them. Candidate wording.

**Remediation.** Use `pull_request` for untrusted contributions, or keep `pull_request_target` jobs free of fork-controlled checkout and execution.

### `security.github-actions-remote-shell`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `ci`, `github-actions`, `security`

Flags workflow run steps that download a remote script with `curl`/`wget`/`Invoke-WebRequest` and pipe it into a shell (for example `curl … | bash`), executing unreviewed remote code in CI.

**Remediation.** Download the script to a file, verify its checksum, and review it before executing rather than piping a remote download into a shell.

### `security.github-actions-secrets-in-pr`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `ci`, `github-actions`, `security`

Flags workflows triggered by `pull_request` or `pull_request_target` that reference a named secret other than the auto-provided `GITHUB_TOKEN`, exposing it to fork-controlled runs. Candidate wording. Each finding's metadata carries the referenced secret name.

**Remediation.** Keep named secrets out of pull-request-triggered workflows; gate secret-using jobs on a trusted event such as push or `workflow_run`.

### `security.github-actions-unpinned-action`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `ci`, `github-actions`, `security`

Flags third-party GitHub Actions referenced by a mutable branch ref (for example `@main` or `@master`), which a maintainer can repoint to new code without review. Version-shaped tags (`@v4`, `@v4.1.0`) and full 40-character commit-SHA pins pass, and first-party `actions/*` and `github/*` are exempt. Each finding's metadata carries the action and ref.

**Remediation.** Pin third-party actions to a release tag or a full commit SHA instead of a branch ref so the referenced code cannot change underneath you.

### `security.http-client-no-timeout`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `http`, `security`

Flags `http.Client` composite literals in production files that do not set the `Timeout` field. Test files and example paths are skipped. The rule reports literal construction evidence only; it does not infer timeout ownership through wrapper factories or later assignments.

**Remediation.** Set `http.Client.Timeout` or use a shared client whose timeout ownership is explicit.

### `security.http-server-no-timeout`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `http`, `security`

Flags production `http.Server` composite literals that omit all explicit timeout controls (`ReadHeaderTimeout`, `ReadTimeout`, and `WriteTimeout`) and direct `http.ListenAndServe` / `http.ListenAndServeTLS` helper calls. The rule reports static-risk evidence only; it does not claim exploitability without deployment context.

**Remediation.** Construct an `http.Server` with explicit read/header/write timeout ownership before calling `ListenAndServe`.

### `security.insecure-random-secret`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `random`, `security`

Flags Go files that import `math/rand` and use package-level random APIs in secret-looking contexts such as token, nonce, session, password, key, CSRF, salt, OTP, or OAuth state generation. The parser-only check looks at the enclosing function name, assignment target, and call arguments, so ordinary sampling, shuffling, simulation, benchmark, and test-randomness names are ignored unless the surrounding symbol clearly carries a production-secret term. `crypto/rand` is not flagged.

Each finding's metadata carries the random API and context word.

**Remediation.** Use `crypto/rand` for security-sensitive random values and keep `math/rand` for sampling, tests, and simulations.

### `security.open-redirect-candidate`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `http`, `redirect`, `security`

Flags request-derived values passed to `http.Redirect` or a `Location` response header without an affirmative allowlist, validator, or relative-path check (possible open redirect). Uses bounded same-function evidence: the request value can be inline (`r.FormValue`, `r.URL.Query().Get`) or a local tainted from one. Safe evidence is a literal committed path segment such as `"/account/" + value`, an exiting `HasPrefix(value, "/account/")` guard, a loop that strips every leading protocol-relative `//`, an exact validator/allowlist/local/relative identifier token, or an explicit parsed HTTP scheme-and-host allowlist. A bare `HasPrefix(value, "/")`, `url.Parse`, or a helper whose name merely contains `parse`, `prefix`, `allow`, or `trusted` is not destination validation. Candidate wording.

Each finding's metadata carries the redirect sink and request source label, never a raw value.

**Remediation.** Validate redirect targets against an allowlist or require a relative path before redirecting request-derived destinations.

### `security.path-traversal-file-access`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `filesystem`, `path-traversal`, `security`

Flags request-derived values passed to filesystem sinks (`os.Open`, `os.ReadFile`, `os.OpenFile`, `os.Create`, `os.WriteFile`, `os.Remove`, `ioutil.ReadFile`, …) or `http.ServeFile` without nearby `filepath.Rel`, `filepath.IsLocal`, basename reduction, or a containment helper. `filepath.Clean` / `path.Clean` preserve request taint because normalising a path does not prove it stayed under the intended base directory. Taint propagates through `filepath.Join`/`path.Join`, `filepath.Clean`/`path.Clean`, and string concatenation but not through arbitrary helpers, so a sanitising wrapper breaks the chain. Candidate wording, bounded same-function evidence.

Each finding's metadata carries the filesystem sink and request source label.

**Remediation.** Constrain request-derived paths with `filepath.Clean` plus a containment check (`filepath.Rel`/`IsLocal`) or reduce them to a basename before opening files.

### `security.permissive-file-mode`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `filesystem`, `security`

Flags literal file and directory modes in `os.OpenFile`, `os.Chmod`, `os.Mkdir`, and `os.MkdirAll` when they are world-writable or, for file creation/chmod calls, world-executable. The rule recognises octal, `0o` literals, and `os.ModePerm`; it does not guess through named constants when the literal value is not visible in the expression.

**Remediation.** Use least-privilege modes such as `0600`, `0640`, `0644`, `0700`, or `0755` depending on whether the target is a file or directory.

### `security.request-body-without-limit`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `http`, `security`

Flags `io.ReadAll` or `ioutil.ReadAll` calls that read a handler's `*http.Request.Body` directly in production files without local evidence of `http.MaxBytesReader` or `io.LimitReader`. Reads of unrelated `io.Reader` values, test files, and already-limited wrapper expressions are ignored.

Each finding's metadata carries the request parameter name and read call.

**Remediation.** Wrap request bodies with `http.MaxBytesReader` or `io.LimitReader` before reading them fully.

### `security.request-controlled-url`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `http`, `security`, `ssrf`

Flags request-derived values passed as the URL of an outbound `net/http` request (`http.Get`/`Head`/`Post`/`PostForm`, `http.NewRequest`/`NewRequestWithContext`, or the same methods on an `http.Client` value) without an affirmative destination constraint (possible SSRF). The request value may be inline or a same-function local tainted from a request accessor, including through `io.ReadAll(r.Body)`, string concatenation, `fmt.Sprintf`, and assigned `url.Parse`/`url.ParseRequestURI` results. Parsing validates syntax only and never suppresses the finding by itself.

Safe evidence is an exact validator/allowlist identifier token that references the sink value, explicit earlier guards that reject every parsed URL outside an allowed HTTP scheme and exact host, or construction from a fixed trusted base. Identifier matching is token-based: `validateURL` and `isAllowedDestination` count, while `parser`, `parseAndReturn`, `allowanceURL`, `untrustedURL`, `notTrustedURL`, and `disallowHost` do not. Candidate wording.

Each finding's metadata carries the HTTP sink and request source label.

**Remediation.** Validate request-derived URLs against an allowlist of trusted hosts, or build the request URL from a fixed base before fetching.

### `security.sensitive-data-logging`

- **Pillar:** security
- **Secondary pillar:** sensitive-data
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `logging`, `security`, `sensitive-data`

Flags logging and print calls (`log.*`, `fmt.Print*`/`Fprint*`, `log/slog`, and methods on a logger-named receiver) whose arguments carry credentials: identifiers whose name contains `password`/`secret`/`credential`/`bearer`/`passphrase`, secret-named `os.Getenv`/`os.LookupEnv` reads, or request `Authorization`/`Cookie` reads. Static text-only messages, non-secret values, plain form values, and values wrapped in a redaction/hash helper are ignored. Candidate wording, bounded same-function evidence.

Each finding's metadata carries only the logging sink and a classification reason; the raw value is never included.

**Remediation.** Remove the secret from the log call or log a redacted/masked placeholder instead of the raw credential.

### `security.shell-command`

- **Pillar:** security
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `security`

Flags `exec.Command` and `exec.CommandContext` calls that invoke a shell interpreter (`sh`, `bash`, `zsh`, `cmd.exe`, `powershell.exe`, etc.) with a command string argument. The matcher recognises aliased `os/exec` imports and path-qualified shell binaries such as `/bin/sh` or `C:\Windows\System32\cmd.exe` without flagging direct executable calls such as `exec.Command("git", "status")`. Shell-routed exec is the classic injection vector when any portion of the command is user-controlled.

**Remediation.** Call the target executable directly with `exec.Command("ls", args...)` and pass arguments as separate parameters rather than interpolating them into a shell string.

### `security.sql-string-query`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `security`, `sql`

Flags SQL execution calls (`Query`, `QueryRow`, `Exec` and `*Context` forms) whose query argument is built with `fmt.Sprintf`, string concatenation, or a same-function variable initialized from those forms. The constructed expression must contain SQL statement keyword evidence, so non-SQL `Exec` calls and literal parameterized queries are ignored. The rule handles both standard `database/sql` argument positions and pgx-style calls where a context value appears before the query. `_test.go` files and `testutil` helpers may build `CREATE SCHEMA ` statements from fixed `test_*_%d` names using `time.Now().UnixNano()` without firing; arbitrary schema variables still fire.

Each finding's metadata carries the call name and construction kind.

**Remediation.** Use parameterized queries or a prepared/query-builder API instead of interpolating SQL text.

### `security.template-injection-xss`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `http`, `security`, `xss`

Flags request-derived values reaching an HTML response without escaping: `text/template` (not `html/template`) executed into an `http.ResponseWriter`, `html/template` `HTML`/`JS`/`URL`/`CSS`/`HTMLAttr` conversions of request-derived values, and raw `w.Write`/`fmt.Fprintf(w, …)`/`io.WriteString(w, …)` of request-derived data when the handler sets an HTML `Content-Type`. `html/template` auto-escaping and `html.EscapeString` (or other escape/sanitise wrappers) are treated as safe. Candidate wording, bounded same-function evidence.

Each finding's metadata carries the reason (`text-template-response`, `raw-html-conversion`, or `unescaped-response-write`).

**Remediation.** Render HTML with `html/template` so output is auto-escaped, or escape request-derived values with `html.EscapeString` before writing them to the response.

### `security.tls-insecure-config`

- **Pillar:** security
- **Default severity:** warning
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `security`, `tls`

Flags `tls.Config` composite literals that explicitly disable certificate verification with `InsecureSkipVerify: true` or set `MinVersion` to obsolete protocol constants: `tls.VersionSSL30`, `tls.VersionTLS10`, or `tls.VersionTLS11`. The rule intentionally does not flag an absent `MinVersion`; that is a hardening preference rather than concrete parser-only vulnerability evidence.

Each finding's metadata carries the unsafe `field` and `value`.

**Remediation.** Keep certificate verification enabled and require TLS 1.2 or newer for minimum protocol versions.

### `security.unsafe-deserialization`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `deserialization`, `security`

Flags decoding of request-controlled input through formats that over-trust their payload: `encoding/gob` (`gob.NewDecoder(r.Body)`), and `gopkg.in/yaml.v2`/`v3` (`yaml.NewDecoder(r.Body)` or `yaml.Unmarshal` of request bytes). Request bytes read via `io.ReadAll(r.Body)` are tracked. Decoding a concrete typed value from a trusted local source, and `encoding/json` of request bodies, are not flagged. Candidate wording, bounded same-function evidence.

Each finding's metadata carries the decoded format and request source label.

**Remediation.** Decode untrusted input into a concrete typed struct with a vetted format (such as `encoding/json` with a size limit) rather than gob or unrestricted YAML.

### `security.weak-crypto`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `crypto`, `security`

Flags weak cryptographic primitives when the parser-only evidence is concrete: `crypto/md5` or `crypto/sha1` calls in password, token, signature, key, session, CSRF, or other security-looking contexts; direct DES, 3DES, or RC4 cipher construction; and `rsa.GenerateKey(..., bits)` with a literal key size below 2048. Plain checksum-style MD5/SHA1 use is ignored unless the surrounding function, target, comment, or call argument carries a security context word.

Each finding's metadata carries the primitive and reason.

**Remediation.** Use modern primitives such as SHA-256 or HMAC-SHA-256 for security hashes, AES-GCM or ChaCha20-Poly1305 for encryption, and RSA keys of at least 2048 bits.

### `security.xxe-candidate`

- **Pillar:** security
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `security`, `xml`, `xxe`

Flags `xml.Decoder` configurations that populate a custom `Entity` map — either `decoder.Entity = …` on a value created by `xml.NewDecoder`, or an `&xml.Decoder{Entity: …}` literal — which re-enables entity resolution (possible XXE). The Go standard library `encoding/xml` does not expand external entities by default, so a plain decoder is never flagged. Candidate wording.

Each finding's metadata records the `entity-map` evidence.

**Remediation.** Leave `xml.Decoder.Entity` unset so `encoding/xml`'s safe default applies, or validate and constrain any custom entity map fed from untrusted input.

**Sensitive-data preview policy.** Every `sensitive-data.*` detector uses one
deny-by-default policy. Empty and nonmatching `allowlists.secretPreviews` emit
only `[redacted]`; matching paths may emit fixed markers such as
`[redacted:aws-access-key]`, `[redacted:private-key]`, `[redacted:jwt]`,
`[redacted:email]`, or `[redacted:ssn]`. Connection findings may additionally
name only the matched scheme (`[redacted:connection-string:postgres]`). Generic
assignment and entropy findings stay `[redacted]` even when allowlisted. The
allowlist never suppresses a finding and never authorizes credential or
identifier payload bytes.

### `sensitive-data.anthropic-api-key`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags Anthropic API key literals (`sk-ant-` prefix plus an alphanumeric body). A leaked Anthropic key bills model usage against the owning organisation and exposes any data the caller had access to send through the API.

**Remediation.** Revoke the key in the Anthropic console, then load credentials from a secret manager.

### `sensitive-data.aws-access-key`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags AWS access-key identifier literals (`AKIA[0-9A-Z]{16}`) embedded in source or text files. Preview metadata follows the shared deny-by-default policy: unauthorized paths receive `[redacted]`, and authorized paths receive `[redacted:aws-access-key]` with zero key characters. Raw and reusable fragments never reach text / JSON / SARIF / GitHub / HTML output.

**Remediation.** Rotate the key, then load credentials from the AWS SDK default provider chain rather than embedding them.

### `sensitive-data.connection-string`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `secrets`

Flags database / queue / cache connection URIs that embed a non-empty username and password in the URL - `postgres://user:pass@host`, `mysql://`, `mongodb://`, `mongodb+srv://`, `redis://`, `amqp://`, `amqps://`. Passwords containing raw or percent-encoded reserved bytes such as `/`, `:`, `+`, `=`, and encoded `@` are detected. Preview is `[redacted]` unless the path is authorized; an authorized preview contains only the scheme marker (for example `[redacted:connection-string:postgres]`), never user, password, host, path, or query.

Obvious dev/test placeholders are skipped only when both halves match: the bare host is local-style (`localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, `db`, `database`, `postgres`) and the entire case-normalised, path-percent-decoded password equals an approved placeholder such as `change_me`, `placeholder`, `dummy`, `dev_password`, or `test_password`. A literal `+` stays a plus rather than becoming a space. Mixed values such as `myPassphrase2024` and `not-invalid-prod`, malformed percent encodings, and placeholders on non-local hosts still fire.

**Remediation.** Pull the password from environment-specific runtime configuration; keep only the scheme and host in source-controlled strings.

### `sensitive-data.gcp-service-account`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags files containing both a `"type": "service_account"` field and a PEM private-key header (`-----BEGIN ... PRIVATE KEY-----`) - the documented shape of a GCP service-account JSON key file. Neither marker alone triggers the rule: `"type": "service_account"` in a doc snippet is harmless, and an isolated PEM key is already covered by `sensitive-data.private-key`. The co-occurrence is the signal.

The finding is located at the line of the `"type"` marker. Empty/nonmatching paths fully mask both preview fields. Matching paths emit only `[redacted:gcp-service-account]` and `[redacted:private-key]`; the type literal, key header/body, and reusable fragments never reach any output format.

**Overlap with `sensitive-data.private-key`.** Both rules fire independently on a real GCP key file, producing two `error` findings on the same file: one for the GCP shape, one for the PEM. This matches ADR-007's stance that every rule should emit on its own evidence.

**Remediation.** Rotate the service-account key, delete the JSON file from source-control history, and re-issue credentials through a secret manager or Workload Identity.

### `sensitive-data.github-token`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags GitHub personal-access (`ghp_`), OAuth (`gho_`), user-to-server (`ghu_`), server-to-server (`ghs_`), and refresh (`ghr_`) tokens embedded in source or text files. The single character class `gh[pousr]_` covers all five variants, followed by a 36-255 alphanumeric body matching GitHub's published format.

**Remediation.** Revoke the token in GitHub's settings, then load credentials from a secret manager or environment-specific runtime configuration.

### `sensitive-data.gitlab-token`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags GitLab personal, trigger, runner, and application token literals with provider-specific prefixes such as `glpat-`, `glptt-`, `glrt-`, and `gloas-`. Preview metadata is redacted through the shared sensitive-data output path.

**Remediation.** Revoke the token in GitLab, then load credentials from a secret manager or environment-specific runtime configuration.

### `sensitive-data.google-api-key`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags Google API keys (`AIza` prefix plus exactly 35 base64url characters) embedded in source or text files. The fixed-width suffix prevents a bare `AIza` prefix from triggering a false positive on unrelated identifiers.

**Remediation.** Delete or restrict the key in the Google Cloud console, then load credentials from a secret manager.

### `sensitive-data.high-entropy-string`

- **Pillar:** sensitive-data
- **Default severity:** warning
- **Default-enabled:** no (opt-in)
- **Threshold:** `minLength` (default `20`), `entropy` (default `4.5` bits/char)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `secrets`

Flags long, high-entropy string tokens that resemble secrets but match no provider-specific pattern - the catch-all for rotated, custom, or vendor-less credentials the exact-prefix rules miss. A token is scored by Shannon entropy (bits per character); the `4.5` default sits above random hex (max `4.0`) and ordinary prose (~1-3) while still catching random base64 secrets (~5-6). To bound false positives the rule skips all-hex ids, UUIDs, SRI/digest prefixes, and path/URL fragments, and defers to the provider-specific rules so one embedded AWS key or JWT is reported once by its precise rule, not twice. Ships opt-in because entropy is a heuristic that cannot prove a token is live; enable it where leaked-credential coverage matters more than occasional review of a legitimate constant.

**Remediation.** Confirm whether the value is a secret; if so move it to a secret manager and rotate it. If it is a legitimate constant, raise the `entropy`/`minLength` thresholds or add an inline `#nosec` / `//nolint:gosec` suppression.

### `sensitive-data.jwt-token`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `secrets`

Flags JWT-shaped literals - three base64url segments separated by dots, the first segment starting with `eyJ` (the literal base64 prefix for `{"`). Tokens can be signing keys, session tokens, or API credentials; the rule does not distinguish.

**Remediation.** Move the token to a secret manager or runtime-only configuration; never check signed tokens into source control. If the literal is a public test vector documented in code, use an inline suppression, path ignore, or rule selection when the finding is intentionally out of scope. `allowlists.secretPreviews` only authorizes the marker `[redacted:jwt]`; it exposes no JWT segment bytes and does not suppress findings.

### `sensitive-data.npm-token`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags npm access token literals with `npm_` and `npm_pat_` provider prefixes when the token body matches expected length and character constraints. Preview metadata is redacted through the shared sensitive-data output path.

**Remediation.** Revoke the token in npm, then load credentials from a secret manager or environment-specific runtime configuration.

### `sensitive-data.phi-pattern`

- **Pillar:** sensitive-data
- **Default severity:** warning
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `secrets`, `phi`

Flags protected health information identifiers embedded in source or text: US Social Security numbers (dashed `AAA-GG-SSSS`, validated against the unissuable 000/666/9xx area, 00 group, and 0000 serial spaces), Medicare beneficiary identifiers (the 11-character MBI format whose letter positions exclude S/L/O/I/B/Z), and medical record numbers (a 6-10 digit run only when a nearby `MRN` / `medical record` / `patient id` label anchors it). Well-known placeholder SSNs (`123-45-6789`, the Woolworth and SSA-pamphlet numbers) are skipped. Each finding carries a `category` tag and either `[redacted]` or its fixed authorized marker (`[redacted:ssn]`, `[redacted:medicare]`, `[redacted:mrn]`), never identifier characters.

**Overlap with `sensitive-data.pii-pattern`.** Government and health identifiers belong to this rule, not the PII rule, so an SSN is reported once here rather than by both. Enable both rules together for full personal-data coverage without double-counting.

**Remediation.** Remove the identifier from source; use synthetic fixture data and store real PHI only in HIPAA-compliant systems. Mask or tokenise PHI before it reaches logs or reports.

### `sensitive-data.pii-pattern`

- **Pillar:** sensitive-data
- **Default severity:** warning
- **Default-enabled:** no (opt-in)
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `secrets`, `pii`

Flags personally identifiable information embedded in source or text: email addresses, phone numbers (NANP/E.164 shapes that carry phone punctuation - a leading `+` or grouping parens/dashes - so a bare digit run is not mistaken for one), and payment card numbers (13-19 digit runs that pass the Luhn checksum). Documentation and fixture placeholders are skipped: RFC 2606 example domains (`example.com`, `test`), generic local-parts (`you@`, `user@`, `noreply@`), and Luhn-invalid card-shaped numbers. Each finding carries a `category` tag and either `[redacted]` or its fixed authorized marker (`[redacted:email]`, `[redacted:phone]`, `[redacted:payment-card]`), never identifier characters.

**Overlap with `sensitive-data.phi-pattern`.** This rule covers contact and payment PII; government/health identifiers (SSN, Medicare, MRN) are owned by `sensitive-data.phi-pattern` so they are never counted twice.

**Remediation.** Remove the identifier from source; use synthetic fixture data or load real values from runtime configuration. Mask or tokenise PII before it reaches logs or reports.

### `sensitive-data.private-key`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags PEM-encoded private-key headers (`-----BEGIN ... PRIVATE KEY-----`) embedded in source or text files. Plain prose that only describes the prefix, such as "begins with `-----BEGIN PRIVATE KEY-----`", and Go code that only strips or re-wraps PEM header delimiters are skipped; a raw PEM block still fires. The most severe of the sensitive-data rules - a leaked private key is almost always a real incident.

Preview is `[redacted]` by default and `[redacted:private-key]` on an authorized path. Neither state includes key type, header, or body bytes.

**Remediation.** Remove the key, rotate it, and load it from a secret manager or environment-specific runtime configuration.

### `sensitive-data.secret-pattern`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser

Flags high-risk secret-like literal assignments in Go source and text/config files. Matches assignments like `apiKey := "AKIA…"`, `password = "p@ssw0rd"`, `bearer = "…"`, and `authorization = "Bearer …"`.

All `sensitive-data.*` rules skip Go lines that are entirely comments and honor same-line suppression annotations already common in Go tooling: `#nosec`, `//nolint:gosec`, and `//nolint:all`. Go raw string literals and same-line code-bearing literal assignments still scan, so test fixtures that embed real secret-shaped values continue to flag. Go assignments that call helper functions to generate or fetch secret values are not treated as embedded secret literals.

Documentation placeholders such as `${sessionToken}` are skipped when they are not secret values. Generic secret previews remain `[redacted]` for every path; `allowlists.secretPreviews` never suppresses findings.

**Remediation.** Move secrets to a secret manager or environment-specific runtime configuration. Never commit production secrets to source control.

### `sensitive-data.slack-token`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags Slack bot (`xoxb-`), user (`xoxp-`), app (`xoxa-`), and refresh (`xoxr-`) tokens embedded in source or text files. The three-segment body (numeric / numeric / alphanumeric) matches Slack's documented format and avoids matching unrelated `xox`-prefixed identifiers.

**Remediation.** Revoke the token in Slack's app management console, then load credentials from a secret manager.

### `sensitive-data.stripe-key`

- **Pillar:** sensitive-data
- **Default severity:** error
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `secrets`

Flags Stripe secret (`sk_live_`), publishable (`pk_live_`), and restricted (`rk_live_`) keys against the live (production) environment, followed by ≥24 alphanumeric characters. Test-mode keys (`*_test_`) are intentionally not flagged: they expose only sandbox state.

**Remediation.** Roll the key in the Stripe dashboard, then load credentials from a secret manager.

### `size.file-length`

- **Pillar:** size
- **Default severity:** advisory
- **Default-enabled:** yes
- **Threshold:** `maxLines` (default `500`)
- **Confidence:** high
- **Capability:** parser

Flags Go files that exceed the configured line-count threshold. Long files frequently mix unrelated responsibilities. Raw file length is advisory by default; `design.hotspot-file` provides stronger signal when size combines with findings from other pillars.

**Remediation.** Split the file by responsibility or move focused behaviour into a smaller sibling file.

### `size.function-length`

- **Pillar:** size
- **Default severity:** warning
- **Default-enabled:** yes
- **Threshold:** `maxLines` (default `80`)
- **Confidence:** high
- **Capability:** parser

Flags Go functions that exceed the configured code-line threshold. Blank lines, comment-only lines, and lines inside block comments are excluded via `go/scanner`; the finding metadata still includes `rawLines` for the original span. In `_test.go` functions, multiline table fixture literals such as `tests := []struct{ ... }{ ... }` are discounted from the executable line count so case matrices do not dominate the signal. A directly attached `//nolint:funlen` or `//nolint:all` doc comment suppresses one function.

`_test.go` findings use the same threshold and fingerprint identity as production findings, but the built-in default reports them as `advisory` severity / `medium` confidence unless you explicitly configure a non-warning rule severity.

**Remediation.** Extract cohesive helper functions or split independent branches.

### `size.parameter-count`

- **Pillar:** size
- **Default severity:** advisory
- **Default-enabled:** yes
- **Threshold:** `maxParameters` (default `8`)
- **Confidence:** high
- **Capability:** parser

Flags functions and methods whose parameter list exceeds the threshold (the method receiver is excluded from the count).

**Remediation.** Group related parameters into a struct, accept an options type, or split the function.

### `test-quality.empty-test`

- **Pillar:** test-quality
- **Default severity:** warning
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `tests`

Flags top-level `Test…` / `Benchmark…` / `Fuzz…` functions whose body contains no executable statements. An empty test is either an unfinished scaffold left behind by IDE generators or a stub waiting for content - both should be removed or filled in before the build is considered green.

**Remediation.** Add an assertion that exercises the behaviour the test name claims, or remove the empty test entirely.

### `test-quality.fatal-in-goroutine`

- **Pillar:** test-quality
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `tests`

Flags `t.Fatal`, `t.Fatalf`, and `t.FailNow` calls inside goroutines in `_test.go` files. Those calls stop only the goroutine that invoked them, so the parent test may continue without the intended failure control flow.

**Remediation.** Report the error back to the parent goroutine through a channel, use `t.Error` with explicit synchronisation, or move the fatal assertion back into the test goroutine.

### `test-quality.helper-missing-t-helper`

- **Pillar:** test-quality
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `tests`

Flags non-runnable test helper functions that accept `testing.TB`, `*testing.T`, or `*testing.B`, can fail the test through a testing failure call, and never call `Helper`. Runnable `Test…`, `Benchmark…`, and `Fuzz…` entrypoints are out of scope.

**Remediation.** Call `t.Helper()` at the start of the helper so failures report the caller's line.

### `test-quality.no-failure-path`

- **Pillar:** test-quality
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `tests`

Flags `Test…` / `Fuzz…` functions that contain executable statements but never reach a failure call - `t.Error`, `t.Errorf`, `t.Fatal`, `t.Fatalf`, `t.Fail`, `t.FailNow`. Benchmarks are excluded because many legitimate benchmarks measure setup or throughput without assertions. A test that cannot fail is asserting nothing and provides false confidence.

The rule walks the function body looking for those methods on the test function's `*testing.T` or `*testing.F` parameter. It also accepts assertion helpers whose function name starts with `Assert`, `Require`, `Expect`, `Must`, or `Check` when a testing receiver is passed as one of the call arguments, such as `testutil.AssertStatus(t, got)`, and same-file helpers that accept the active testing receiver and contain a parser-visible failure path. Captured helper objects are recognised only when they were initialized with the active testing receiver before the assertion call and the called method has an assertion-like name. Locally allocated `*testing.T/B/F` values used to self-test assertion helpers are recognised too. A `MustX()` call that does not receive a testing receiver is still treated as a non-assertion helper.

**Remediation.** Add an assertion, or document why the test cannot fail (e.g. it only exercises compilation).

### `test-quality.parallel-range-capture`

- **Pillar:** test-quality
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `tests`

Flags table-driven `t.Run` closures that call `t.Parallel()` and reference a range variable without an explicit shadow copy before the subtest, but only when the nearest `go.mod` declares `go < 1.22`.

Go 1.22 changed declaration-form range-loop variable semantics so each iteration gets its own variables. For modules declaring `go 1.22` or newer, this rule stays silent. A found `go.mod` without a `go` directive uses Go's implicit 1.16 semantics and remains in scope. When no `go.mod` can be found between the file and scan root, the default-on rule stays silent rather than guessing.

The rule recognises the common `tc := tc` pattern as the local evidence that capture is intentional and stable in legacy modules.

**Remediation.** Create an explicit shadow copy such as `tc := tc` before starting the parallel subtest, or update the module to Go 1.22+ loop-variable semantics.

### `test-quality.skipped-test`

- **Pillar:** test-quality
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** medium
- **Capability:** parser
- **Tags:** `tests`

Flags Go tests that call `t.Skip`, `t.Skipf`, or `t.SkipNow` unconditionally. Conditional skips inside `if`, `for`, `switch`, `range`, or `select` bodies are treated as legitimate environment guards unless their string-literal message carries a debt marker (`TODO`, `FIXME`, `XXX`, `HACK`, or `WIP`, case-insensitive). Skipped tests are easy to forget and often hide real regressions.

**Remediation.** Remove the skip or document and track the skip condition outside the test body (issue link, build-tag rationale, environment requirement).

### `test-quality.sleep-in-test`

- **Pillar:** test-quality
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `flake`, `tests`

Flags `time.Sleep` calls inside `_test.go` files. Sleeps make tests slower and usually encode timing assumptions that become flaky under CI load. The rule accepts bounded polling loops when the parser can see all three safety signals: a finite deadline or explicit attempt counter, an observable state-based exit condition, and a failure path after the loop. Blind sleeps, state-comparison loops without a real bound, and polling that never fails still emit findings.

**Remediation.** Wait on channels, contexts, condition variables, fake clocks, or explicit readiness signals instead of sleeping for an assumed duration.

### `test-quality.static-analysis-redundant-test`

- **Pillar:** test-quality
- **Default severity:** advisory
- **Default-enabled:** no
- **Confidence:** high
- **Capability:** parser
- **Tags:** `candidate`, `tests`

Flags Go unit-test assertions whose main evidence is a parser-visible static code-shape fact rather than runtime behaviour. The initial candidate set covers same-package reflection assertions such as `reflect.TypeOf(T{}).Kind() != reflect.Struct`, `Name() != "T"`, `NumField() != N`, and direct `FieldByName("Field")` existence checks when the matching type or field declaration is visible in parsed Go source.

The rule is opt-in while calibration proves precision. It does not execute reflection, load packages, or use SSA/type information, and it does not flag assertions about returned values, errors, parsing, IO, security behaviour, or interaction between components.

**Remediation.** Remove the shape assertion if it is the only evidence in the test, or replace it with an assertion about meaningful runtime behaviour.

### `test-quality.tempdir-misuse`

- **Pillar:** test-quality
- **Default severity:** advisory
- **Default-enabled:** yes
- **Confidence:** high
- **Capability:** parser
- **Tags:** `tests`

Flags `os.MkdirTemp("", ...)` and `ioutil.TempDir("", ...)` in tests when a `*testing.T`, `*testing.B`, `*testing.F`, or `testing.TB` handle is in scope. `t.TempDir()` provides automatic cleanup and per-test isolation.

**Remediation.** Replace process-wide temporary directory creation with `t.TempDir()` unless the test deliberately needs a non-test-owned parent directory.

## Configuring rules

Every rule above accepts the same override shape. See [`configuration.md`](configuration.md) for the full schema. Common patterns:

```yaml
rules:
  # Tighten a default-enabled rule.
  complexity.cyclomatic:
    threshold: 12
    severity: error

  # Disable a rule for this repo.
  docs.package-comment:
    enabled: false

  # Tune a rule's threshold.
  size.parameter-count:
    threshold: 6

  # Raise a warning-default rule to a hard-error gate.
  security.shell-command:
    enabled: true
    severity: error
```
