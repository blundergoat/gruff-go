---
category: security-rules
last_reviewed: 2026-06-14
---

# Security-Rule Footguns

## Footgun: Workflow action ref safety is shape-based, not tag-aware

**Status:** active | **Created:** 2026-06-05 | **Evidence:** OBSERVED

`security.github-actions-unpinned-action` is a parser-only text rule. It cannot ask GitHub whether `owner/action@ref` names a tag or a branch, so the regexes in `internal/rule/security_workflow.go` (search: `isMutableActionRef`, `actionShaRefPattern`, `actionVersionTagPattern`) are the security boundary. Broad "looks pinned" patterns create false negatives: short SHA prefixes and digit-prefixed branch names can otherwise be misclassified as safe pins.

How to avoid:
- Keep commit pins to a full 40-character hex SHA and keep version-tag recognition narrow. When touching `isMutableActionRef`, add adversarial cases to `internal/rule/security_workflow_test.go` (search: `third-party short sha prefix`, `third-party digit-prefixed branch`) as well as positive release-tag cases, because a parser-only rule cannot recover later with API truth.

## Footgun: Template XSS must classify Execute receivers, not file imports

**Status:** active | **Created:** 2026-06-05 | **Evidence:** OBSERVED

Importing `html/template` in a file does not make `text/template` auto-escaped. The `security.template-injection-xss` rule must decide whether an `Execute` call is backed by `text/template` from the call receiver, not from package presence alone. The relevant boundary is `internal/rule/security_template_xss.go` (search: `textTemplateXSSHit`, `templateExecuteReceiverKind`, `collectTemplateValueKinds`).

How to avoid:
- In mixed-import files, require same-file evidence that the `Execute` receiver came from `text/template`, while preserving `html/template` auto-escape as a no-finding case. Pin both sides in `internal/rule/security_template_xss_test.go` (search: `text template still flags when html template is also imported`, `html template execute stays safe when text template is also imported`).

## Footgun: secret-pattern precision guards are Go-only; config files and test fixtures both bite

**Status:** active | **Created:** 2026-06-14 | **Evidence:** OBSERVED

The generic `sensitive-data.secret-pattern` rule (`internal/rule/builtin.go`, search: `func (r SensitiveDataRule) AnalyzeUnit`) is `SeverityError`, so a false positive fails the grade and blocks a CI/agent gate. Two related traps live here:

- **Precision guards were gated to Go.** The comment-skip (search: `lineIsCodeBearing`) and the "value looks like a literal" check (search: `goSecretAssignmentLooksLiteral`) only run when `unit.File.Type == source.FileTypeGo`. Config files (`.toml` / `.yaml` / `.env`) are `FileTypeText` and got none of them, so commented-out example assignments like `# api_key = "your-minimax-api-key"` flagged at Error severity. Corpus calibration surfaced 16 such false positives in `cc-connect/config.example.toml`, all `#`-commented `your-…` placeholders. The fix added `textLineIsComment` (skips `#` / `//` / `;` comment-only lines for non-Go text) and broadened `isPlaceholderSecretAssignment` beyond `${VAR}` to `your-` prefixes and a narrow `placeholderSecretTokens` list (`changeme`, `placeholder`, `redacted`, …). Keep that list narrow: a broad substring match creates false negatives on real high-entropy secrets, which for a security rule is the worse failure.
- **Test fixtures self-flag in the dogfood scan.** Any `_test.go` line carrying ≥20 contiguous `[A-Za-z0-9_./+=-]` chars after a secret-shaped key (e.g. `access_token = "abcdefghijklmnopqrstuvwxyz123456"`) is itself a secret-pattern hit when gruff-go scans its own repo, dropping the dogfood from grade A. Build real-token fixtures from `secretPatternFixtureValue()` (search in `internal/rule/builtin_test.go`), which splits the body across two literals so no single source line matches.

How to avoid:
- When changing secret detection, exercise BOTH file types: Go (`builtin_test.go`) and non-Go config (`internal/rule/secret_pattern_config_test.go`, search: `TestSensitiveDataRuleSkipsConfigCommentsAndPlaceholders`), with negative cases (comments, placeholders) and positive cases (real credentials still flag).
- `internal/rule/builtin_test.go` sits near the 500-line `size.file-length` cap; add new secret-pattern fixtures to a focused sibling test file, not to `builtin_test.go`, or the dogfood gains a `size.file-length` advisory.
- After any change, run `go run ./cmd/gruff-go analyse .` and confirm grade A, then re-scan the corpus to confirm the false-positive count dropped without zeroing real-credential detection.

## Resolved Entries

## Footgun: `filepath.Clean` is suppressed by two independent mechanisms in the request-taint engine

**Status:** resolved | **Created:** 2026-06-04 | **Resolved:** 2026-06-05 | **Evidence:** OBSERVED

hallucination-risk: high (a PR review flagged "Clean is not containment" as if it were a one-line word-list edit; it is not)

`filepath.Clean` normalises a path but does **not** constrain it (`Clean("../../etc/passwd")` is unchanged), so unlike `filepath.Rel` / `IsLocal` / `Base` it is not genuine path-traversal containment. PR #4's review (Copilot) correctly flagged that the path-traversal rule treated `Clean` as evidence. Acting on it was bigger than it looked, because two separate code paths suppressed a Clean'd request value:

- **The sanitizer word list.** `internal/rule/security_path_traversal.go` (search: `pathSanitizerWords`) contained `"clean"`. That governed the **inline** sink form `os.Open(filepath.Clean(r.FormValue("f")))`, where the inline-sanitizer check (search: `argHasInlineSanitizer`) matched the `Clean` call name.
- **Taint propagation.** `internal/rule/security_request_source.go` (search: `func (s *requestTaintScope) directRequestExpr`) propagated taint only through string builders, conversions, and `+`; an arbitrary call such as `filepath.Clean(x)` broke the chain. So the **variable-stored** form `c := filepath.Clean(r.FormValue("f")); os.Open(c)` was silent regardless of the word list, because `c` was never marked tainted.

Deleting `"clean"` from `pathSanitizerWords` alone would have made the inline form fire but left the var-stored form silent - an inconsistent half-fix where adding a local variable suppressed the finding. The fix made `path.Clean` / `filepath.Clean` taint-transparent in `directRequestExpr`, removed `"clean"` from containment/sanitizer word lists where Clean alone was not enough, and added regression tests for inline and stored Clean forms.

Evidence for the resolved boundary:
- `internal/rule/security_path_traversal_test.go` (search: `clean alone still flags`) pins the var-stored Clean form to a finding.
- `internal/rule/security_path_traversal_test.go` (search: `clean plus containment helper`) keeps Clean plus a real containment helper quiet.
- `internal/rule/security_request_url_test.go` (search: `cleaned request url is still request controlled`) pins that Clean does not erase taint for SSRF-style URL sinks.

How to avoid repeating:
- When changing request-sanitizer evidence, check both `internal/rule/security_request_source.go` (search: `func (s *requestTaintScope) directRequestExpr`) and the rule-specific sanitizer word list. Any taint-transparent wrapper added to `directRequestExpr` can affect SSRF, open redirect, and path traversal, so add focused tests in each impacted rule file and run the dogfood scan.
