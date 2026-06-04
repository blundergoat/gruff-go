---
category: security-rules
last_reviewed: 2026-06-04
---

# Security-Rule Footguns

## Footgun: `filepath.Clean` is suppressed by two independent mechanisms in the request-taint engine

**Status:** active | **Created:** 2026-06-04 | **Evidence:** OBSERVED

hallucination-risk: high (a PR review flagged "Clean is not containment" as if it were a one-line word-list edit; it is not)

`filepath.Clean` normalises a path but does **not** constrain it (`Clean("../../etc/passwd")` is unchanged), so unlike `filepath.Rel` / `IsLocal` / `Base` it is not genuine path-traversal containment. PR #4's review (Copilot) correctly flagged that the path-traversal rule treats `Clean` as evidence. Acting on it is bigger than it looks, because two separate code paths suppress a Clean'd request value:

- **The sanitizer word list.** `internal/rule/security_path_traversal.go` (search: `pathSanitizerWords`) contains `"clean"`. This only governs the **inline** sink form `os.Open(filepath.Clean(r.FormValue("f")))`, where the inline-sanitizer check (search: `argHasInlineSanitizer`) matches the `Clean` call name.
- **Taint propagation.** `internal/rule/security_request_source.go` (search: `func (s *requestTaintScope) directRequestExpr`) propagates taint only through string builders, conversions, and `+`; an arbitrary call such as `filepath.Clean(x)` breaks the chain (it might be a sanitiser). So the **variable-stored** form `c := filepath.Clean(r.FormValue("f")); os.Open(c)` is already silent regardless of the word list, because `c` is never marked tainted.

So deleting `"clean"` from `pathSanitizerWords` alone makes the inline form fire but leaves the var-stored form silent — an inconsistent half-fix where adding a local variable suppresses the finding. A coherent "Clean is not containment" change must ALSO make `filepath.Clean` taint-transparent in `directRequestExpr`, and that helper hangs off `requestTaintScope`, shared by the SSRF, open-redirect, and path-traversal rules — blast radius is three default-on rules, not one. Note `redirectSanitizerWords` (`internal/rule/security_request_url.go`) also lists `"clean"`.

Evidence the current behaviour is deliberate, not an oversight to silently flip:
- `internal/rule/security_path_traversal_test.go` (search: `cleaned and contained`) pins the var-stored Clean form to **zero** findings.
- The rule's own remediation (search: `Constrain request-derived paths with filepath.Clean plus a containment check`) already says Clean PLUS a check — i.e. Clean alone is documented as insufficient, which contradicts accepting it as standalone evidence.

How to avoid:
- Treat this as a scoped, tested precision change across all three request rules, not a word-list tweak: update the word lists AND `directRequestExpr`, flip/extend the `cleaned and contained` test (add a `Clean + containment helper` negative case), run `go run ./cmd/gruff-go analyse .` to confirm the dogfood stays grade A, and add a `CHANGELOG.md` entry. It is `Ask First` territory — it changes a default-on rule's findings.
