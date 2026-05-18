# Security Policy

`gruff-go` is a developer-facing static analysis tool. It runs locally, parses your code with the Go standard library, and (when the `dashboard` subcommand is in use) opens a single TCP listener on the loopback interface. We take security issues in the tool itself — and the security advice the tool gives — seriously.

## Supported versions

`gruff-go` follows semantic versioning. The current line receives security fixes; older minors do not.

| Version | Supported |
|---------|-----------|
| `0.1.x` (current) | ✅ |
| anything else | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Send vulnerability reports privately by either:

1. Opening a [GitHub security advisory](https://github.com/blundergoat/gruff-go/security/advisories/new) on this repository (preferred — keeps disclosure coordinated and auditable), or
2. Emailing the maintainer at **mattyh@outlook.com** with the subject prefix `[gruff-go security]`.

Include in your report:

- A description of the vulnerability and the affected component (`internal/dashboard`, a specific rule, the config loader, etc.).
- Reproduction steps. A minimal repository or input that triggers the issue is ideal.
- The impact you observed and the impact you believe is possible.
- The version (`gruff-go --help` prints it) and the OS / Go version you ran against.
- Whether you intend to disclose publicly, and if so on what timeline.

We will acknowledge receipt within **3 business days** and aim to provide an initial assessment within **7 days**. Coordinated disclosure timelines are agreed case-by-case; we default to public disclosure after a fix ships or 90 days from the initial report, whichever is sooner.

## What counts as a vulnerability

In scope:

- Remote or local code execution triggered by parsing untrusted Go source, config, baseline, or diff input.
- The `dashboard` subcommand exposing more than the documented surface — e.g. binding to a non-loopback host without `--allow-public`, accepting unintended HTTP methods, leaking process state, or executing user-supplied strings as shell commands.
- HTML injection / XSS in the rendered report (`--format html`) or the dashboard shell from any user-controllable input (paths, rule IDs, messages, config values, query string keys).
- Path traversal or arbitrary-file-read via config / baseline / diff inputs.
- Credential or secret leakage from `sensitive-data.secret-pattern` findings into a transport (logs, dashboard postMessage payload, etc.) that wasn't the intended sink.

Out of scope (these are working-as-intended unless paired with an in-scope flaw):

- False positives or false negatives in rule findings. File a normal issue instead.
- Performance regressions or denial of service from very large inputs. File a normal issue.
- Vulnerabilities that require modifying the local checkout, the Go toolchain, or system paths the user already controls.
- Reports against `0.0.x` or branches other than `main`.

## After a fix lands

When a fix ships we will:

- Credit the reporter in the release notes (unless you ask us not to).
- Add a `Security` section to [`CHANGELOG.md`](CHANGELOG.md) for the release that contains the fix.
- File a GitHub Security Advisory with a CVE if the severity warrants it.

Thanks for helping keep `gruff-go` and its users safe.
