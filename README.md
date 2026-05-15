# gruff-go

An opinionated code-quality scanner for Go. `gruff-go` reads your packages, scores them across eleven pillars — size, complexity, dead code, naming, documentation, modernisation, security, sensitive data, test quality, maintainability, and design — and writes a report you can pipe into a terminal, CI annotation, SARIF feed, static HTML page, or a local browser dashboard. It is heuristic, not a type checker; pair it with `go vet`, `staticcheck`, and `govulncheck`, not in place of them.

## Status

Pre-release: the binary reports its version as `0.1.0-dev`. The package is not yet published, schemas are versioned but may shift before `v0.1.0` final, and the CLI surface is consumed from source. See [`CHANGELOG.md`](CHANGELOG.md) for the running list of foundation work.

## Requirements

- Go `1.25` or newer ([`go.mod`](go.mod))
- Git (only required for `--diff-base`-mode scans)

No runtime dependencies outside the Go standard library.

## Install

From source today:

```bash
git clone https://github.com/blundergoat/gruff-go.git
cd gruff-go
go install ./cmd/gruff-go
gruff-go --help
```

Or use `go run` without installing:

```bash
go run ./cmd/gruff-go analyse .
```

Once a release is published, `go install github.com/blundergoat/gruff-go/cmd/gruff-go@latest` will be the convenient form.

## Quick start

```bash
# Analyse the current module
gruff-go analyse .

# Analyse a directory or specific files
gruff-go analyse ./internal
gruff-go analyse ./cmd/myapp ./internal/auth

# Fail only on critical findings (default: medium)
gruff-go analyse --min-severity critical .

# Skip the auto-loaded .gruff.yaml for a single run
gruff-go analyse --no-config .

# Scan only what changed against main
gruff-go analyse --diff-base origin/main .

# Apply a baseline (suppresses pre-existing findings)
gruff-go analyse --baseline gruff-baseline.json .
```

> **Flag ordering.** `gruff-go` uses Go's standard `flag` package, which stops parsing at the first non-flag argument. Put every `--flag` *before* the path arguments.

## Commands

| Command | Purpose |
|---------|---------|
| `analyse` | Run the rule registry over the supplied paths and emit a report in the chosen format. The main command. |
| `baseline` | Run a scan and write the current findings to a JSON baseline so subsequent runs can suppress them. |
| `list-rules` | Print rule metadata (id, pillar, default severity, threshold defaults) as text or JSON. |
| `dashboard` | Serve a local interactive dashboard (default `127.0.0.1:8765`) that re-runs scans on demand from a browser. |

`gruff-go --help` prints the full flag list.

## Output formats

`gruff-go analyse --format <fmt>` accepts:

| Format | Use it for |
|--------|------------|
| `text` *(default)* | Reading findings in a terminal. |
| `json` | Full structured report — schema `gruff-go.analysis.v0.1`. |
| `summary-json` | Compact CI digest. Same shape as `json` minus the per-finding list. |
| `sarif` | SARIF 2.1.0 for GitHub Code Scanning, GitLab, and tools that consume the format. |
| `github` | GitHub Actions workflow commands (`::error`, `::warning`, `::notice`). |
| `html` | Self-contained HTML inspection report. Open in a browser or open via `gruff-go dashboard`. |

See [`docs/output-formats.md`](docs/output-formats.md) for the schema details and HTML-specific flags (`--report-editor-link`, `--report-interactive`).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--min-severity` and no diagnostics. |
| `1` | At least one finding at or above `--min-severity`. |
| `2` | Diagnostics (path missing, parse error, config error, baseline error, diff error) **or** invalid input flag. |

`--min-severity` defaults to `medium` and accepts `info / low / medium / high / critical`.

## Configuration

`gruff-go` auto-loads `.gruff.yaml`, `.gruff.yml`, then `.gruff.json` from the project root unless `--config <path>` or `--no-config` is given. The config is strict: unknown keys, unknown rule IDs, unknown pillars, and invalid thresholds all fail closed.

A minimal example:

```yaml
paths:
  ignore: ["vendor/", "internal/generated/"]

allowlists:
  acceptedAbbreviations: ["ID", "HTTP", "JSON", "AST"]

selection:
  excludeRules: []
  excludePillars: []

rules:
  complexity.cyclomatic:
    enabled: true
    threshold: 15
    severity: high
  size.file-length:
    threshold: 400
  naming.package-underscore:
    enabled: true
```

The schema, every option, and validation rules are documented in [`docs/configuration.md`](docs/configuration.md).

## Rule catalog

`gruff-go` v0.1 ships twelve rules across eight pillars. Five are enabled by default; the rest are opt-in via config so existing repos can phase them in without baseline churn.

See [`docs/rules.md`](docs/rules.md) for the full list with severities, thresholds, and remediation guidance.

## Dashboard

```bash
gruff-go dashboard --project .
# Open http://127.0.0.1:8765/ in a browser.
```

The dashboard binds to loopback by default and refuses public hosts without `--allow-public`. The controls panel re-runs the scan against the project root you typed in the form, and the report renders in an iframe. See [`docs/dashboard.md`](docs/dashboard.md) for the security model, the postMessage protocol, and the `--scan-timeout` behaviour.

## CI integration

GitHub Actions, GitLab CI, and other runners can consume the SARIF or GitHub-annotations output. See [`docs/ci-integration.md`](docs/ci-integration.md) for ready-to-paste workflow snippets and the baseline workflow used to roll the scanner out incrementally.

## Contributing

Patches welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for dev setup, the milestone-style workflow, and the test conventions. Security issues: please follow [`SECURITY.md`](SECURITY.md) instead of opening a public issue.

## License

[MIT](LICENSE). See the LICENSE file for the full text.
