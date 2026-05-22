# gruff-go

An opinionated code-quality scanner for Go. `gruff-go` reads your packages, scores them across nine pillars — complexity, dead code, design, documentation, naming, security, sensitive data, size, and test quality — and writes a report you can pipe into a terminal, CI annotation, SARIF feed, static HTML page, or a local browser dashboard. It is heuristic, not a type checker; pair it with `go vet`, `staticcheck`, and `govulncheck`, not in place of them.

## Status

`v0.1.0` is the first release line. This checkout reports its binary version as `0.1.0` and is being prepared as the 0.1 release candidate. Schemas (`gruff-go.analysis.v0.1`, `gruff-go.config.v0.1`, `gruff-go.baseline.v0.1`) are stable within the `0.1.x` line; breaking changes to the CLI, schemas, or default rule pack land in a future minor and are called out in [`CHANGELOG.md`](CHANGELOG.md).

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

For a tagged install after the release tag is pushed:

```bash
go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.1.0
```

Use `@latest` only when you intentionally want the newest published release rather than a pinned build.

## Quick start

```bash
# Analyse the current module
gruff-go analyse .

# Analyse a directory or specific files
gruff-go analyse ./internal
gruff-go analyse ./cmd/myapp ./internal/auth

# Fail only on critical findings (default: medium)
gruff-go analyse --min-severity critical .

# Skip the auto-loaded .gruff-go.yaml for a single run
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
| `summary` | Print a compact digest of a scan — composite score, per-pillar counts, top rules, top file offenders. |
| `report` | Convenience wrapper around `analyse` for static HTML or JSON reports written to stdout or `--output <file>`. |
| `baseline` | Run a scan and write the current findings to a JSON baseline so subsequent runs can suppress them. |
| `list-rules` | Print rule metadata (id, pillar, default severity, threshold defaults) as text or JSON. |
| `list` | List the available commands (same output as `--help`). |
| `dashboard` | Serve a local interactive dashboard (default `127.0.0.1:8765`) that re-runs scans on demand from a browser. |
| `help` | Display help for the given command, or the command list when no command is named. |

`gruff-go --help` prints the full flag list. Run `gruff-go help <command>` for per-command flags.

## Global flags

| Flag | Purpose |
|------|---------|
| `-h`, `--help` | Display help. Use `gruff-go help <command>` for command-specific help. |
| `-V`, `--version` | Display the gruff-go version. |
| `-q`, `--quiet` | Only errors are displayed; non-error stdout output is suppressed. |
| `--ansi` | Force ANSI colour output (auto-detected when omitted). |
| `--no-ansi` | Disable ANSI colour output. Honours `NO_COLOR` and `TERM=dumb`. |

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

`gruff-go` auto-loads `.gruff-go.yaml` from the project root unless `--config <path>` or `--no-config` is given. The config is strict: unknown keys, unknown rule IDs, unknown pillars, and invalid thresholds all fail closed.

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
    threshold: 300
  naming.package-underscore:
    enabled: true
```

The schema, every option, and validation rules are documented in [`docs/configuration.md`](docs/configuration.md).

## Rule catalog

The current checkout contains **41 rules** across **9 pillars**. The built-in pack enables 40 rules by default; `docs.config-field-comment` is the single opt-in rule for projects that want exported struct fields documented. Disable any rule per project via `selection.excludeRules` or `rules.<id>.enabled: false`.

Current built-in rule distribution:

| Pillar | Rules |
|--------|-------|
| complexity | 2 |
| dead-code | 1 |
| design | 2 |
| documentation | 4 |
| naming | 9 |
| security | 6 |
| sensitive-data | 11 |
| size | 3 |
| test-quality | 3 |

See [`docs/rules.md`](docs/rules.md) for the full list with severities, thresholds, and remediation guidance.

## Release calibration

The release gate is `make check` plus a dogfood scan (`gruff-go analyse .`) that must return grade A with zero findings on this repository. Rule precision is also calibrated against a separate Go service corpus so dogfood-only blind spots show up before release. The latest external calibration removed noisy `security.*` and `naming.*` false positives while preserving size and genuinely assertionless-test findings; details are recorded in [`CHANGELOG.md`](CHANGELOG.md) and [ADR-008](.goat-flow/decisions/ADR-008-external-codebase-calibration-precision-fixes.md).

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

## Author

Built by [Matthew Hansen](https://www.blundergoat.com/about).

## License

[MIT](LICENSE)
