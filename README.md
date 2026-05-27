# gruff-go

[![CI](https://github.com/blundergoat/gruff-go/actions/workflows/gruff-go.yml/badge.svg)](https://github.com/blundergoat/gruff-go/actions/workflows/gruff-go.yml)
[![Release](https://img.shields.io/github/v/release/blundergoat/gruff-go?sort=semver&color=blue)](https://github.com/blundergoat/gruff-go/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/blundergoat/gruff-go.svg)](https://pkg.go.dev/github.com/blundergoat/gruff-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/blundergoat/gruff-go)](https://goreportcard.com/report/github.com/blundergoat/gruff-go)
[![License: MIT](https://img.shields.io/github/license/blundergoat/gruff-go)](LICENSE)

`gruff-go` is an opinionated code-quality scanner for Go projects. It reads Go packages, scores findings across quality pillars, and emits reports for terminals, CI annotations, SARIF consumers, static HTML, and a local dashboard. It is heuristic static analysis; run it beside `go vet`, `staticcheck`, `govulncheck`, tests, and code review, not instead of them.

## Status At A Glance

| Field | Value |
| --- | --- |
| Release line | Published `0.2.0` package line |
| Runtime | Go `1.25+` |
| Module | `github.com/blundergoat/gruff-go` |
| Binary | `gruff-go` |
| Rule catalogue | 64 rules across 11 pillars; 64 enabled by default |
| Primary config | `.gruff-go.yaml` |
| Analysis schema | `gruff-go.analysis.v0.2` |
| Baseline schema | `gruff-go.baseline.v0.1` |
| Severity gate | `--min-severity` with `advisory`, `warning`, `error` |
| Dashboard | `127.0.0.1:8765` by default |

## Requirements

- Go `1.25` or newer, matching [`go.mod`](go.mod).
- Git only when using `--diff-base` changed-line filtering.
- No runtime dependencies outside the Go standard library.

The project-pinned install flow uses Go's `tool` support, introduced before this module's current Go requirement. The binary itself still requires Go `1.25+`.

## Install

Install as a project-pinned dev tool:

```bash
go get -tool github.com/blundergoat/gruff-go/cmd/gruff-go@v0.1.0
go tool gruff-go init
go tool gruff-go summary .
```

From a source checkout:

```bash
git clone https://github.com/blundergoat/gruff-go.git
cd gruff-go
go build -o ./bin/gruff-go ./cmd/gruff-go
./bin/gruff-go --help
```

Linux, macOS, and Windows archives are attached to each [GitHub Release](https://github.com/blundergoat/gruff-go/releases). Releases include `checksums.txt`.

## Quick Start

```bash
# Create the project config.
go tool gruff-go init

# Review the current finding mix.
go tool gruff-go summary .

# Inspect the current module.
go tool gruff-go analyse .

# Raise the failure floor while exploring an existing codebase.
go tool gruff-go analyse --min-severity error .

# Emit SARIF for code scanning.
go tool gruff-go analyse --format sarif --min-severity error . > gruff.sarif

# Generate a fresh-start baseline.
go tool gruff-go analyse --generate-baseline gruff-baseline.json .

# Start the local dashboard.
go tool gruff-go dashboard --project .
```

Go's standard `flag` package stops parsing flags at the first non-flag argument. Put every `--flag` before path arguments.

## Commands

| Command | Purpose |
| --- | --- |
| `analyse` | Run rules over the supplied paths and emit a report. |
| `summary` | Print a compact score, per-pillar counts, top rules, and top files. |
| `report` | Render static HTML or JSON to stdout or `--output <file>`. |
| `baseline` | Run a scan and write the current findings to a baseline file. |
| `init` | Generate a default `.gruff-go.yaml`. |
| `list-rules` | Print rule metadata as text or JSON. |
| `dashboard` | Serve the local browser dashboard. |
| `list`, `help` | Show command lists and command-specific help. |

Run `go tool gruff-go help <command>` for command-specific flags.

## Output Formats

`go tool gruff-go analyse --format <fmt>` accepts:

| Format | Use it for |
| --- | --- |
| `text` | Human terminal output. |
| `json` | Full `gruff-go.analysis.v0.2` report. |
| `summary-json` | Compact CI digest without the full finding list. |
| `sarif` | SARIF 2.1.0 for code scanning. |
| `github` | GitHub Actions workflow annotations. |
| `html` | Self-contained inspection report. |

`go tool gruff-go report --format <fmt>` accepts `html` and `json`. See [`docs/output-formats.md`](docs/output-formats.md) for schema details and HTML flags.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | No finding met `--min-severity`, and no fatal diagnostic occurred. |
| `1` | At least one finding met `--min-severity`. |
| `2` | Invalid input or a fatal diagnostic such as config, parse, baseline, path, or diff failure. |

`--min-severity` defaults to `advisory` (every finding fails). Pass `warning` for moderate gating or `error` for the strict gate. Go uses `--min-severity` where the other gruff implementations use `--fail-on`; both names work on the CLI as of v0.1.1.

## CI Usage

Generic CI command:

```bash
go tool gruff-go analyse --format github --min-severity warning .
```

SARIF upload jobs can use:

```bash
go tool gruff-go analyse --format sarif --min-severity error . > gruff-go.sarif
```

For incremental rollout, generate a baseline first, commit it after review, then run with `--baseline gruff-baseline.json`. See [`docs/ci-integration.md`](docs/ci-integration.md) for GitHub Actions and GitLab examples.

## Configuration

`gruff-go` auto-loads `.gruff-go.yaml` from the project root unless `--config <path>` or `--no-config` is supplied. Config validation fails closed on unknown keys, unknown rule IDs, unknown pillars, and invalid thresholds.

```yaml
paths:
  ignore:
    - "vendor/"
    - "internal/generated/"

allowlists:
  acceptedAbbreviations: ["ID", "HTTP", "JSON", "AST"]

selection:
  excludeRules: []
  excludePillars: []

rules:
  complexity.cyclomatic:
    threshold: 15
    severity: error
  naming.package-underscore:
    enabled: true
```

See [`docs/configuration.md`](docs/configuration.md) for the full schema and validation rules.

## Rules And Pillars

The current checkout contains 64 rules across 11 pillars. All 64 rules are enabled by default.

| Pillar | Rules |
| --- | ---: |
| `complexity` | 3 |
| `dead-code` | 2 |
| `design` | 1 |
| `documentation` | 5 |
| `maintainability` | 7 |
| `modernisation` | 2 |
| `naming` | 8 |
| `security` | 10 |
| `sensitive-data` | 13 |
| `size` | 3 |
| `test-quality` | 7 |

See [`docs/rules.md`](docs/rules.md) for rule IDs, severities, thresholds, and remediation guidance.

`list-rules` reports the effective rule state after applying project config. Use `go tool gruff-go list-rules --no-config` to inspect built-in defaults.

## Baselines And Changed-Code Scans

Baselines suppress reviewed findings by fingerprint without disabling rules:

```bash
go tool gruff-go analyse --generate-baseline gruff-baseline.json .
go tool gruff-go analyse --baseline gruff-baseline.json .
```

Changed-line scans use Git only when requested:

```bash
go tool gruff-go analyse --diff-base origin/main .
```

Display filters such as `--include-pillars`, `--exclude-rules`, and `--include-rules` reduce report noise without changing which rules execute.

## Dashboard

```bash
go tool gruff-go dashboard --project .
# Open http://127.0.0.1:8765/ in a browser.
```

The dashboard binds to loopback by default and refuses public hosts unless `--allow-public` is supplied. It has no authentication; treat the bind address as the safety boundary. See [`docs/dashboard.md`](docs/dashboard.md) for the security model, postMessage protocol, and scan timeout behavior.

In polyglot repositories, remember that `gruff-go`, `gruff-php`, and `gruff-py` all default to port `8765`; use `--port` when running multiple dashboards at the same time.

## Trust Boundary

Default scans are local source inspections. `gruff-go` parses Go source and selected text/config files; it does not execute target code, run tests, call package build scripts, query vulnerability feeds, or replace type-aware tools. Git is invoked only for explicit diff scans. Sensitive-data previews are redacted before they reach terminal, JSON, SARIF, GitHub, or HTML output.

## Stability Contract

Within `0.1.x`, the CLI surface, rule IDs, finding fingerprints, baseline identity, and schemas named in this README are compatibility-sensitive. Breaking changes to those surfaces land in a future minor release and are called out in [`CHANGELOG.md`](CHANGELOG.md). Rule precision is calibrated by dogfooding this repository and by scanning a separate Go service corpus before release.

## How It Compares

| Tool | Relationship |
| --- | --- |
| `go vet` | Type-aware checks for suspicious Go constructs. Run it before or beside `gruff-go`. |
| `staticcheck` | Deeper semantic linting. `gruff-go` focuses on scoring, baselines, reports, and project-level quality signals. |
| `govulncheck` | Vulnerability-feed-backed dependency and call-path checks. `gruff-go` does not query vulnerability feeds. |
| `gofmt` / `go fmt` | Formatting only. `gruff-go` does not format code. |
| Code review and tests | Still required; gruff findings are deterministic review prompts, not runtime proof. |

## Development

```bash
go test ./...
go vet ./...
make check
```

`make check` is the release gate together with a dogfood scan that must return grade A with zero findings on this repository. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for workflow and test conventions.

## Documentation

- [Changelog](CHANGELOG.md)
- [Configuration](docs/configuration.md)
- [Output formats](docs/output-formats.md)
- [Rules](docs/rules.md)
- [Dashboard](docs/dashboard.md)
- [CI integration](docs/ci-integration.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## Author

Built by [Matthew Hansen](https://www.blundergoat.com/about).

## License

[MIT](LICENSE)
