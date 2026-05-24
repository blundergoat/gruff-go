# gruff-go docs

Use these docs with the top-level README for the stable user-facing surface.

## Core Docs

- [Configuration](configuration.md) - config discovery, schema, allowlists, and rule overrides.
- [Rules](rules.md) - rule IDs, severities, thresholds, and remediation guidance.
- [Output Formats](output-formats.md) - text, JSON, summary JSON, SARIF, GitHub annotations, and HTML.
- [CI Integration](ci-integration.md) - GitHub Actions, SARIF upload, pre-commit, and exit codes.
- [Dashboard](dashboard.md) - local dashboard flags, safety model, and scan protocol.
- [Releasing](releasing.md) - release checks and packaging notes.

## Stable Surface

This docs directory records the Go implementation's stable user-facing surface:
configuration, rule IDs, output formats, CI behaviour, dashboard flags, and
release process. Go keeps a few documented extensions: the `baseline` helper
command, the `analyze` alias, five-level severity names, and `summary-json`.
