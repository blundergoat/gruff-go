# Changelog


## [0.1.0] - 2026-05-23

First public release of `gruff-go`, a parser-only Go code-quality scanner. CLI commands: `analyse`, `baseline`, `dashboard`, `report`, `summary`, `list-rules`. 41 rules across 9 pillars (40 default-on), strict `.gruff-go.yaml` config, baselines, diff-mode, gitignore-aware discovery, six output formats (text/json/summary-json/sarif/github/html), and a local HTML dashboard.

Schemas `gruff-go.analysis.v0.1`, `gruff-go.config.v0.1`, and `gruff-go.baseline.v0.1` are stable within `0.1.x`.

**Install:** `go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.1.0` (or `go get -tool ...@v0.1.0` on Go 1.24+). Prebuilt Linux/macOS/Windows binaries are attached to the GitHub Release.

Known limitations: parser-only (no type/SSA analysis yet); HTML dashboard accessibility review ongoing.

[Unreleased]: https://github.com/blundergoat/gruff-go/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/blundergoat/gruff-go/releases/tag/v0.1.0
