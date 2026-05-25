# Contributing to gruff-go

Thanks for considering a contribution. `gruff-go` is on the `0.1.x` line and the surface is small enough that focused PRs land quickly. This page covers the dev loop, the test gates the project expects to stay green, and a few conventions worth knowing before you open a change.

## Prerequisites

- Go `1.25` or newer (matches `go.mod`).
- `git` available on `PATH` (only required for diff-mode work; not for general builds).
- A POSIX shell environment to run `make check`. Windows users can run the underlying `go` commands directly.

No third-party Go dependencies are vendored or required; everything is standard library.

## Dev loop

```bash
# Clone and bootstrap.
git clone https://github.com/blundergoat/gruff-go.git
cd gruff-go

# Build the binary into the local Go bin.
go install ./cmd/gruff-go

# Run the scanner against the project itself (it dogfoods cleanly).
go run ./cmd/gruff-go analyse .

# Full quality gate: gofmt + go vet + go test ./...
make check
```

## Project layout

| Directory | Purpose |
|-----------|---------|
| `cmd/gruff-go/` | Thin executable entrypoint; the meat lives under `internal/`. |
| `internal/cli/` | CLI parser; subcommand dispatch for `analyse`, `baseline`, `dashboard`, `help`, `list`, `list-rules`, `report`, `summary`. |
| `internal/source/` | File discovery; skips VCS, dependency caches, generated files. |
| `internal/parser/` | Standard-library `go/parser` wrapper plus parse diagnostics. |
| `internal/rule/` | Rule metadata, registry, dispatch, builtin rule pack. |
| `internal/finding/` | Severity / confidence / pillar enums, fingerprint logic. |
| `internal/config/` | Strict `.gruff-go.yaml` loader. |
| `internal/baseline/` | Fingerprinted baseline persistence. |
| `internal/diff/` | `git diff` changed-line filter. |
| `internal/scoring/` | Severity-weighted pillar + composite scoring. |
| `internal/analysis/` | End-to-end runner; produces the `gruff-go.analysis.v0.1` payload. |
| `internal/report/` | Text, JSON, summary-JSON, SARIF, GitHub annotations, HTML, dashboard shell. |
| `internal/dashboard/` | Local HTTP server that wraps the HTML reporter. |
| `docs/` | User-facing docs. Updated alongside code that changes them. |
| `.goat-flow/` | Project memory: architecture, decisions, milestone plans, footguns. |

All current rules run at the parser layer (the `parser` capability). Rules operate on `parser.Unit`s, source text, and project-level unit collections. Type-aware analysis is not yet supported by the runtime; cross-file rules that need it should declare a higher capability tier and wait for runtime support.

## Tests

- Every package has unit tests next to its source (`*_test.go`).
- `internal/cli/golden_test.go` snapshots end-to-end output. When you change a rendered format, regenerate goldens with `UPDATE_GOLDEN=1 go test ./internal/cli/...` and review the diff before committing.
- HTML, dashboard, and config surfaces have dedicated test files: `internal/report/html_test.go`, `internal/report/html_interactive_test.go`, `internal/dashboard/server_test.go`, `internal/dashboard/handler_test.go`, `internal/config/config_test.go`.
- The repository dogfoods itself. `go run ./cmd/gruff-go analyse .` should exit `0` on `main`; if it doesn't, fix the finding rather than masking it through the baseline.

Run the full sweep before pushing:

```bash
make check    # gofmt -d, go vet ./..., go test ./...
```

## Adding a rule

1. Read `internal/rule/builtin.go`, `internal/rule/expansion.go`, and the rule-specific files (`naming_*.go`, `sensitive.go`, `composite.go`, `comment_rubric.go`) for the existing patterns. Pick the file whose pillar the new rule fits.
2. Implement the rule type with `Definition() Definition` and either `AnalyzeUnit(unit parser.Unit, ctx Context)` or a project-level analyzer. All shipped rules carry `DefaultEnabled: true` per [ADR-007](.goat-flow/decisions/ADR-007-comprehensive-default-rule-pack.md); pick a default severity that won't push existing CI gates into a stricter bucket for an unrelated codebase. Default `--min-severity` is `advisory` (every finding surfaces), so most new naming/test-quality rules ship at `advisory` and only escalate to `warning` or `error` when the failure mode is unambiguous.
3. Register the rule in `Defaults()` (`internal/rule/defaults.go`) so `list-rules` picks it up.
4. Add a fixture and a unit test in `internal/rule/*_test.go`.
5. Update [`docs/rules.md`](docs/rules.md) and `.gruff-go.yaml` so dogfood reflects the new policy.
6. Run `make check` and confirm the self-scan still exits clean (`go run ./cmd/gruff-go analyse .`).

## Adding an output format

1. Add the renderer to `internal/report/`. Mirror the existing `WriteText / WriteJSON / WriteSARIF` shape (`func WriteX(io.Writer, analysis.Report) error`).
2. Wire the format name into `internal/cli.supportedAnalysisFormat` and `writeAnalysisReport`.
3. Add a snapshot to `internal/cli/testdata/golden/` via `UPDATE_GOLDEN=1`.
4. Document the format in [`docs/output-formats.md`](docs/output-formats.md).

## Planning non-trivial work

For larger changes (cross-cutting refactors, new rule families, schema changes, CLI surface changes), write a short plan first: objective, dependencies, kill criteria, read-first list, assumptions, tasks, exit criteria, and the testing gate that proves you are done. Small fixes, doc tweaks, and isolated rule additions don't need a plan; cross-cutting work usually does.

## Commits and PRs

- Keep commits focused and reviewable. Prefer multiple small commits over one large one when the changes are independent.
- Commit messages follow the convention recorded in [`.github/git-commit-instructions.md`](.github/git-commit-instructions.md). When in doubt, mirror the style in `git log`.
- Open the PR against `main`. Describe what changed and why; link to the milestone or footgun if relevant. Run `make check` locally first.
- If you broke a schema or CLI flag, note it explicitly in the PR. `gruff-go` is `v0.1.x` - semver minor bumps may carry breaking changes, but they should be intentional and called out in `CHANGELOG.md`, never incidental.

## Security issues

Don't open a public issue for a vulnerability. Follow [`SECURITY.md`](SECURITY.md) for the private reporting channel.

## License

By contributing, you agree that your contribution will be licensed under the [MIT License](LICENSE).
