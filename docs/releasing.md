# Releasing

This page captures the gruff-go release checks that protect the user-facing CLI
and report contracts.

## Preflight

Run the local check suite before tagging:

```sh
scripts/preflight-checks.sh
```

Preflight is the release gate and runs nine checks: version metadata, `npm audit`,
`govulncheck`, `bash -n`, shellcheck, `gofmt -l`, `go vet`, `go test ./...`, and a
dogfood self-scan that must return grade A. `make check` covers only the three Go
checks in that list and is the edit-time floor, so preflight supersedes it here.

Before changing a source version, exercise the read-only ownership guard:

```sh
scripts/bump-version_test.sh
scripts/bump-version.sh --check-references --root . --source-version "$(go run ./cmd/gruff-go --version | awk '{ print $2 }')"
```

`source-current` rows must match the source version. `published-install` and
`security-support` rows are review prompts because public releases may
intentionally trail the source tree; `unclassified` rows must gain an owner or
be removed before the bump.

## CLI Contract

Before release, verify the common CLI surface:

```sh
go run ./cmd/gruff-go --help
go run ./cmd/gruff-go analyse --help
go run ./cmd/gruff-go summary --help
go run ./cmd/gruff-go list-rules --format json
```

`--fail-on` and `--min-severity` must both remain accepted until a documented
breaking release removes the old name.

## Docs

Update docs when command output or schemas change:

- `docs/configuration.md`
- `docs/output-formats.md`
- `docs/ci-integration.md`
- `docs/dashboard.md`
- `docs/agent-guardrail.md`
- `docs/rules.md`

`docs/rules.md` is machine-checked: `TestRulesDocsStructuredMetadataMatchesRegistry`
compares its counts, opt-in IDs, catalogue rows, and per-rule sections against the
no-config registry, so a registry change fails `go test ./internal/cli/...` until the
page matches. The other pages have no such guard and need a manual pass.

## Binary Wrapper

`bin/gruff-go.sh` is the tracked launcher, mirroring the `bin/gruff-<lang>`
entrypoints in the sibling gruff ports. It rebuilds `bin/gruff-go` whenever that
binary is missing or older than the tracked Go sources, then execs it, so it
always exercises current code:

```sh
bin/gruff-go.sh --help
```

`bin/gruff-go` itself is build output (gitignored, not tracked). Build it directly
when you want to skip the staleness check:

```sh
go build -o bin/gruff-go ./cmd/gruff-go   # or: scripts/build-bin-gruff-go.sh
bin/gruff-go --help
```

## Changelog

Record compatibility-sensitive changes in `CHANGELOG.md`, especially:

- schema strings
- severity names
- default exit thresholds
- baseline behaviour
- dashboard defaults
- output format additions or removals
