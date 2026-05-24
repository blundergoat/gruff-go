# Releasing

This page captures the gruff-go release checks that protect the user-facing CLI
and report contracts.

## Preflight

Run the local check suite before tagging:

```sh
make check
scripts/preflight-checks.sh
```

The checks should cover formatting, `go vet`, tests, shell syntax, and dogfood
analysis.

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
- `docs/rules.md`

If the rule registry changes, regenerate or manually verify `docs/rules.md`
against `gruff-go list-rules --format json`.

## Binary Wrapper

`bin/gruff-go` must expose the same command surface as source. Rebuild or remove
the tracked binary whenever CLI source changes:

```sh
go build -o bin/gruff-go ./cmd/gruff-go
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
