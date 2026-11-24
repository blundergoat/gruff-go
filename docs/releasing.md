# Releasing

This page captures the gruff-go release checks that protect the user-facing CLI
and report contracts.

## Preflight

Run the local check suite before tagging:

```sh
scripts/preflight-checks.sh
```

Preflight is the release gate and runs 12 checks: version metadata, `npm audit`,
`govulncheck`, `bash -n`, `shellcheck`, post-turn limit hardening, `gofmt -l`,
`go vet`, `go test ./...`, a dogfood self-scan (must return grade A with zero
findings), documentation drift, and documentation drift fixtures. `make check`
covers only the three Go checks in that list and is the edit-time floor, so
preflight supersedes it here.

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

`--fail-on` is the exit-gate flag. `--min-severity` is refused in 0.6.0 and
returns in 0.7.0 as a display filter.

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
no-config registry, and `TestDocsRulesPrecisionGuidanceMatchesRegistry` verifies
lockstep false-positive guidance, so registry drift fails `go test ./internal/cli/...`.
`scripts/preflight-checks.sh` also checks `README.md` and `docs/*.md` for catalogue
counts, pillar tables, unknown rule IDs, cited ADRs, and README links; prose accuracy
and examples still need a human pass.

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
