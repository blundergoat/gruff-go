# Glossary

Last reviewed 2026-05-16.

## gruff-go

Go CLI quality scanner in module `github.com/blundergoat/gruff-go`. The runtime entrypoint is `cmd/gruff-go/main.go`; parser-only discovery, config loading, rules, analysis, scoring, baselines, diff filtering, and report rendering live under `internal/`.

## Parser-Only Scanner

The v0.1 analysis model uses standard-library source discovery and `go/parser` without `golang.org/x/tools/go/packages`. Type-aware rules are deferred until there is evidence that the extra dependency and runtime cost are worth it.

## Gruff Config

Analysis config loaded explicitly by `--config` or discovered as `.gruff-go.yaml`. The root `.gruff-go.yaml` is this repository's dogfood config. It uses the gruff-family shape `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, `selection`, and `rules.<id>`. Rule IDs are canonical dotted names, while legacy hyphen-only and old `documentation.*` aliases are still accepted for rule-ID compatibility.

## Rule ID

Stable public identifier for one rule. gruff-go now emits dotted gruff-family IDs such as `size.file-length`, `docs.package-comment`, and `sensitive-data.secret-pattern`; old config aliases such as `size-file-length` and `documentation.package-comment` canonicalize to the dotted form.

## Accepted Abbreviation

An initialism accepted by naming rules through `allowlists.acceptedAbbreviations`. gruff-go currently validates these as uppercase values such as `ID`, `HTTP`, and `AST`, unlike newer implementations that normalize lowercase values.

## Finding

A rule-produced quality result with rule ID, severity, confidence, pillar, location metadata, remediation, and a stable fingerprint.

## Fingerprint

Stable 16-character hash derived from a finding's identity fields. Baselines and downstream tooling can key on it together with rule ID and file path.

## Baseline

A JSON file with schema `gruff-go.baseline.v0.1` that stores rule ID, file, and fingerprint entries. Applying a baseline suppresses only exact matches and reports stale entries.

## Diagnostic

A run-level problem such as a missing input path, read error, parse error, config error, baseline error, or diff error. Diagnostics force analysis exit code `2`.

## Diff Mode

The `--diff-base` analysis mode. It uses local `git diff --unified=0` output to keep findings whose location overlaps changed lines and records a caveat that the run is changed-line scoped rather than full-project proof.

## SARIF

The Static Analysis Results Interchange Format. `gruff-go` emits SARIF 2.1.0 from the same report data used by text, JSON, summary JSON, and GitHub annotation output.

## Dashboard

Local-only `gruff-go dashboard` HTTP server. It binds to loopback by default, renders a dashboard shell around the HTML report, and runs scans in-process with explicit project root/context options rather than changing the process working directory.

## Opt-In Rule

A rule listed by `list-rules` with `defaultEnabled: false`. It can be enabled through strict config, but default scans skip it so experimental or context-sensitive signals do not change baseline dogfood behavior.

## Composite Design Finding

A score-neutral `design.*` finding derived from already-emitted base findings. Current composites are `design.god-function` for same-symbol size plus complexity overlap and `design.hotspot-file` for multi-pillar file hotspots. Composites do not feed other composite rules.

## GOAT Flow

Local agent workflow framework installed from `@blundergoat/goat-flow`. It provides Claude/Codex skills, audit commands, safety references, and `.goat-flow/` project-memory directories.

## Agent-Owned Surfaces

Files one agent setup owns without widening scope. Claude owns `CLAUDE.md` and `.claude/**`; Codex owns `AGENTS.md`, `.codex/config.toml`, `.codex/hooks.json`, and `.codex/hooks/**`.

## Learning Loop

Durable shared project-memory directories under `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, and `.goat-flow/decisions/`.

## Gitignored Discovery Skip

A `paths.skipped` entry with reason `gitignored` indicates the path matched a rule in the repo's own `.gitignore` chain (see ADR-004 and ADR-005). Discovery never consults the user's global gitignore, `.git/info/exclude`, or any external Git state. A malformed `.gitignore` produces one entry with reason `gitignore-parse-error` and its rules are dropped wholesale.

## --include-ignored

CLI flag on `analyse`, `baseline`, `summary`, and `dashboard`. When set, discovery bypasses both the gitignore filter and the hardcoded fallback directory list, scans every classifiable file in the working tree, and emits `run.includeIgnored: true` in the JSON output. The flag is the documented opt-out; there is no per-rule split.
