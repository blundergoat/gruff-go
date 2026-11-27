# CI Integration

`gruff-go` is built to run in CI without any plugin or external service. The exit code (`0` clean, `1` findings, `2` diagnostics or invalid input) is the primary integration surface; the output formats decide how the findings show up alongside that exit code.

This page is a copy-paste cheat sheet for common runners and the recommended rollout pattern for existing codebases.

> **Flag ordering.** Flags may appear before, between, or after path arguments. `--` ends flag parsing; use `gruff-go analyse -- -leading-dash-path` when a path begins with `-`.

## Recommended rollout pattern

Adopting any new static analysis tool on a real codebase tends to trigger a baseline avalanche. `gruff-go` handles this with a three-step rollout:

1. **First run** - generate a baseline of the current state. Don't fail the build.

   ```bash
   gruff-go analyse --generate-baseline gruff-baseline.json .
   git add gruff-baseline.json
   git commit -m "chore: capture initial gruff-go baseline"
   ```

2. **Steady state** - fail on regressions against the baseline.

   ```bash
   gruff-go analyse --baseline gruff-baseline.json .
   ```

   A `gruff-baseline.json` at the project root also applies without `--baseline`,
   and the text report names it, as `baseline: default gruff-baseline.json;
   suppressed N findings`. Pass `--no-baseline` to see every finding.

   `gruff.baseline.v3` matches findings by a line-insensitive 16-hex SHA-256
   `identity` (tool language, rule ID, project-relative path, and symbol plus
   declaration ordinal or normalized message) with a count budget. Harmless line
   or measured-value shifts therefore stay reviewed, while duplicate occurrences
   past the recorded count report as new. Non-v3 baselines fail closed until
   migrated with `gruff-go baseline --migrate-baseline`.

3. **Drift-down** - periodically regenerate the baseline as the team fixes findings.

   ```bash
   # In a clean-up branch.
   gruff-go analyse --generate-baseline gruff-baseline.json .
   ```

Inside a PR, prefer `--since origin/main` to scope findings to the changed region only:

```bash
gruff-go analyse --since origin/main .
```

`--diff-base <ref>` is the family-canonical spelling for base-ref scoping and gruff-go accepts it, so a pipeline written against another port needs no change here. `--since` is gruff-go's own spelling and is what the recipe above uses. Both sit alongside `--diff`, `--changed-ranges`, and `--changed-scope symbol|hunk`.

Diff mode records a `"diff mode is changed-line scoped"` caveat in the report so consumers know the scan wasn't full-project.

Use `git diff --unified=0 origin/main | gruff-go analyse --diff=- .` when the pipeline supplies the patch on standard input.
An empty Git diff is valid. Unrecognized input, such as a piped error message, produces a changed-region diagnostic and exit code `2`.

## GitHub Actions

### Inline annotations + summary

```yaml
# .github/workflows/gruff-go.yml
name: gruff-go

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0  # required for --since

      - uses: actions/setup-go@v7
        with:
          go-version: '1.27'  # the Go that builds gruff-go decides which syntax it can parse

      - name: Install gruff-go
        run: go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.6.0

      - name: Scan (diff-mode for PRs, full for push)
        run: |
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            gruff-go analyse --baseline gruff-baseline.json --since origin/${{ github.base_ref }} --format github .
          else
            gruff-go analyse --baseline gruff-baseline.json --format github .
          fi
```

The `--format github` output is one workflow command per finding, so each one shows up in the PR diff as an inline annotation without any extra action.

### SARIF upload to Code Scanning

```yaml
      - name: Scan to SARIF
        run: gruff-go analyse --baseline gruff-baseline.json --format sarif . > gruff-go.sarif
        continue-on-error: true   # let the upload step run even if findings fail the build

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: gruff-go.sarif
          category: gruff-go
```

Code Scanning will track findings over time, surface them in the Security tab, and dedupe across runs using the `partialFingerprints.gruffFingerprint` value `gruff-go` emits.

### Archive the HTML report as an artefact

```yaml
      - name: Render HTML report
        if: always()
        run: gruff-go analyse --baseline gruff-baseline.json --format html . > gruff-report.html

      - name: Upload HTML report
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: gruff-report
          path: gruff-report.html
```

Reviewers can download the artefact and open it locally. The HTML report is self-contained - no external network requests.

## GitLab CI

```yaml
# .gitlab-ci.yml
gruff-go:
  image: golang:1.25
  stage: test
  script:
    - go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.6.0
    - gruff-go analyse --baseline gruff-baseline.json --format sarif . > gruff-report.sarif
  artifacts:
    when: always
    reports:
      sast: gruff-report.sarif
    paths:
      - gruff-report.sarif
  rules:
    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

GitLab's SAST report consumer picks up SARIF directly. To scope MR pipelines to changed lines, add `--since $CI_MERGE_REQUEST_DIFF_BASE_SHA`.

## CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  gruff-go:
    docker:
      - image: cimg/go:1.25
    steps:
      - checkout
      - run:
          name: Install gruff-go
          command: go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.6.0
      - run:
          name: Scan
          command: gruff-go analyse --baseline gruff-baseline.json .
      - run:
          name: Archive HTML report
          when: always
          command: gruff-go analyse --format html . > /tmp/gruff-report.html || true
      - store_artifacts:
          path: /tmp/gruff-report.html
          destination: gruff-report.html
```

## Jenkins (declarative)

```groovy
pipeline {
    agent any
    tools {
        go '1.25'
    }
    stages {
        stage('gruff-go') {
            steps {
                sh 'go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.6.0'
                sh 'gruff-go analyse --baseline gruff-baseline.json --format sarif . > gruff-report.sarif'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'gruff-report.sarif', fingerprint: true
                }
            }
        }
    }
}
```

## Pre-commit hook

For local enforcement before code even reaches CI:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: gruff-go
        name: gruff-go
        entry: gruff-go analyse --since HEAD --fail-on advisory .
        language: system
        pass_filenames: false
        types: [go]
```

`--since HEAD` scopes the hook to changed regions. `--fail-on advisory` keeps the gate at gruff-go’s comprehensive default, so every reported finding can block.

## Threshold knobs

The one flag most CI configurations end up tuning:

- `--fail-on` - the binary default is **per command**, not a single value: `advisory` for the gating command (`analyse`) and `none` for `summary` and the artifact generators (`report`, `dashboard`). A CI job that gates on `summary` passes `--fail-on` or sets `failOn.summary`. [`configuration.md`](configuration.md#failon) carries the authoritative table. `advisory` is the broadest gate: every finding can fail the run. `warning` narrows the gate to warning and error findings; `error` narrows it to error findings only; `none` disables finding-driven exit `1`. The four values (`advisory | warning | error | none`) live on `finding.FailThreshold`; the three severity-equivalent values reuse the vocabulary from [ADR-009](../.goat-flow/learning-loop/decisions/ADR-009-three-severity-model.md). `none` and the per-command defaults were added in v0.2.0 per [ADR-010](../.goat-flow/learning-loop/decisions/ADR-010-per-command-minimum-severity.md).

Migrating from 0.5: `--min-severity` is refused in 0.6.0 and returns in 0.7.0 as a display filter. The config key [`minimumSeverity`](configuration.md#minimumseverity) already carries that display floor, and never changes an exit code.

### `--fail-on=error` is not a security gate

With the built-in v0.6.0 registry, all 17 default-enabled `security.*` rules are below error: 15 advisory and 2 warning. An error-only gate therefore ignores every built-in `security.*` finding, including `security.shell-command` (`security.sql-string-query`, which this sentence named, was removed in 0.6.0). No default-enabled `sensitive-data.*` rule reaches error either: since 0.6.0 every one defaults to warning, so an error-only gate ignores every built-in secret finding too.

The below-error invariant is enforced in tests: `TestDefaultSecurityRulesStayBelowError` in `internal/rule/` reads the built-in registry and fails the build if any default-enabled `security.*` rule reaches `error`, citing this section in its failure message. Verify the live counts yourself with `gruff-go list-rules --no-config --format json` (`list-rules` always prints the built-in defaults; `--no-config` skips validating your local `.gruff-go.yaml`).

Use `--fail-on advisory` to gate CI on every reported security finding — `analyse` already uses this by default. `summary`, `report`, and `dashboard` need an explicit `--fail-on` flag or a `failOn` entry such as `failOn.summary: advisory`. On an existing codebase, use a baseline or `--since` to limit initial scope while keeping all severities eligible for the gate.

### Open family decision: security findings and grade A

Because the composite score averages pillars, a run can report security findings and still earn grade `A`. In [ADR-020](../.goat-flow/learning-loop/decisions/ADR-020-security-tier-evidence-routed-to-family.md), a fixture carrying explicit shell execution and a dynamic SQL finding scored `A (99 / 100)`: `--fail-on=error` exited `0`, while the default `advisory` gate exited `1`. Grade `A` means the weighted aggregate is at least 90, not that the scan found zero security issues.

[ADR-020](../.goat-flow/learning-loop/decisions/ADR-020-security-tier-evidence-routed-to-family.md) records the evidence — registry distribution, fixture behaviour, gate defaults, and this repo's own `.gruff-go.yaml` override raising `security.shell-command` to `error` — and routes the grade-cap question to the cross-port family contract (§12). Capping grade `A` on `security.*` findings would change serialized scores and cross-port semantics, so no cap is applied here. Until ratified across ports, gate CI on findings at `advisory` rather than treating grade `A` as security proof.

For projects that want per-command defaults without passing the flag on every invocation, set [`failOn`](configuration.md#failon) in `.gruff-go.yaml`:

```yaml
failOn:
  analyse: warning   # CI gate: fail on warning+
  summary: warning
  report: none       # artifact generation: never fail
  dashboard: none
```

The CLI flag still wins when set; the config block supplies the per-command default; the binary default applies when neither is present. Full precedence is recorded in ADR-010.

If CI needs to **scan and report** without **failing**, two equally valid options:
- Run the scan in a step with `continue-on-error: true` (GitHub Actions) or `allow_failure: true` (GitLab) and upload the report artefact separately.
- Pass `--fail-on none` (or set `failOn.analyse: none` in the project config). Findings cannot produce exit `1`, but diagnostics and invalid input still produce exit `2`.

Thresholds never downgrade operational failures. Missing paths, parse errors,
baseline or diff failures, and invalid configuration/CLI input exit `2` at every
threshold, including `none`.

## Common pitfalls

- **Shallow clones** break base-ref scoping (`--since`, `--diff-base`). Use `fetch-depth: 0` (Actions), `GIT_DEPTH: 0` (GitLab), or whichever full-history flag your runner takes.
- **First run on a busy codebase** with thousands of findings is a waste of CI cycles. Generate a baseline locally first, commit it, and let CI scan against it.
- **Display filters ≠ score filters.** `--show-rule`, `--hide-rule`, `--show-pillar`, `--hide-pillar`, and `minimumSeverity` filter the rendered output (including text, JSON `findings`, and SARIF `results`), while the composite score and exit code still reflect the full scan. To exclude a rule from execution and scoring, disable it in `.gruff-go.yaml` or pass `--exclude-rule` / `--exclude-pillar`.
