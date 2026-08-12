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

   Gruff pairs exact fingerprints first, then remaining line-insensitive contract
   identities, consuming one current and one prior occurrence per match. Harmless
   line or measured-value shifts therefore stay reviewed, while a single baseline
   row cannot hide several duplicate findings. Older rows without
   `stableIdentity` continue to match exact fingerprints only.

3. **Drift-down** - periodically regenerate the baseline as the team fixes findings.

   ```bash
   # In a clean-up branch.
   gruff-go analyse --generate-baseline gruff-baseline.json .
   ```

Inside a PR, prefer `--since origin/main` to scope findings to the changed region only:

```bash
gruff-go analyse --since origin/main .
```

`--diff-base <ref>` is the older name for the same base-ref scoping and still works, so existing pipelines need no change. New recipes should use `--since`, which sits alongside `--diff`, `--changed-ranges`, and `--changed-scope symbol|hunk`.

Diff mode records a `"diff mode is changed-line scoped"` caveat in the report so consumers know the scan wasn't full-project.

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
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # required for --since

      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install gruff-go
        run: go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.4.0

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
        uses: github/codeql-action/upload-sarif@v3
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
        uses: actions/upload-artifact@v4
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
    - go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.4.0
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
          command: go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.4.0
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
                sh 'go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.4.0'
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
        entry: gruff-go analyse --since HEAD --min-severity advisory .
        language: system
        pass_filenames: false
        types: [go]
```

`--since HEAD` scopes the hook to changed regions. `--min-severity advisory` keeps the gate at gruff-go’s comprehensive default, so every reported finding can block.

## Threshold knobs

The two flags that most CI configurations end up tuning:

- `--min-severity` - the binary default is **per command**, not a single value: `advisory` for the gating commands (`analyse`, `summary`) and `none` for the artifact generators (`report`, `dashboard`). [`configuration.md`](configuration.md#minimumseverity) carries the authoritative table. `advisory` is the broadest gate: every finding can fail the run. `warning` narrows the gate to warning and error findings; `error` narrows it to error findings only; `none` disables finding-driven exit `1`. The four values (`advisory | warning | error | none`) live on `finding.FailThreshold`; the three severity-equivalent values reuse the vocabulary from [ADR-009](../.goat-flow/learning-loop/decisions/ADR-009-three-severity-model.md). `none` and the per-command defaults were added in v0.2.0 per [ADR-010](../.goat-flow/learning-loop/decisions/ADR-010-per-command-minimum-severity.md).
- `--fail-on` is an alias for `--min-severity`.

### `--fail-on=error` is not a security gate

With the built-in v0.5.0 registry, all 22 default-enabled `security.*` rules are below error: 20 advisory and 2 warning. An error-only gate therefore ignores every built-in `security.*` finding, including `security.sql-string-query` and `security.shell-command`. Some `sensitive-data.*` rules use error severity, but that separate rule family does not cover the application-security classes under `security.*`.

The below-error invariant is enforced, not just documented: `TestDefaultSecurityRulesStayBelowError` in `internal/rule/` reads the built-in registry and fails the build if any default-enabled `security.*` rule reaches error, naming this section in its failure message. Verify the live numbers yourself with `gruff-go list-rules --no-config --format json` - without `--no-config` you get the effective severities after your own `.gruff-go.yaml` overrides, which is a different question.

Use the advisory floor when CI is intended to gate on all detected security issues. `analyse` and `summary` default to it, so the recipes above already gate. `report` and `dashboard` default to `none` and have **no** finding gate, so a pipeline whose failing step is one of those needs an explicit `--min-severity advisory` or a `minimumSeverity` entry - an artifact generator reports security findings and still exits `0`. For an existing codebase, reduce initial scope with a baseline or `--since` rather than raising the severity floor and silently excluding detected classes.

### Open family decision: security findings and grade A

A run can report security findings and still receive grade A because the composite is a weighted aggregate. A fixture containing a dynamic SQL query and explicit shell execution scores A (99 / 100) while `--fail-on=error` exits `0`; the default advisory gate exits `1` for the same report. Grade A means the aggregate score is at least 90, not that the scan found no security issues.

The evidence behind this question - the registry distribution, the fixture above, the mitigating gate defaults, and this project's own `.gruff-go.yaml` override of `security.shell-command` to error - is recorded in [ADR-020](../.goat-flow/learning-loop/decisions/ADR-020-security-tier-evidence-routed-to-family.md), which routes the decision to the family rather than taking it.

Gruff family contract §12 must decide whether any `security.*` finding should cap the composite below A or whether grades and finding gates remain independent. A cap would change serialized scores, grades, and cross-port semantics. No cap, severity, or scoring change is made here. Until that decision is ratified, CI should gate on findings at the advisory floor - on a command that has one, per the note above - and must not treat grade A as security proof.

For projects that want per-command defaults without passing the flag on every invocation, set [`minimumSeverity`](configuration.md#minimumseverity) in `.gruff-go.yaml`:

```yaml
minimumSeverity:
  analyse: warning   # CI gate: fail on warning+
  summary: warning
  report: none       # artifact generation: never fail
  dashboard: none
```

The CLI flag still wins when set; the config block supplies the per-command default; the binary default applies when neither is present. Full precedence is recorded in ADR-010.

If CI needs to **scan and report** without **failing**, two equally valid options:
- Run the scan in a step with `continue-on-error: true` (GitHub Actions) or `allow_failure: true` (GitLab) and upload the report artefact separately.
- Pass `--min-severity none` (or set `minimumSeverity.analyse: none` in the project config). Findings cannot produce exit `1`, but diagnostics and invalid input still produce exit `2`.

Thresholds never downgrade operational failures. Missing paths, parse errors,
baseline or diff failures, and invalid configuration/CLI input exit `2` at every
threshold, including `none`.

## Common pitfalls

- **Shallow clones** break base-ref scoping (`--since`, `--diff-base`). Use `fetch-depth: 0` (Actions), `GIT_DEPTH: 0` (GitLab), or whichever full-history flag your runner takes.
- **First run on a busy codebase** with thousands of findings is a waste of CI cycles. Generate a baseline locally first, commit it, and let CI scan against it.
- **Display filters ≠ score filters.** `--include-rules`, `--exclude-rules`, `--include-pillars`, `--exclude-pillars` only hide findings from the rendered output. The composite score, exit code, and SARIF results still see the full set. If you need a *real* exclusion, turn the rule off in `.gruff-go.yaml`.
