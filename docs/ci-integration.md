# CI Integration

`gruff-go` is built to run in CI without any plugin or external service. The exit code (`0` clean, `1` findings, `2` diagnostics or invalid input) is the primary integration surface; the output formats decide how the findings show up alongside that exit code.

This page is a copy-paste cheat sheet for common runners and the recommended rollout pattern for existing codebases.

> **Flag ordering.** Every `--flag` must appear before the path arguments - `gruff-go` uses the Go standard `flag` package, which stops parsing at the first non-flag token. Write `gruff-go analyse --baseline foo.json .`, not `gruff-go analyse . --baseline foo.json`.

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

3. **Drift-down** - periodically regenerate the baseline as the team fixes findings.

   ```bash
   # In a clean-up branch.
   gruff-go analyse --generate-baseline gruff-baseline.json .
   ```

Inside a PR, prefer `--diff-base origin/main` to scope findings to changed lines only:

```bash
gruff-go analyse --diff-base origin/main .
```

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
          fetch-depth: 0  # required for --diff-base

      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install gruff-go
        run: go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.1.0

      - name: Scan (diff-mode for PRs, full for push)
        run: |
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            gruff-go analyse --baseline gruff-baseline.json --diff-base origin/${{ github.base_ref }} --format github .
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
    - go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.1.0
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

GitLab's SAST report consumer picks up SARIF directly. To scope MR pipelines to changed lines, add `--diff-base $CI_MERGE_REQUEST_DIFF_BASE_SHA`.

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
          command: go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.1.0
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
                sh 'go install github.com/blundergoat/gruff-go/cmd/gruff-go@v0.1.0'
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
        entry: gruff-go analyse --diff-base HEAD --min-severity error .
        language: system
        pass_filenames: false
        types: [go]
```

Pair `--diff-base HEAD` with `--min-severity error` so the hook stays fast and only blocks on serious regressions in the working tree.

## Threshold knobs

The two flags that most CI configurations end up tuning:

- `--min-severity` - default `advisory` (every finding fails). Set `warning` for moderate gating, or `error` for strict gating that blocks only on the highest-impact findings. Add `none` to disable the gate entirely (report findings, always exit 0). The four values (`advisory | warning | error | none`) live on `finding.FailThreshold`; the three severity-equivalent values reuse the 3-bucket vocabulary from [ADR-009](../.goat-flow/decisions/ADR-009-three-severity-model.md). `none` was added in v0.1.2 per [ADR-010](../.goat-flow/decisions/ADR-010-per-command-minimum-severity.md).
- `--fail-on` is an alias for `--min-severity`.

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
- Pass `--min-severity none` (or set `minimumSeverity.analyse: none` in the project config). The exit code is forced to 0 regardless of findings.

## Common pitfalls

- **Shallow clones** break `--diff-base`. Use `fetch-depth: 0` (Actions), `GIT_DEPTH: 0` (GitLab), or whichever full-history flag your runner takes.
- **First run on a busy codebase** with thousands of findings is a waste of CI cycles. Generate a baseline locally first, commit it, and let CI scan against it.
- **Display filters ≠ score filters.** `--include-rules`, `--exclude-rules`, `--include-pillars`, `--exclude-pillars` only hide findings from the rendered output. The composite score, exit code, and SARIF results still see the full set. If you need a *real* exclusion, turn the rule off in `.gruff-go.yaml`.
