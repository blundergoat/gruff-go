# Using gruff as an agent guardrail

gruff-go's purpose is to make AI-generated code something a human can trust:
legible enough to verify, secure where review misses, and tested for real rather
than padded with low-signal ceremony. See the [README mission](../README.md#mission)
for the framing and [ADR-011](../.goat-flow/decisions/ADR-011-mission-ai-generated-code-verifiability.md)
for the decision record.

This page is about deploying gruff for that purpose: as a gate on code a coding
agent produced and a human now has to sign off on.

## The loop

The guardrail is a cycle, not a one-shot scan:

1. The agent writes or edits code.
2. gruff scans it and emits findings (legibility, security, test quality).
3. The agent fixes the findings before handing off.
4. A human reviews code that is already legible, documented, and honestly tested.

Run gruff at step 2 as a non-optional step in the agent's edit loop, and again at
commit and in CI. The point is that the human at step 4 never sees the noise -
they see code that already clears the bar, with doc comments to check the
implementation against.

> Commands below use `gruff-go`; substitute however you installed it
> (`go tool gruff-go`, `./bin/gruff-go`, or a binary on `PATH`).

## Wiring it in

### In the agent loop (primary)

Run after the agent edits, and gate on every finding so the agent clears it all
before a human looks:

```bash
gruff-go analyse --min-severity advisory .
```

To judge the agent on its own work rather than the whole repo, scan only the
changed region with the diff-aware flags - `--diff`, `--since`,
`--changed-ranges`, and `--changed-scope symbol|hunk`. See
`gruff-go analyse --help` and [CI Integration](ci-integration.md) for the exact
recipes. Feed the findings back to the agent and re-run until clean.

### Pre-commit hook

```bash
# .git/hooks/pre-commit
gruff-go analyse --min-severity warning . || {
  echo "gruff: fix findings (or scope with --baseline) before committing" >&2
  exit 1
}
```

### CI gate

Run gruff in CI and upload SARIF for code scanning; see
[CI Integration](ci-integration.md) for the GitHub Actions recipe and exit-code
semantics.

```bash
gruff-go analyse --format sarif --min-severity error . > gruff.sarif
```

### Existing codebases

Adopt without drowning in legacy debt: baseline the current findings, then gate
only on new ones.

```bash
gruff-go analyse --generate-baseline gruff-baseline.json .
gruff-go analyse --baseline gruff-baseline.json --min-severity advisory .
```

## How the rules serve the mission

| Axis | What enforces it |
| --- | --- |
| Legible enough to verify | `size.*`, `complexity.*`, and `docs.*` - especially `docs.comment-rubric` with `minWordsBeyondSymbol` set, which rejects name-restatement comments so a doc actually states intent a reviewer can check against the code. |
| Secure where the eye fails | the `security.*` and `sensitive-data.*` pillars. |
| Tested for real, not padded | `test-quality.*` - `no-failure-path`, `empty-test`, the skip and sleep checks - which reject assertion-free and ceremony tests. |

Tune these in [Configuration](configuration.md); the full catalogue is in
[Rules](rules.md).

## Recommended settings for agent-generated code

- **`--min-severity advisory` inside the agent loop.** The agent should clear
  everything; do not let it defer findings to the human reviewer.
- **Keep `docs.comment-rubric`'s signal floor.** `minWordsBeyondSymbol` is what
  stops the agent from satisfying the doc requirement with a comment that just
  restates the symbol name. Lowering it turns documentation into ceremony.
- **Gate on the diff, baseline the rest.** New code clears the full bar; legacy
  debt is tracked, not blocking.

## Honest limit

gruff is parser-only heuristic analysis, not a proof. It can force the agent to
*produce* the artifact a reviewer checks - a doc comment, an assertion - but it
cannot verify that artifact is *truthful*: a doc comment can lie, an assertion
can be vacuous. That judgement stays with the human (or a semantic/LLM review
step). gruff makes the final review tractable; it does not replace it. Run it
beside `go vet`, `staticcheck`, `govulncheck`, and tests.
