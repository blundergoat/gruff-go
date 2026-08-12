---
category: cli
last_reviewed: 2026-08-12
---

# CLI Argument Footguns

## Footgun: Go's `flag` package stops parsing at the first operand

**Status:** active | **Created:** 2026-08-12 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** A new subcommand must route through `parseCommandArguments`, never `FlagSet.Parse`; and a command that consumes no operands must reject them rather than let `Args()` fall on the floor.
**Trigger phase:** ACT

hallucination-risk: high (the stdlib behaviour produces no error and no warning — a flag placed after a path is simply absent, so the command runs successfully with the wrong configuration and every surface reports success)

Go's `flag.FlagSet.Parse` stops at the first non-flag token and leaves everything after it in
`FlagSet.Args()`. It does not error. A subcommand that treats `Args()` as paths therefore accepts
flags as filenames, and a subcommand that ignores `Args()` accepts them as nothing at all. Both
failures are silent.

Evidence:

- `internal/cli/flags.go` (search: `func parseCommandArguments`) — the repair. Before it existed,
  `analyse <path> --format json` emitted TEXT and exited 2 while
  `analyse --format json <path>` emitted JSON and exited 0. A bogus flag was rejected in front and
  ignored behind: `analyse --bogus <path>` exited 2, `analyse <path> --bogus` scanned and exited 0.
- `internal/cli/flag_order_test.go` (search: `TestPathCommandsAcceptFlagsAfterPaths`) — the six
  operand-accepting commands are pinned by a byte-identical-stdout comparison. The affected set is
  `analyse`, `baseline`, `summary`, `report`, **`hook`**, and **`check-ignore`**. `hook` matters
  most: it is the port's primary surface.
- Measured 2026-08-12, the second half of the same trap in commands that take no operands:
  `list-rules --no-config --format text ./nonexistent-path-xyz` exited **0** with the full rule list,
  operand discarded. `dashboard --no-config --port 38517 main.go` **bound a listener** and ran until
  killed, scanning whatever `--project`/`--paths` resolved to and never the path the user named.
  `completion bash extra` used `Arg(0)` and dropped the rest.
- `internal/cli/init.go` (search: `init takes no positional arguments`) — the one command that got
  this right from the start, and the template the others now copy.
- `internal/cli/dashboard.go` (search: `dashboard takes no positional arguments`) and
  `internal/cli/positional_test.go` — the repair for the no-operand half.

What this means in practice:

- `parseCommandArguments` partitions arguments into flags and operands, lets a registered
  non-Boolean flag claim its following token even when that token starts with `-`, then re-parses
  with a synthetic `--` so reordered operands stay positional. `--` and a bare `-` still terminate.
- Adding a subcommand means two decisions, not one: parse through `parseCommandArguments`, **and**
  decide what `NArg()` means for that command. There is no safe default — ignoring `Args()` is the
  silent-failure path.
- `dashboard` is the trap's worst shape because a rejected operand is cheap and an ignored one starts
  a server that scans the wrong tree. Prefer rejecting over guessing which flag the operand meant.
- All five gruff ports hit this class in their own argument layers, so a port-local fix is not a
  family fix. The gruff family contract governs the shared CLI surface and is maintained outside this
  repository; as of 2026-08-12 its CLI-surface section covers flag acceptance and input kinds but has
  no argument-ordering clause, so cross-port agreement here rests on convention rather than contract.

How to avoid:

- Never call `FlagSet.Parse` directly in `internal/cli`. Grep before adding a command:
  `rg -n 'flags?\.Parse\(' internal/cli` should return nothing.
- After adding a command that takes paths, add its row to `TestPathCommandsAcceptFlagsAfterPaths`.
  After adding one that does not, add its row to `TestCommandsRejectUnusedPositionalArguments`.
- When auditing which commands are affected, do not trust a `flag.NewFlagSet` grep as the answer.
  It over-matches commands that never consume operands and says nothing about which ones do. The
  question is what happens to `Args()`, so grep `\.Args\(\)` and `NArg\(\)` and read each site.

## Footgun: `go run` does not propagate the program's exit code

**Status:** active | **Created:** 2026-08-12 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Verify any CLI exit-code contract with a compiled binary; a `go run` exit status is evidence of nothing but success versus failure.
**Trigger phase:** VERIFY

hallucination-risk: medium (the number looks like a real exit code and is plausible — `1` where the program returned `2` — so it silently corrupts an exit-code table nobody re-checks)

`go run` exits **1** whenever the program exits non-zero, printing `exit status N` to stderr rather
than adopting `N`. gruff-go's exit contract distinguishes `0`, `1` (findings gated), and `2` (invalid
input or fatal diagnostic), so measuring it through `go run` collapses two of the three states.

Evidence:

- Measured 2026-08-12. `go run ./cmd/gruff-go check-ignore --no-config` reported exit **1**. The same
  invocation from a compiled binary reported exit **2**, which is what
  `internal/cli/check_ignore.go` (search: `check-ignore requires at least one path`) actually
  returns. A remediation plan's defect table recorded the wrong `1` from the `go run` measurement and
  had to be corrected during execution.
- `README.md` (search: `Invalid input or a fatal diagnostic`) — the three-state contract this
  destroys.

What this means in practice:

- `go run` is fine for reading output and for pass/fail. It is not fine for any assertion of the form
  "this exits 2".
- Redirecting stderr hides the `exit status N` line that would otherwise give the game away, so the
  common `>/dev/null 2>&1; echo $?` idiom is the exact shape that produces a wrong number silently.

How to avoid:

- `go build -o <tmp>/gruff-go ./cmd/gruff-go` first, then measure the binary. The dogfood and
  preflight paths already do this.
- In Go tests, call `Main(...)` directly — `internal/cli/flag_order_test.go` (search:
  `func captureCLIResult`) returns the real integer with no subprocess in the way.
