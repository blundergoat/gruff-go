---
category: cli
last_reviewed: 2026-08-12
---

# CLI Argument Patterns

## Pattern: Partition then re-parse to accept flags in any position

**Created:** 2026-08-12

**Evidence:** OBSERVED

**Context:** Go's `flag.FlagSet.Parse` stops at the first operand, so every gruff-go subcommand that
took positional paths silently discarded any flag placed after one — see the matching entry in
`../footguns/cli.md` (search: "stops parsing at the first operand"). The family surface expects
argument order not to change behaviour, and four sibling ports already permuted, so "document that
flags go first" was not an acceptable answer. Rejecting trailing flags outright would have removed
the silent-wrong-result class but created a new cross-port divergence.

**Approach:** `internal/cli/flags.go` (search: `func parseCommandArguments`) makes one pass over the
raw arguments, splitting them into two slices, then hands the stdlib a rearranged argument list:

- A token matching `hasFlagSyntax` (longer than one character, leading `-`) goes to the flag slice.
  If it names a registered non-Boolean flag, the **next** token is pulled with it, so a flag value
  that itself begins with `-` is never mistaken for a flag. Boolean flags do not claim a following
  token, matching stdlib `-flag=value`-only semantics.
- `--` sends every later token to the operand slice and stops the scan; a bare `-` does the same but
  keeps itself as an operand, preserving the conventional stdin spelling.
- Everything else is an operand, in the caller's original order.
- The rebuilt list is `flags... ++ "--" ++ operands...`. The synthetic terminator is what makes the
  reordering safe: without it the stdlib would stop at the first operand again.

Call it in place of `FlagSet.Parse` everywhere. Commands that consume no operands still need their
own `NArg()` guard afterwards — permutation decides where a flag may appear, not whether a stray
operand is acceptable. `internal/cli/init.go` (search: `init takes no positional arguments`) is the
guard template.

**Why this shape rather than a hand-written parser:** the stdlib keeps ownership of flag lookup,
type conversion, error text, and `--help`, so the unknown-flag message a user sees is unchanged
(`flag provided but not defined: -bogus`) and there is no second parser to keep in sync with the
flag registrations.

**Pinned by:** `internal/cli/flag_order_test.go` — byte-identical stdout across both argument orders
for all six operand-accepting commands (`TestPathCommandsAcceptFlagsAfterPaths`), trailing unknown
flags rejected (`TestAnalyseRejectsUnknownFlagAfterPath`), and both terminators
(`TestDoubleDashPreservesLeadingDashPaths`, `TestBareDashStopsFlagParsing`).
