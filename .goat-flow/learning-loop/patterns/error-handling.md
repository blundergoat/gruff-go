---
category: error-handling
last_reviewed: 2026-05-27
---

# Error-Handling Patterns

## Pattern: User-facing errors name the bad value, the expected value, and the exact remediation command

**Context:** Any error that rejects user input — config field, baseline file, CLI flag value, schema version, severity bucket, threshold sentinel, YAML decode failure. A terse error like `unsupported schemaVersion "0.1"` already knows everything the user needs (the expected constant lives in the same file; the regeneration command is stable CLI surface) but withholds it, turning a 5-second fix into a documentation hunt. Concrete prior offenders: `internal/config/config.go::Config.Validate` and `internal/baseline/baseline.go::Parse` both returned `fmt.Errorf("unsupported schemaVersion %q", ...)` until the 2026-05-27 sweep replaced them with the trio form.

**Approach:** Every user-facing rejection error includes all three:

1. **What was wrong** — the bad value, quoted so whitespace and case are visible (`%q`, not `%s`).
2. **What was expected** — the literal expected value or the closed vocabulary (e.g. `expected "0.2"`, or `must be one of advisory|warning|error|none`).
3. **How to fix it** — the exact runnable command, not a doc link or category of action.

Prefer:

```go
return fmt.Errorf("unsupported schemaVersion %q; expected %q. Run `gruff-go init --force` to regenerate the config (your tuning is preserved)", cfg.SchemaVersion, SchemaVersion)
```

over:

```go
return fmt.Errorf("unsupported schemaVersion %q", cfg.SchemaVersion)
```

When the remediation has a side effect worth flagging (overwrites file, drops tuning, takes minutes), mention it in parentheses so the user is not surprised. The schemaVersion example notes "your tuning is preserved" because `gruff-go init --force` rewrites the schema field while keeping rule tuning — without the parenthetical a user might fear losing their config and avoid the command.

**Audit sweep:** after a schema bump or vocabulary rename, run:

```
rg -nE 'fmt\.Errorf\("(unsupported|invalid|unknown) [^"]+ %q"' internal/ cmd/
```

Any match that does not also name the expected value and the remediation command is a stale error message. Apply the same rule to `errors.New("...")` callers, to validation-time errors that bubble up from YAML decoding, and to CLI flag-validation errors.

**Cost trade:** one extra `fmt.Errorf` argument and one sentence of prose, versus every future user re-deriving the fix from source.
