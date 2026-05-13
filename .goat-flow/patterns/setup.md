---
category: setup
last_reviewed: 2026-05-13
---

# Setup Patterns

## Pattern: Verify bootstrap repos by absence as well as presence

**Created:** 2026-05-13

**Context:** This checkout has a project name and npm package metadata, but no application source files.

**Approach:** Before selecting commands or writing architecture claims, read `README.md`, `package.json`, `package-lock.json`, and `rg --files -g '!node_modules' -g '!dist' -g '!build' -g '!vendor'`. Run any detected script once if it appears to be a health gate, then record placeholder failures as setup gaps rather than working commands.
