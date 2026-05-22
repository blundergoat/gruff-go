---
category: workflow
last_reviewed: 2026-05-23
---

# Workflow Lessons

## Lesson: Check scanner config before agent-skill rubrics

**Created:** 2026-05-23

**Incident:** When asked to list security rubrics, the agent searched for `rubric` and returned the GOAT critique/security-assessment rubric from `.agents/skills/` instead of first checking the project scanner config. The relevant evidence was in `.gruff-go.yaml`, where `security.shell-command` and the `sensitive-data.*` rules were explicitly configured with severities.

**Do differently:** For questions about this repo's security rubrics, rule IDs, configured severities, or active scan policy, read `.gruff-go.yaml` and `docs/rules.md` before consulting agent skill files. Treat `.agents/skills/` as workflow guidance, not the scanner's configured rule source, unless the user explicitly asks about GOAT skills.
