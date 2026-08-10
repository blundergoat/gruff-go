# Git Commit Instructions

The commit-message standard for this repository is [`docs/coding-standards/git-commit-message.md`](../docs/coding-standards/git-commit-message.md). Follow it; this file adds no separate convention.

In short: conventional commits (`type(scope): subject` or `type: subject`), no ticket or branch prefix, name the concrete behaviour or surface rather than a weak subject such as "update things", and add a body when motivation or multi-axis scope is not obvious.

Keep commits scoped to the task. Do not commit `node_modules/`, local IDE metadata, Claude local settings, session scratch files, or unrelated user changes.
