---
name: quality-gates
description: Select and execute validation before a commit, handoff, completion claim, or release-readiness assessment. Match existing checks to the changed surface and report actual passes, failures, skipped checks, and unavailable host evidence.
---

# Quality Gates

Input: the final diff, affected mechanisms, delivery stage, and existing results.
Output: validation results in chat with material gaps; no validation paperwork.

Read [quality guidance](../../standards/quality-gates.md) and select the affected
rows. For the complete application gate or failure diagnosis, inspect
[.check.exs](../../../.check.exs) and the relevant existing command. Do not repeat
checks already passed for unchanged files/mechanisms without a new reason.

Inspect selected entrypoints before running them: `bin/check` fetches locked
dependencies and the complete gate builds production packages and mutation
artifacts. Confirm available disk, prerequisites and ownership of outputs before
a heavy run; remove only outputs created for that run. Guidance-only changes use
existing metadata/reference checks and do not need bootstrap or compilation.
Keep the configured security, mutation, coverage and release gates intact.

Run selected checks using available tools. Inspect failures, fix those caused by
the change within scope, and rerun affected checks. Continue independent checks
when one is blocked. Review the final diff for unrelated edits and artifacts.

Report commands and actual outcomes. Do not turn a planned check, a clean text
search, a partial gate, or a declaration in a task file into test evidence.
Coverage, mutation, package, hosted CI, and live host claims each require their
own observed results. Bind reusable evidence to source/dependency, fixture,
configuration, environment and command; rerun invalidated proof. Each mandatory
binding or state invariant needs its actual assertion/result. A public guide
consumer pass establishes that caller boundary, not a live host's authentication,
durable storage or sandbox. State unavailable proof explicitly.
