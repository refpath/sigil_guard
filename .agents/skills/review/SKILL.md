---
name: review
description: Review changes for security, compatibility, test integrity, and documentation drift when review is requested or runtime security work reaches delivery. Trace reachable attack paths for affected trust boundaries; exclude routine prose cleanup.
---

# Review

Input: the diff or requested review scope, relevant specs, code paths, and test
results. Output: actionable findings with file/line, preconditions, impact,
evidence, and the smallest owning fix, plus remaining validation limits.

Read the implementation and callers behind changed behavior. Prioritize boundary
failures and compatibility regressions, then missing negative tests, quality
risks, and documentation drift. Inspect tests for assertions of behavior rather
than execution or inflated coverage. Apply
[AGENTS.md](../../../AGENTS.md) to architectural and project-policy questions.

For relevant paths, examine confused-deputy behavior, actor/origin/sink
substitution, trust-zone crossing, digest/payload mismatch, policy bypass,
confirmation reuse, replay/clock edges, malformed canonicalization, bundle/key
rollback, audit omission, and host callback ambiguity. Check reachability and
input bounds before claiming exploitability.

Compare public signatures, wire shapes, and errors with affected specs and
[consumer assertions](../../../test/sigil_guard/conformance/consumer_contracts_test.exs).
Check documented host responsibilities against implementation ownership. Follow
stateful runtime lifetimes rather than assuming every API is pure.

Report concrete defects and uncertainty separately. A suspicious writing style
does not establish provenance or a bug. If no issue is found, say so and state
what was actually reviewed/tested and what remains unverified.
