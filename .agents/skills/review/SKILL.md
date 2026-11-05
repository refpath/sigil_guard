---
name: review
description: "Review changes, delivery or requested security audits for reachable security, compatibility, host-boundary, test-integrity and documentation defects. Trace affected verification and policy paths; exclude routine prose cleanup."
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


## Scoped security assessment

For an audit, trace the selected caller/origin/sink, manifest and action digest
through policy, confirmation/replay state and any host callback. Keep in-process
verification distinct from host authentication, durable storage and sandboxing.
Record revision/working-tree scope, checked paths and missing host evidence;
use security-tests for the mechanism's behavioral proof.

Establish each claim against the strongest current control and owning contract.
Confirmed findings need a complete reachable boundary trace and evidence for
the stated consequence. Keep decisive unobserved facts as `needs_validation`,
with the exact missing check and no severity; reject disproved claims.
Distinguish source inspection, inspected tests, executed local tests and live
evidence. Group duplicate root causes and recheck previous findings against
current source and conditions.

Use the existing validation owner for authorized dummy-data regressions.
Executing untrusted code or hostile native/availability checks requires verified
OS isolation, no external networking, a sanitized environment and resource/time
limits. If unavailable, leave that execution unverified and continue source
review. A review grants no live/provider operations or agent-permission changes.
Independent verification is conditional on authorized, available delegation;
otherwise state the single-reviewer limit. Return findings in chat unless the
requested deliverable and repository contract permit a report.

Audit-method background: [Cloudflare's source-first workflow](https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit).
