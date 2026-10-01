---
name: debug
description: Diagnose a failing verification, policy, digest, replay/expiry, gateway, audit, vault, or package/documentation gate. Reduce the failure to its owning mechanism and retain regression proof; exclude planned features without a failure.
---

# Debug

Input: the observed failure, public input, expected result, and available error
or test output. Output: a minimal reproduction, owning fix where in scope, and
actual regression results or a specific blocker.

Capture the relevant phase/origin/sink/actor/trust zone, action/payload bytes and
digests, policy/bundle/key versions, time input, and returned verdict/error.
Sanitize secrets and private identifiers. Reduce the reproduction without
discarding the boundary condition that makes it fail.

Separate parsing/canonicalization, digest binding, identity/trust, policy,
replay-store state, clock/expiry, host callbacks, and compatibility as applicable.
For a gate failure, read the existing command and its owning configuration before
changing guidance or application code.

Fix the earliest faulty owner. Retain the rejection/acceptance contract instead
of adding broad rescues, weakening checks, or masking the failing test. Run the
regression and affected tests, then use
[quality guidance](../../standards/quality-gates.md) to determine further checks.
Report unrelated failures without expanding the task silently.
