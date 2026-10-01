---
name: security-tests
description: Add or assess behavioral proof when confirmation/nonce consumption, canonical digests, trust-bundle freshness, key rotation, parser bounds, or fail-closed decisions change. Exercise tamper, replay, expiry, and malformed cases for the affected mechanism.
---

# Security Tests

Input: the changed mechanism, expected acceptance/rejection contract, and existing
fixtures. Output: deterministic regression tests and their actual results.

Choose cases from the mechanism rather than applying a blanket matrix:

- Digest/attestation/manifest changes: alter action, payload, context, identity,
  origin, or sink independently; verify the expected mismatch through public APIs.
- Confirmation/replay changes: prove the original can succeed, the consumed
  token/nonce cannot succeed again, and concurrent claims admit only the intended
  winner. Distinguish consuming verification from stateless inspection.
- Bundle/key changes: check freshness boundaries, revocation, rotation, rollback,
  and quarantine using the relevant existing trust-bundle fixtures.
- Parser/boundary changes: test malformed containers, ambiguous canonical keys,
  bounded input, and the specified error/verdict without unintended effects.

Use explicit time/nonce inputs where supported, stable fixture bytes, and cleanup
for shared ETS/process state. Consult
[existing tests](../../../test/sigil_guard/) and
[fixtures](../../../test/fixtures/) only for the affected mechanism. Property
tests are useful for canonicalization/parser state spaces; do not replace
concrete negative assertions with coverage-only execution.

Run the affected tests and inspect assertions for the actual contract. Public
compatibility proof should exercise the generic
[consumer suite](../../../test/sigil_guard/conformance/consumer_contracts_test.exs).
Label fixture/unit/property evidence and unavailable live host evidence accurately.
