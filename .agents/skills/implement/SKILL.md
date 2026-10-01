---
name: implement
description: Implement a bounded runtime or public API change involving verification, boundary policy, MCP gates, scanning, audit, vault, or trust material. Trace security impact and affected consumer contracts before editing; exclude prose-only maintenance.
---

# Implement

Input: the requested behavior and applicable spec/task, current modules, callers,
and tests. Output: the scoped implementation, regression evidence, and applicable
task/doc updates.

Read the relevant [spec](../../../docs/specs/) and affected callers/tests.
Identify the public inputs, outputs, errors, canonical bytes, and state ownership
that the change can affect. For a new protocol/security design, resolve its
design contract before broad implementation.

Trace the changed boundary through phase, origin, sink, actor/identity, trust
zone, action/payload digests, policy verdict, key/bundle lifetime, replay state,
audit evidence, and host callbacks. Follow only relevant paths; distinguish host
assumptions from guarantees enforced by the library.

Implement at the owning module. Prefer behaviours and plain data structs where
state is unnecessary; retain supervised OTP ownership where runtime security
depends on state lifetime. Test the changed mechanism through public APIs,
including relevant negative cases. Use existing
[consumer assertions](../../../test/sigil_guard/conformance/consumer_contracts_test.exs)
when public contracts are affected.

Update affected API docs/specs and existing [tasks](../../../docs/tasks/sigil-tasks.md)
when their behavior or status changes. Run focused tests first, then apply the
[quality guidance](../../standards/quality-gates.md) for the delivery stage.
