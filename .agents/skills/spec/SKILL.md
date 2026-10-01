---
name: spec
description: Define or revise an implementation contract under docs/specs when a protocol/security design introduces new behavior or a task requires a specification. Turn decisions into observable acceptance, rejection, ownership, and compatibility rules.
---

# Spec

Input: the behavior to define, accepted design evidence, affected code/public
contracts, and unresolved decisions. Output: an implementable spec and applicable
task acceptance criteria, with unresolved choices stated explicitly.

Read the relevant research, existing spec, and affected APIs. Use the
[spec format](../../../docs/templates/spec-base.md) for a new spec in
[docs/specs](../../../docs/specs/); preserve the structure of an existing spec.
Define data flow, model, real module paths, error handling, security boundaries,
host responsibilities, and a testing/implementation plan to the extent relevant.

Specify observable accepted and rejected inputs, exact digest/signature binding,
state/time ownership, replay/expiry rules, and side-effect ordering for the
changed mechanism. Mark any intended future breaking change and map its consumer
impact. Examples must correspond to existing APIs or clearly proposed interfaces.

Use a diagram when cross-module flow benefits from one. Link primary sources and
affected research rather than copying unrelated material. Add/update
[task criteria](../../../docs/tasks/sigil-tasks.md) when the design creates work;
use the existing [task format](../../../docs/templates/task-base.md) as needed.
Do not mark designed or planned behavior as implemented or tested.
