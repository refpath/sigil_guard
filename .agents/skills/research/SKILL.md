---
name: research
description: Resolve external facts for a protocol or security design decision involving MCP, canonicalization, trust bundles, audit evidence, identity, replay, or expiry. Use primary sources and compare options against the affected repository contracts.
---

# Research

Input: a specific unresolved question, affected spec/module, and decision
criteria. Output: cited facts, competing options, recommendation, and material
uncertainty in the requested destination.

Read only relevant repository design context. Prefer official specifications,
RFCs, upstream source, and primary security guidance such as MCP, W3C, OWASP,
TUF, SLSA, Sigstore, in-toto, and NIST. Verify evolving claims against current
sources; include relevant version/date and separate facts from inference.

Compare trust boundaries, failure behavior, compatibility, operational ownership,
and dependency cost. Explain which conclusions change the affected module/spec
and which remain host assumptions. Identify contradictory evidence and unresolved
questions instead of inventing a certainty score.

For an accepted protocol/security design, use the existing
[research format](../../../docs/templates/research-base.md) in
[docs/research](../../../docs/research/) and connect it to the relevant spec/task.
For fact checks or chat-only requests, return the evidence in chat without
creating a note. Research does not authorize implementation or external changes.
