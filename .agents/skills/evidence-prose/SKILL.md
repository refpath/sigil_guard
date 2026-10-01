---
name: evidence-prose
description: Write or revise technical claims about security, cryptography, compatibility, tests, coverage, or completion in specs, public docs, comments, release notes, or handoff text. Keep terminology exact and claims bounded by observed evidence.
---

# Evidence Prose

Input: the text being written/edited, its intended reader, governing contract,
and available design/test/operational evidence. Output: precise prose that states
the mechanism, its scope, and material uncertainty.

Apply [naming guidance](../../standards/naming.md) when public terms change.
Identify the boundary, threat, mechanism, and failure behavior needed to support
the claim. Preserve commands, API identifiers, wire fields, error output, dates,
and measured numbers exactly.

Separate design reasoning, unit/property/tamper/replay tests, mutation/coverage
measurements, generic consumer proof, and live host evidence. Use the evidence
actually available; qualify missing verification and host assumptions. Attribute
external claims to a primary source where relevant.

Remove vague security assurances, repeated conclusions, generic filler, and
comments that restate code. Keep enough explanation to describe the contract;
do not enforce a prose blacklist or a compressed session mode. A review with no
findings does not establish security, and a passing test does not prove a broader
unexercised guarantee.
