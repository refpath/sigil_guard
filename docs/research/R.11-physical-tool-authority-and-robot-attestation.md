# R.11 — Physical tool authority, robot task attestation and industrial trust

**Status:** research, non-normative. **Inspected baseline:** `main@d57dc2b23ca9495bf896bb6bb705ea070f985cf1`, 2026-11-11. **Existing owners:** `SP.01` Agent Trust Profile (implemented v3 declarations); `SP.04` boundary policy; `SP.07` runtime gates; `SP.08` MCP confirmation; `SP.09` audit/anchor; `SP.10` identity/vault; `SP.13` A2A trust statements; `SP.14` interop; `SP.15` benchmarks; `R.06` agentic threat model.

## 1. Research objective and mandatory distinction

**RQ:** Can the existing deterministic policy, action/payload digests, DSSE/JCS statements, trust bundles, replay gates and confirmation contracts bind an AI agent's *high-level* request to one eligible physical operation and preserve verifiable evidence across compromised gateways, model substitution, disconnection and uncertain device outcomes?

SigilGuard is **not** a robot safety controller or a certification authority. Cryptographic authorization answers *who was permitted to request exactly what, on which boundary, under what policy*; it does not prove that a motion was physically safe or completed. The latter remains within manufacturer/site safety and independent measured evidence. The Black-Box Simplex research [P1] supports architectural separation, but its mathematical guarantees are specific to validated plant/safety models, not inherited by signing a tool call.

`SP.01` already binds action, payload, context, manifest digests with DSSE/JCS and in-toto-style statements. `SP.08` already defines confirmation/replay behavior. Do **not** create a second token, policy engine, signature envelope, privileged execution service or remote registry for robotics.

## 2. Distinct identities and trust zones

A physical request involves at least:
1. human/institution principal and delegated agent; session/tenant and authority revision;
2. *current* intended robot/site/Thing identity, controller identity and acceptable capability class;
3. exact operation revision, parameters and payload digest, operation time/deadline and effect ID;
4. approved machine envelope and independently enforced safety-policy owner;
5. transport/bridge identity (e.g. ROS 2 DDS participant, WoT Thing Form, VDA 5050 broker/robot), provider configuration and trust epoch;
6. resulting machine event, observation, inspection/review actor and evidence origin.

These need separate attestations. Never infer physical control from an authenticated model or a signed high-level request. Changing robot, site, coordinates, input, policy/manifest revision or beneficiary after confirmation invalidates the original action digest; use an explicitly approved successor.

A site gateway must verify **current** external/robot authority before forwarding even when SigilGuard admits a tool request. For offline modes, enforce finite signed authority/revocation-freshness limits; beyond permitted freshness, refuse new operations. Avoid relying on cloud availability or global clock assumptions in the core verifier.

## 3. Threats and candidate controls

| Threat | Candidate existing control / experiment | Required rejection |
|---|---|---|
| Agent changes target from simulated robot to production robot | SP.01 digests + SP.04 sink/policy binding + SP.08 confirmation | Target substitution cannot retain confirmation |
| Replayed approved task under network retry or gateway restart | SP.01/08 replay records, nonce and exact effect ID | Duplicate action admission denied / original outcome checked |
| Forged or misleading 'success' HTTP/ROS response | Different signed controller/inspection evidence owner | Signed request alone never qualifies completion |
| Cross-tenant robot access through shared broker | SP.04 actor/origin/sink and Orvane tenant scope | Other tenant capability refused |
| Action data differs from reviewed plan | JCS canonical payload hash and manifest revision | Modified trajectory/task rejected before I/O |
| Expired trust / revoked operator during long workflow | Current status check, bounded expiry and policy epoch | New effects denied; already-committed physical effect reconciled separately |
| Malicious ROS 2/Zenoh bridge or wrong DDS-Security config | Dedicated adapter identity and trust-zone/egress policy | No implicit trusted ROS graph based on network reachability |
| LLM prompt injection from robot telemetry or manuals | Source-to-sink scanner and domain-owner validation | Untrusted observation cannot grant tool authority |
| Physical E-stop request via VDA 5050 / MQTT misinterpreted as safety control | Explicit `operational_command` vs `safety_function` capability type | Product cannot claim compliant emergency-stop via a chat/transport tool |
| Compromised site link during offline operation | Machine-local policy, signed bundle freshness, no hidden remote trust | Deny unqualified new authority and preserve independent machine safety |

## 4. Candidate contract comparison — not new schema

Use the existing `SP.01` statement and `SP.08` confirmation structures before adding robotics fields. The required **comparison** attributes are: principal; delegation chain; tenant/site; asset and endpoint revision; operation class; command digest; fixed parameter bounds; model/tool provenance (informational, not authority); manifest hash; decision/policy version; expiration/freshness; effect correlation; actor confirmation; signed attestation identity; and separately verified result evidence. A native product capability, `Thing` and vendor robot command mapping belong to Orvane or the producer, not SigilGuard.

Adopt new policy or statement fields only when a minimal exploit succeeds against existing contracts and no existing context/manifest attribute can express the invariant. Protocol-adapter trust claims belong at the host integration seam; SigilGuard's deterministic engine must not perform ROS discovery, poll OPC UA, read cameras, open sockets or decide trajectories.

## 5. Reproducible adversarial corpus

| ID | Test | Pass |
|---|---|---|
| SG-RA-01 | Signed intention for robot A, mutate coordinates, robot ID, expiry or command revision | Existing signature/confirmation fails and diagnostic names changed field |
| SG-RA-02 | Simultaneous agents race to execute same physical effect; crash/restart/retry | Original effect identity retained; replay denied or external owner consulted |
| SG-RA-03 | Revocation after confirmation, before I/O; and during in-flight operation | New submission refused; in-flight effect marked unknown/observed, not auto-cancelled |
| SG-RA-04 | Forge signed gateway 'done' while independent robot sensor contradicts it | Tool attestation remains valid only as tool decision evidence; physical acceptance refused |
| SG-RA-05 | Cross-tenant broker, switched namespace, untrusted ROS participant | Policy/transport binding refuses at current authority boundary |
| SG-RA-06 | Offline token age/clock drift and rollback of trust bundle | Freshness and rollback rule enforced, no silent default trust |
| SG-RA-07 | Large/malformed/JCS-ambiguous payload and nested prompt injection | Deterministic rejection, bounded memory and no dynamic atom creation |
| SG-RA-08 | Compare old agent-tool trust flow with physical task flow | No second policy grammar or redundant attestation format is needed |

For each witness retain original signed bytes and key/manifest epochs, trust decision, independent device facts, denied/accepted effect IDs, runtime restart ordering and producer versions. Simulator and mocked gateway evidence are not physical-device certification.

## 6. Research-to-spec gates

- **SG-M0** — map SP.01/04/07/08/09/13/14 existing code and consumers to the physical threat matrix.
- **SG-M1** — create negative fixtures with a fake robot adapter; obtain failures independent of caller prompt.
- **SG-M2** — show cross-vendor physical operation binding and replay/expiry handling through existing extension seam.
- **SG-M3** — prove one verified unchanged action accepted, and each target/authority mutation refused on real host transport.
- **SG-M4** — propose **bounded amendments** to owning SP specs only for demonstrated representational gaps, preserving v3 statement formats unless an interoperable migration is justified.
- **SG-M5** — validate Orvane and Refpath consumers' custody of effect/result evidence; publish neutral conformance fixtures without naming private consumer modules.

**Stop:** relying on cryptography as machinery safety; embedding robot semantics in policy kernel; creating a generic physical-safety certificate; live network dependencies in core verifier; implementing new action tokens without invalidating attacks on old interface. This research does not alter the local-only release/push policy of the repository.

## 7. Primary reference register

- **[S1]** RFC 8785, *JSON Canonicalization Scheme* (JCS). https://www.rfc-editor.org/rfc/rfc8785.
- **[S2]** Dead Simple Signing Envelope (DSSE), reference specification. https://github.com/secure-systems-lab/dsse.
- **[S3]** in-toto Attestation Framework, statement and predicate specification. https://github.com/in-toto/attestation.
- **[S4]** ROS 2, DDS security integration. https://github.com/ros2/design/blob/gh-pages/articles/180_ros2_dds_security.md.
- **[S5]** W3C WoT Thing Description 1.1, security metadata and affordances. https://www.w3.org/TR/wot-thing-description/.
- **[S6]** VDA 5050 v3.0.0 (2026), official document. https://www.vda.de/en/news/publications/publication/vda-5050.
- **[S7]** IEC 62443, industrial network zones and security lifecycle. https://syc-se.iec.ch/deliveries/cybersecurity-guidelines/security-standards-and-best-practices/iec-62443/.
- **[S8]** ISO 10218-1:2025 industrial robot safety. https://www.iso.org/standard/73933.html.
- **[S9]** EU Cyber Resilience Act (EU) 2024/2847. https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847.
- **[S10]** NIST AI Risk Management Framework 1.0 (2023), voluntary general risk practice. https://www.nist.gov/itl/ai-risk-management-framework.
- **[P1]** *The Black-Box Simplex Architecture for Runtime Assurance of Autonomous Cyber-Physical Systems* (2021), arXiv:2102.12981. https://arxiv.org/abs/2102.12981.
- **[P2]** Jiang et al., *What Are We Actually Benchmarking in Robot Manipulation?* (2026), arXiv:2606.04233. https://arxiv.org/abs/2606.04233 — unreliable benchmark proxy warning.
- **[P3]** *OK-Robot* (2024), arXiv:2401.12202. https://arxiv.org/abs/2401.12202 — real-robot system error accumulation.

**Limitations:** no independent industrial safety audit, no real robot cohort or threat campaign is claimed. Standard names alone do not establish conformance or legal status.
