# R.11 — Physical tool authority, contextual admission and replay boundaries

**Revised:** 2026-11-14. **Status:** research and proposed conformance cases. Branch baseline: `d57dc2b23ca9495bf896bb6bb705ea070f985cf1`. No physical-device security campaign or safety certification is claimed.

## 1. Research objective

Determine whether the existing trust profile can authorize bounded physical work across changing programs, device configurations and observations without confusing four different properties:

1. authenticity and integrity of a request;
2. current authority to perform it;
3. prevention/reconciliation of repeated external effects;
4. physical safety and correctness of the result.

A sound answer is useful foundational security work without a separate robotics product. It does not require adding a robotics-specific signature scheme, motion model or network service to this library.

## 2. Inspected implementation and ownership

The branch's SP.01 defines the v3 trust profile; SP.04 owns boundary policy, SP.07 runtime gates, SP.08 confirmation, SP.09 audit and SP.13 agent-to-agent statements. Preserve existing canonicalization, digest and confirmation semantics before considering extensions.

`lib/sigil_guard/replay_store.ex` was inspected in this revision. It records hashed identity/nonce pairs with TTLs in a named ETS table, uses monotonic time and bounds live claims. This provides a process-runtime replay boundary. It does **not**, by itself, establish persistence across a node restart or a shared durable claim across independent nodes.

Consequently, a physical host must keep its durable operation identity and external-result reconciliation in the actual effect owner. A replay-cache pass after restart cannot be interpreted as evidence that a physical action has never happened. This is an ownership distinction, not a request to turn SigilGuard into a workflow database.

The library remains native Elixir. Hosts own transports, authentication, sandbox execution, durable storage and device access. The source review above is bounded; it is not a complete security audit of every caller or current main branch.

## 3. What robotics research changes about the trust question

Code-as-policy and generalized-program synthesis allow an agent to produce a program rather than one pre-enumerated action. [P1, P2] Learned policies may continuously generate bounded actions from observations. [P3] A trust boundary should therefore distinguish:

- approval of an immutable program or checkpoint;
- authorization of a bounded goal and operating envelope;
- admission of an individual effectful operation;
- controller enforcement of current state and physical limits.

Signing every generated motor sample is not a substitute for the other boundaries. Signing a program also does not authorize it to choose arbitrary devices, tools or goals. The host must expose only the admitted execution interface.

Runtime-assurance methods provide a different form of evidence about control behavior under explicit assumptions. [P4] The earlier report should not be read as claiming that cryptographic approval supplies those assumptions, or that Black-Box Simplex always requires a statically verified baseline controller.

## 4. Context binding without freezing the world

For a high-level physical operation, compare the existing context/manifest fields against the need to bind:

- principal/delegation and tenant or trust zone;
- target asset and endpoint identity;
- operation, exact parameters or approved bounded goal;
- program/policy artifact and relevant tool/controller configuration;
- frame, calibration or map revision when it changes parameter meaning;
- applicable policy/qualification epoch, time/freshness limits and confirmation;
- durable external-operation correlation supplied by the host.

These are a coverage checklist, not proposed additional fields in every statement. Existing context and manifest mechanisms may already express them.

A digest can identify the state reviewed at approval, but the physical world continues to change. The host needs a current precondition check immediately before dispatch, with a defined response to changed conditions. A human entering a workspace cannot be handled merely by hashing an earlier empty-workspace observation. Independent local protective functions remain necessary where required by the equipment.

A deliberately bounded adaptive policy needs different approval semantics from an exact one-shot command. Its allowed variation must be explicit and enforced outside the model. A changed goal, target or permitted envelope requires new authority; an ordinary observation update within an already approved policy need not automatically create a new human-signature ceremony.

## 5. Threat model and falsifiable controls

| Threat or ambiguity | Existing owner to test | Required result |
|---|---|---|
| Approved simulated target replaced by a physical target | SP.01 context/manifest and SP.04 boundary | Confirmation cannot survive target/authority substitution |
| Tool/calibration revision changes after review | Host current-condition check plus bound context | Re-evaluate or refuse according to declared validity; no silent reuse of obsolete interpretation |
| Generated program opens a different actuator endpoint | Host sandbox/transport policy plus library admission | Program signature cannot expand capabilities |
| Nonce replay within the same runtime | ReplayStore and receiving boundary | Duplicate claim denied within declared TTL/capacity behavior |
| Node restart or two hosts admit the same physical work | Host durable effect owner | Reconcile original external operation; ETS alone is not presented as a durable guarantee |
| Signed gateway claims success while observation disagrees | Independent result/inspection acceptance | Preserve the signed claim as a claim; do not promote it to physical truth |
| Authority revoked after dispatch | Host lifecycle and controller contract | New work refused; in-flight work follows defined safe transition/reconciliation |
| Offline site has stale trust material | Host freshness/clock policy and bundle protection | Explicit bounded behavior, not a hidden cloud dependency or silent trust extension |
| Telemetry/manual contains injected instructions | SP.04 source-to-sink policy and host input validation | Untrusted observation cannot grant authority or change the approved goal |

A valid signature proves which key endorsed bytes under a verification policy. It does not establish that the signer measured the world correctly, that its sensor is honest or that the action succeeded. Multiple independent observations may be needed for a particular acceptance criterion; the host owns that criterion.

## 6. Proposed neutral conformance corpus

Use synthetic names and a fake physical endpoint first. No private consumer names or internal modules belong in the public fixtures.

**SG-F1 — Bound identity.** Admit one exact request, then mutate target, frame/calibration revision, artifact digest, parameter, deadline and principal independently. Expected failures must name the violated boundary without exposing secrets.

**SG-F2 — Adaptive envelope.** Test a program that may choose among a finite set of permitted operations. An allowed choice succeeds; a new target or out-of-envelope parameter is refused. Compare existing manifest/context expressiveness before adding a new statement type.

**SG-F3 — Replay versus effects.** Exercise simultaneous nonce claims, expiration, capacity exhaustion and runtime restart. Pair this with a host fake durable-operation record. Demonstrate precisely which repetition the library rejects and which the host must reconcile.

**SG-F4 — Time-of-check/time-of-use.** Change authority or configuration after confirmation but before external I/O. The receiving host's current-condition decision must be observable. Repeat with an operation already accepted externally; do not falsely record cancellation as completion.

**SG-F5 — Evidence honesty.** Supply a valid signed success report with a contradictory independent observation, and an unsigned truthful report. Authentication and physical acceptance must produce distinct results; neither should silently substitute for the other.

**SG-F6 — Hostile input.** Keep existing bounds, canonical encoding and malformed/tampered-input tests. Include nested prompt injection in observation fields and attempted type/identifier confusion; no external network access or dynamic atom creation is justified by these fixtures.

The positive cases matter: a system that denies all requests does not demonstrate a usable security profile. Retain exact signed bytes, source identities, policy epochs and expected decisions. Do not use invented production keys or certification identifiers.

## 7. Research-to-specification disposition

First map SG-F1–F6 to existing SP.01/04/07/08/09/13 interfaces and host responsibilities. An independently reproduced gap or a supported new use case can justify a narrow amendment. Prefer existing context/manifest composition to another token or envelope format.

If a host needs durable replay/effect recovery, specify its integration boundary rather than quietly promising persistence from ETS. If a new adaptive-authority construct is necessary, define its semantics, deterministic refusal behavior and consumer assertions before implementation.

Technical milestones are: a neutral threat/fixture corpus; an existing-API expressiveness result; a library-plus-host contract test; and one separately qualified real receiving boundary. None requires a speculative robotics business. A commercial product built on those controls is a separate decision.

No algorithm here decides a trajectory, controls an emergency stop or certifies machinery. The important reusable capability is precise authority and evidence semantics at the boundary where an untrusted proposal can become an external effect.

## 8. Primary references and retained reading

- **[P1]** CaP-X, proceedings/author project inspected: https://proceedings.mlr.press/v306/fu26u.html ; https://capgym.github.io/ . Motivation for program-producing agents, not evidence for SigilGuard security.
- **[P2]** *Coding Agents for Generalized Task and Motion Planning Problems*, arXiv:2609.30233, full-text simulated study inspected: https://arxiv.org/abs/2609.30233 .
- **[P3]** OpenVLA, arXiv:2406.09246, full-text policy study inspected: https://arxiv.org/html/2406.09246v3 .
- **[P4]** Black-Box Simplex, arXiv:2102.12981, primary record checked: https://arxiv.org/abs/2102.12981 . The paper's control-assurance problem is distinct from request authenticity.

Existing protocol reference points: JCS https://www.rfc-editor.org/rfc/rfc8785 ; DSSE https://github.com/secure-systems-lab/dsse ; in-toto https://github.com/in-toto/attestation . This revision does not claim a fresh cryptographic implementation audit.

Industrial scope references: WoT TD 1.1 https://www.w3.org/TR/2023/REC-wot-thing-description11-20231205/ ; ISO 21423:2026 https://www.iso.org/standard/86749.html ; ROS 2 DDS security https://github.com/ros2/design/blob/gh-pages/articles/180_ros2_dds_security.md ; VDA 5050 https://www.vda.de/en/news/publications/publication/vda-5050 . Protocol reachability is not permission.

Retained safety/risk review inputs, not conformity claims: ISO 10218-1 https://www.iso.org/standard/73933.html ; IEC 62443 https://syc-se.iec.ch/deliveries/cybersecurity-guidelines/security-standards-and-best-practices/iec-62443/ ; CRA https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847 ; NIST AI RMF https://www.nist.gov/itl/ai-risk-management-framework . Earlier benchmark/context references remain background only: https://ripl.github.io/manipulation_benchmark_audit/ ; https://arxiv.org/abs/2401.12202 .
