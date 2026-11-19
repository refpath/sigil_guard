---
sigil_guard:
  id: "R.11"
  topic: "Physical Tool Authority, Contextual Admission And Replay Boundaries"
  category: research
  status: complete
  created: "2026-11-19"
  updated: "2026-11-19"
  decision: adopted
  tags:
    ["physical-effect", "robotics", "replay", "confirmation", "toctou",
     "evidence", "dsse", "mcp"]
---

# R.11 — Physical tool authority, contextual admission and replay boundaries

**Revised:** 2026-11-19. **Status:** complete. **Decision:** adopted as the planned specification [SP.19](../specs/SP.19-physical-effect-authority.md), which is specified and not implemented. Branch baseline: `d57dc2b23ca9495bf896bb6bb705ea070f985cf1`. No physical-device security campaign or safety certification is claimed.

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

### 2.1 Second inspection for the specification

Before SP.19 was written, the modules behind confirmation, digests, the tool gateway and the replay store were read again and probed with throwaway scripts on Elixir 1.20.4 / OTP 29.0.4. A result marked "probe" was observed once on 2026-11-19 and is not asserted by a committed test.

- Every change to the arguments, the context actor, `mcp_server`, `resource_uri` or a value under an unreserved `params._meta` key makes confirmation verification return `:digest_mismatch`. The atom does not say which element changed. Committed tests cover payload, context, actor and manifest changes.
- The confirmation action digest covers the whole `SigilGuard.Context` struct, so it also changes with `context.metadata` and `workspace_root_digest`. The SP.01 attestation context digest excludes both (probe; matches SP.01).
- JCS writes `120` and `120.0` as the same bytes, so attestation payload and action digests are equal for the two. The confirmation digest distinguishes them (probe).
- A token consumed before `SigilGuard.Runtime` restarts verifies again after the restart until it expires. The replay table dies with its owner (probe).
- `ToolGateway.guard_request/3` verifies an inbound attestation without consuming its nonce. It forwards only `:now` and `:max_skew_ms` to `Attestation.verify/3`. The committed test "accepts valid inbound attestations for optional and required modes" guards one attested request twice and both pass.
- The runtime gate records `action_digest` in decision metadata only for a `confirm` verdict. A request allowed without confirmation carries none (probe).
- The library never evaluates arguments against a pinned `input_schema`. SP.16 leaves JSON Schema validation to the host.
- The boundary policy grammar has matchers for `tool` and `actor` and none for `mcp_server`, `resource_uri` or payload values. A rule listing tools under `default block` passed the listed tool and blocked an unlisted tool and another actor (probe).
- A binding record placed under `params._meta` is retained by `MCP.SecurityPayload`, changes the gateway payload digest, and produced no built-in scanner hit for one sample record containing SHA-256 digests (probe).
- The trust-bundle rollback floor and revocation union are per boot, like the replay table.

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

SP.19 adopts this note. It gives each requirement a stable `PE.` identifier and a status: met by current code with the module and test named, specified and not implemented, or a host obligation. It turns SG-F1 to SG-F6 into acceptance tests with inputs, expected decisions and falsifiers.

| Case | SP.19 section | Outcome of the expressiveness check |
|---|---|---|
| SG-F1 | Binding, Substitution Refusal | Principal, tool definition, parameters and endpoint are bound today. Target identity, artifact digests, frame revision, deadline and policy epoch have no field. They go into a closed record in the guarded payload, which the existing digests already cover. Naming the changed element needs a comparison with current host facts; a token carries digests only. |
| SG-F2 | Adaptive Envelope | Pinned manifests and `tool:`/`actor:` rules express a static set of operations. Task-scoped parameter bounds, a target set, a link from a program digest to its permitted set, and one approval for a set are not expressible. SP.19 defines a narrow envelope document for these and nothing else. |
| SG-F3 | Replay, Durable Effect Reconciliation | The replay store rejects reuse of one authority artifact within one runtime. It does not survive a restart or span nodes, and it says nothing about effects. The host ledger contract carries the effect identity. |
| SG-F4 | Time Of Check To Time Of Use | Token verification binds the presented request. Nothing checks conditions at dispatch. SP.19 adds a deny-only admission check with a required bound on fact age, and fixed rules for what a cancel may be recorded as. |
| SG-F5 | Evidence Honesty | Verification returns a statement, not an acceptance result. SP.19 defines separate authentication, claim and acceptance outputs. |
| SG-F6 | Untrusted Observations, Conformance Cases | Result scanning, untrusted-zone blocking, input budgets and closed parsing exist. The new inputs follow the same rules. |

The design keeps the preference stated in the first revision. No statement type, envelope format, token claim, manifest field or configuration key is added, and the library gains no durable store.

Remaining milestones, tracked as M13 in [`../tasks/sigil-tasks.md`](../tasks/sigil-tasks.md): characterization tests for the probed facts, the pure `EffectAuthority` module, the gateway option, the ledger fake with the conformance cases, and host guidance. Qualifying one real receiving boundary is separate work outside this repository. None of this requires a robotics product; a commercial product built on these controls is a separate decision.

No algorithm here decides a trajectory, controls an emergency stop or certifies machinery. The reusable capability is precise authority and evidence semantics at the boundary where an untrusted proposal can become an external effect.

## 8. Primary references and retained reading

Citation identity (title, authors, year, edition and catalogue, arXiv or regulation number) was rechecked for every reference below on 2026-11-19. The ISO catalogue and EUR-Lex pages refused automated retrieval and were confirmed through search records only. ISO 21423:2026 and ISO 10218-1:2025 are the current published editions. Section 9 records what was read of each source afterwards, and section 10 lists what that reading changed.

- **[P1]** CaP-X, proceedings/author project inspected: https://proceedings.mlr.press/v306/fu26u.html ; https://capgym.github.io/ . Motivation for program-producing agents, not evidence for SigilGuard security.
- **[P2]** *Coding Agents for Generalized Task and Motion Planning Problems*, arXiv:2609.30233, full-text simulated study inspected: https://arxiv.org/abs/2609.30233 .
- **[P3]** OpenVLA, arXiv:2406.09246, full-text policy study inspected: https://arxiv.org/html/2406.09246v3 .
- **[P4]** Black-Box Simplex, arXiv:2102.12981, primary record checked: https://arxiv.org/abs/2102.12981 . The paper's control-assurance problem is distinct from request authenticity.

Existing protocol reference points: JCS https://www.rfc-editor.org/rfc/rfc8785 ; DSSE https://github.com/secure-systems-lab/dsse ; in-toto https://github.com/in-toto/attestation . This revision does not claim a fresh cryptographic implementation audit.

Industrial scope references: WoT TD 1.1 https://www.w3.org/TR/2023/REC-wot-thing-description11-20231205/ ; ISO 21423:2026 https://www.iso.org/standard/86749.html ; ROS 2 DDS security https://github.com/ros2/design/blob/gh-pages/articles/180_ros2_dds_security.md ; VDA 5050 https://www.vda.de/en/news/publications/publication/vda-5050 . Protocol reachability is not permission.

Retained safety/risk review inputs, not conformity claims: ISO 10218-1 https://www.iso.org/standard/73933.html ; IEC 62443 https://syc-se.iec.ch/deliveries/cybersecurity-guidelines/security-standards-and-best-practices/iec-62443/ ; CRA https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847 ; NIST AI RMF https://www.nist.gov/itl/ai-risk-management-framework . Earlier benchmark/context references remain background only: https://ripl.github.io/manipulation_benchmark_audit/ ; https://arxiv.org/abs/2401.12202 .

## 9. Source reading record

Read on 2026-11-19 from the primary text unless noted. "Full" means the named document or page was read in full. Where only part was read, the part is named, and no claim in this note or in SP.19 rests on an unread clause.

### Attestation and canonical encoding

| Source | Version and extent read | What SP.19 takes from it |
|---|---|---|
| [DSSE](https://github.com/secure-systems-lab/dsse) | v1.0.2, 2024-05-10; `protocol.md` and `envelope.md` in full. The repository now resolves to `dsse-lf/dsse`. | The signature covers the PAE of the payload type and the exact payload bytes; the verifier passes on the bytes it verified; `keyid` is an unauthenticated hint. The text has no replay, freshness, nonce or expiry provision and puts key management out of scope. |
| [in-toto attestation](https://github.com/in-toto/attestation) | v1.2.0, 2026-03-18; `spec/v1` statement, resource descriptor, predicate and envelope in full | A Statement has four fields and none is an issuer, a time, an expiry or a nonce. Subjects are immutable artifacts matched by digest. A resource descriptor needs one of `uri`, `digest` or `content`. Consumers ignore unknown fields unless a predicate says otherwise. |
| [SLSA build provenance](https://slsa.dev/spec/v1.2/build-provenance) | v1.2; provenance page in full, verification page steps 1 and 2 | External parameters must be complete at Build L3 and verifiers should reject unrecognized ones. A parameter may be allowed a range of values when every value in the range is known to be safe. Provenance describes a build that already ran, not an authorization. |
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) | sections 1, 3 and 5, appendices B (part), D, E and F | Numbers are IEEE 754 doubles in ECMAScript form, so `120` and `120.0` are one value. Larger integers are carried as strings. Strings are not normalized. Section 5 requires data validation as well as signature verification. |

### Replay, freshness and effects

| Source | Version and extent read | What SP.19 takes from it |
|---|---|---|
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) | sections 4.2, 4.3, 8, 9 and 11 | The only requirement on replay is a limited acceptance time. Storing `jti` values is described with "can", is scoped to the target URI, and "may not always be feasible" when servers share no state. DPoP does not protect the request body (11.7). |
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | sections 2, 4.5, 4.10 and 4.14 | A resource server must refuse a token not meant for it (2.3). Sender-constraining and audience restriction are recommendations. |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | full | `resource` is an absolute URI without a fragment. The audience may be coarser than the resource, so it does not by itself identify one device. |
| [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) | July 2025; sections 3.2.5 to 3.2.8 and four glossary entries | Replay resistance rests on nonces or challenges that prove freshness. Authentication intent needs an explicit response to each request. Both are defined for authenticating a claimant, not for authorizing one action. |
| [RFC 8881](https://www.rfc-editor.org/rfc/rfc8881.html) | section 2.10.6 introduction and 2.10.6.5 | "true and complete EOS is not possible unless the server persists the reply cache in stable storage". This is the source for the restart limit. |
| [Gray, The Transaction Concept](https://jimgray.azurewebsites.net/papers/thetransactionconcept.pdf) | 1981; action categories and the passage on deferred real actions | An action on a real device cannot be undone. Such actions are named so that duplicates are discarded. |
| [Saltzer, Reed, Clark, End-to-End Arguments](https://web.mit.edu/Saltzer/www/publications/endtoend/endtoend.pdf) | 1984; the duplicate suppression section | Only the application can detect its own duplicate requests. |
| [Idempotency-Key header draft](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/) | draft 08, 2026-10-22, work in progress; sections 2, 3.1 and 5 | A key must not be reused with a different payload. The draft says nothing about durable storage or restart and is not cited for that. |
| RFC 9396, RFC 9421, draft-ietf-oauth-transaction-tokens-11 | selected sections | Read for comparison. No requirement rests on them. |

### Check, use and delegated authority

| Source | Version and extent read | What SP.19 takes from it |
|---|---|---|
| [Bishop and Dilger, Checking for Race Conditions in File Accesses](https://nob.cs.ucdavis.edu/bishop/papers/1996-compsys/racecond.pdf) | 1996; sections 1 and 3 and the closing section | The flaw needs an interval between check and use and an attacker able to change the checked assumption during it. The paper defines this for file access. |
| [CWE-367](https://cwe.mitre.org/data/definitions/367.html) | CWE 5.0, 2026-10-28; description and mitigations | Shortening the interval "will not fix the problem". Rechecking after use is a listed mitigation. |
| [Park and Sandhu, The UCON_ABC Usage Control Model](https://www.profsandhu.com/journals/tissec/ucon-abc.pdf) | 2004, author copy; abstract and passages of sections 3 and 4.2 | Authorization before use and authorization during use are different decisions. Revocation during use is the second. |
| [Hardy, The Confused Deputy](http://cap-lore.com/CapTheory/ConfusedDeputy.html) | 1988, author-hosted copy; full | A deputy holding authority from two sources cannot say which one an action uses. Designation and authority should travel together. |
| [CWE-441](https://cwe.mitre.org/data/definitions/441.html) | CWE 5.0; description, mitigations and notes | Renamed "Unintended Proxy or Intermediary" on 2026-10-28. |

### Model Context Protocol and agent guidance

| Source | Version and extent read | What SP.19 takes from it |
|---|---|---|
| [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28) | revision `2026-07-28`, marked current; repository commit `c5c0da7` of 2026-11-18. Tools (except two example blocks), cancellation, multi round-trip and authorization security pages in full; base protocol, authorization, elicitation and transports in part. The draft differs by two minor changes. | Tool annotations are hints and are untrusted unless the server is trusted. A human in the loop is a recommendation. Authorization is optional, defined for HTTP transports, and has no per-call clause in the pages read. A request `id` is unique only among outstanding requests and a retry uses a new one. There is no idempotency key. A cancellation can arrive after completion and a server may ignore it. Vendor-prefixed `_meta` keys are permitted. |
| [MCP tasks extension](https://github.com/modelcontextprotocol/ext-tasks) | v0.2.3; creation, cancellation and security sections | Cancellation is cooperative and does not guarantee that work stopped. |
| [OWASP LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) and [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | LLM01 description and mitigations; ASI01 and ASI02 | Natural-language input is untrusted. High-impact actions need confirmation by a person or a policy engine. |
| arXiv:2503.18813, arXiv:2506.08837 | abstracts and selected passages | Background on separating control flow from untrusted data. Already cited by SP.04. |

### Robot and device boundaries

| Source | Version and extent read | What SP.19 takes from it |
|---|---|---|
| [ROS 2 DDS-Security integration](https://design.ros2.org/articles/ros2_dds_security.html), access control policies and security enclaves | design articles 180, 181 and 182; full | ROS 2 uses the authentication, access control and cryptographic plugins. Identity is one certificate per enclave. Policy grants publish or subscribe on topics, request or reply on services, and call or execute on actions. The articles do not say that authority over one command's parameters is out of scope; SP.19 infers it from the rule vocabulary. |
| [OMG DDS-Security](https://www.omg.org/spec/DDS-SECURITY/1.1/PDF) | 1.1; sections 9.4.1.2 and 9.4.1.3. Version 1.2 of February 2026 was not read. | Permission rules match on domain, topic, partition and data tag. |
| [ROS 2 actions](https://design.ros2.org/articles/actions.html) and `action_msgs` | design article in part; `GoalInfo`, `CancelGoal` and `GoalStatus` in full | A goal has a client-generated UUID. Cancel is a request the server may reject. |
| [VDA 5050](https://github.com/VDA5050/VDA5050/blob/3.0.0/VDA5050_EN.md) | 3.0.0, GitHub release of 2026-03-18; GitHub text, sections 0 to 4, 6.1.1 to 6.1.4, 6.2, 6.6.5.4, 6.6.7 to 6.6.9 and 7.2 to 7.4. The VDA PDF, which prevails, was not read. | An order is identified by `orderId` and `orderUpdateId`. A lower update id is reported as `OUTDATED_ORDER_UPDATE`; the same id with other content as `SAME_ORDER_UPDATE_ID`. Actions carry an `actionId`. Cancelling is "considered unreliable". The header names the robot, not the sender. Security and safety are declared out of scope. |
| ISO 21423:2026 | ISO Open Data metadata record only; the catalogue page refused retrieval | Title "Robotics — Industrial mobile robots — Communications and interoperability", edition 1, published 2026-10-14, ISO/TC 299. The public scope says the document has no safety requirements. No clause was read. |
| [W3C WoT Thing Description 1.1](https://www.w3.org/TR/2023/REC-wot-thing-description11-20231205/) | Recommendation of 2023-12-05; sections 5.3.1.1, 5.3.1.4, 5.3.3, 6.3.4, 10 and 11 | A security scheme is metadata on how to access a Thing for a consumer that "already has authorization". `id` is optional and should be mutable, so it is a weak device anchor. `safe` and `idempotent` are declarations. No signing of the description is defined. |
| [OPC 10000-2](https://reference.opcfoundation.org/specs/OPC-10000-2) | release 1.05.06; selected sections | Application authentication sits in the communication layer and user authorization in the application layer. |

### Assurance and threat driver

| Source | Version and extent read | What SP.19 takes from it |
|---|---|---|
| [arXiv:2102.12981](https://arxiv.org/abs/2102.12981) | v3, "The Black-Box Simplex Architecture for Runtime Assurance of Autonomous CPS", NASA Formal Methods 2022; sections 1 to 2.2 | The baseline controller need not be verified in advance. Safety still depends on a correct decision module, a known system model and an initial safe command sequence. |
| [CaP-X](https://proceedings.mlr.press/v306/fu26u.html) | PMLR 306:32155-32212, 2026; abstract, sections 1 to 2.1 and part of 3 | Agents generate programs that compose perception and control primitives. The primitive set differs by benchmark tier. |
| [arXiv:2609.30233](https://arxiv.org/abs/2609.30233) | v1; abstract and selected passages | The generated program is frozen and acts as the per-step policy. Evaluation is in simulation. The coding agents ran in a sandboxed container without network access. |
| [arXiv:2406.09246](https://arxiv.org/abs/2406.09246) | v3; abstract and the action representation passages | The model predicts 7-dimensional actions, each dimension discretized into 256 bins. |
| [arXiv:2609.31110](https://arxiv.org/abs/2609.31110) | AuthGuard-R, 2026-09-25; abstract only | Closest related work: it binds each action to a signed mission, robot identity, scope, state, time and provenance beside an independent safety gate. It is a preprint with a preliminary evaluation and was not read in full. SP.19 claims no novelty over it. |
| arXiv:2410.13691, 2407.20242, 2506.03350, 2604.03890 | abstracts only | Threat context for language-driven robots. |

### Scope boundaries

No clause of a paywalled standard was read. These documents limit what SP.19 may claim and are not conformity targets.

| Source | Extent read | Use |
|---|---|---|
| ISO 10218-1:2025 and ISO 10218-2:2025 | ISO Open Data metadata records | Safety of industrial robots and robot applications belongs there. |
| IEC 62443 series | IEC overview page and webstore abstracts of 3-3:2013 and 4-2:2019 | Zones, conduits and security levels are the host's system design. |
| IEC 61508-1, ISO 13849-1:2023 | catalogue abstracts | Safety functions are designed under these, not here. |
| Regulation (EU) 2024/2847 | Articles 1 to 3(1), 14(1) to 14(2)(a) and 71 and recital 53, from the Publications Office copy | Applies from 11 December 2027; reporting under Article 14 from 11 September 2026. |
| Regulation (EU) 2023/1230 | Article 54 in the consolidated text of 2026-07-27 and Annex III sections 1.1.9 and 1.2.1 (part) | Applies from 20 January 2027. It requires protection of safety-relevant software and data against corruption. Not cited in the first revision. |
| NIST AI RMF 1.0 | web pages only | Voluntary framework of 2023-01-26. A revision is announced and none is published. |

## 10. What the reading changed

1. DSSE and the in-toto Statement give integrity and a typed payload and nothing about freshness, replay, target or deadline. Those bindings have to come from the profile. SP.19 puts them in the guarded payload so no envelope or statement type changes.
2. The replay guidance read here assumes shared state for single use and says so. RFC 8881 states the restart limit outright. SP.19 therefore states what the replay store cannot promise and puts effect identity in a durable host ledger.
3. MCP `2026-07-28` has no request-level idempotency and no confirmed cancellation, while VDA 5050 and ROS 2 actions do carry a command identity. SP.19 binds a host-assigned `operation_id` and requires the host to convey it where the target protocol can carry one.
4. SLSA requires external parameters to be complete, recommends rejecting unknown ones, and allows a range of values known to be safe. Envelope membership follows that model: every argument has a declared bound or the request is refused.
5. RFC 8785 number handling led to a binding record of strings and to integer-only bounds.
6. The second code inspection found that the gateway does not consume inbound attestation nonces and that only `confirm` decisions record an action digest. Both become requirements for physical-effect requests.
7. Corrections to earlier wording: the Black-Box Simplex guarantee is conditional as recorded in section 9; the ROS 2 articles support the transport-level description and not, by themselves, the statement about command parameters; Regulation (EU) 2023/1230 is a scope boundary alongside the Cyber Resilience Act; CWE-441 has a new name.
