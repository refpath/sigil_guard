---
sigil_guard:
  id: "R.12"
  topic: "Conformance Backlog Decisions: Trust Roots, Statement Content, Identifiers, Release Evidence, Telemetry"
  category: research
  status: complete
  created: "2026-11-20"
  updated: "2026-11-20"
  decision: adopted
  tags:
    ["tuf", "dsse", "in-toto", "spiffe", "did-key", "slsa", "sbom", "mcp",
     "opentelemetry", "conformance"]
---

# R.12 - Conformance Backlog Decisions

## Executive Summary

A read of SP.01 to SP.18 against the code found requirements the code did
not meet. Milestone M14 lists them. For each one the choice was to implement
the requirement or to change the spec. This note records the external facts
that decided the cases where a standard has something to say, and the
decisions that follow. Decisions that rest on repository rules alone are in
the Closed Decisions table of the task list (D23 to D45) and in the owning
specs.

The sources support these conclusions:

- A trust root is shipped out of band. TUF has no trust-on-first-use
  provision, so a bundle that arrives with a rotation chain and no pinned
  root cannot establish its own pin.
- TUF protects against rollback with client state and a monotonic version.
  It has no signed floor field. The `rollback_floor` of a bundle is a
  SigilGuard addition and its checks are SigilGuard's to define.
- DSSE verifies t of n signatures against trusted keys and forbids using
  `keyid` for a security decision. Which keys are trusted for which
  statement is the verifier's choice, so a bundle role for attestation
  issuers is consistent with it.
- in-toto requires consumers to ignore fields they do not recognize, and it
  fixes the timestamp format without fixing its precision. Adding predicate
  fields is compatible; one statement with two precisions is not forbidden
  but breaks string comparison.
- SPIFFE-ID and did:key have exact syntaxes that fit in a few clauses. They
  can be offered as helpers without making identifiers a closed type.
- An attestation proves something about a file only when the digest it is
  checked against comes from somewhere other than that file.
- OpenTelemetry has no stable MCP or agent conventions, advises against
  borrowing its namespaces, and requires high-cardinality attributes to be
  opt-in.

Material uncertainty: the MCP and OpenTelemetry generative-AI conventions
are in development and may define names that overlap `sigilguard.*`
attributes later. Nothing here depends on their current draft names.

## Research Question

Which of the unmet requirements in M14 are settled by a primary source, and
what does that source require of an embedded verifier that performs no
network calls and holds per-boot state only?

## Methodology

Sources were the current published text of each standard, read on
2026-11-20: the TUF specification, the in-toto attestation framework v1,
the DSSE protocol, the SPIFFE-ID standard, the did:key method and the W3C
Controlled Identifiers recommendation, SLSA v1.2, the GitHub CLI manual for
`gh attestation verify`, the CycloneDX 1.6 schema, the MCP `2026-07-28`
specification and the MCP Apps `2026-01-26` extension, and the
OpenTelemetry semantic conventions. Quotations are verbatim. A statement
marked as an inference is a conclusion drawn here and not text from a
source. Secondary commentary was not used.

## Context

SigilGuard verifies trust bundles, attestations, agent cards, and
confirmation tokens inside a host application. AGENTS.md fixes the frame:
core decision paths perform no HTTP, default trust material is embedded and
local, pure APIs acquire no hidden process, clock, network, or
configuration dependency, and the v3 consumer contracts are preserved. The
decisions below had to fit that frame as well as the standards.

## Findings

### TUF: trusted roots, rotation, and rollback

The specification assumes a root the client already holds: "We assume that
a good, trusted copy of this file was shipped with the package manager or
software updater using an out-of-band process." Section 2.1.1 requires that
a client "MUST ship with trusted root keys for each configured repository".
Bootstrapping is a stated non-goal: "We are not providing a means to
bootstrap security".

A new root must be signed twice over. Root N+1 "MUST have been signed by:
(1) a THRESHOLD of keys specified in the trusted root metadata file
(version N), and (2) a THRESHOLD of keys specified in the new root metadata
file being validated (version N+1)", and its version is exactly N+1. Only
the final root of a chain is checked for expiry: "the expiration of the new
(intermediate) root metadata file does not matter yet".

Rollback protection is client state plus a monotonic version: "The version
number of the trusted timestamp metadata file, if any, MUST be less than
the version number of the new timestamp metadata file." Root metadata has
no floor field. Its signed fields are `_type`, `spec_version`,
`consistent_snapshot`, `version`, `expires`, `keys`, and `roles`.

Takeaways. A first-seen bundle that carries a rotation chain needs a
genesis root supplied by the host; the chain cannot vouch for its own first
link. Checking sequence and floor inside `TrustBundle.verify/2` matches the
TUF rule that a verified document is compared with trusted state before it
is accepted. The per-boot cache is weaker than TUF's persistent state, and
SP.02 says so.

### DSSE: thresholds and key identifiers

"A (t, n)-ENVELOPE is valid if the enclosed signatures pass the
verification against at least t of n unique trusted public keys where t is
application-specific." On `keyid`: "It MUST NOT be used for security
decisions; it may only be used to narrow the selection of possible keys to
try." The protocol fixes the order: verify signatures, reject an
unsupported payload type, then parse the payload, and it forbids parsing
the envelope again after verification.

Takeaways. Trust in a key is decided by the verifier's key set, not by the
identifier in the envelope. A bundle delegate role named `attestation` that
lists issuer keys is a verifier-side key set in this sense, and it keeps
bundle signers, card issuers, and attestation issuers apart. A manifest's
`issuer_keyid` is a label under this rule and cannot authorize anything by
itself.

### in-toto: unknown fields and timestamps

"Consumers MUST ignore unrecognized fields unless otherwise noted in the
predicate specification." A policy is monotonic "if ignoring an
attestation, or a field within an attestation, will never turn a DENY
decision into an ALLOW." Timestamps: "A timestamp is represented as a
string and MUST be in RFC 3339 format in the UTC timezone ("Z")." Precision
is not specified. RFC 3339 section 5.1 notes that string ordering of
timestamps needs equal digit counts.

Takeaways. A statement may gain predicate fields (`nonce`, `matched_rules`,
`evidence`, `boundary`, `resource`) without breaking a conforming consumer.
None of the added fields can turn a denial into an allowance when ignored.
Writing every timestamp with three fractional digits keeps the two
timestamps of one statement comparable as strings.

### SPIFFE-ID and did:key syntax

A SPIFFE ID "MUST have the scheme set to `spiffe`, include a non-zero trust
domain name, and MUST NOT include a query or fragment component". The trust
domain "MUST contain only letters, numbers, dots, dashes, and underscores
([a-z0-9.-_])", is lowercase, has no userinfo or port, and is at most 255
bytes. Path segments "MUST contain only letters, numbers, dots, dashes, and
underscores ([a-zA-Z0-9.-_])", are not empty, are not `.` or `..`, and the
path has no trailing `/`. Implementations "MUST support SPIFFE URIs up to
2048 bytes in length".

A did:key identifier for Ed25519 is the multibase prefix `z` (base58btc)
over the multicodec header `0xed 0x01` and the 32-byte public key. The
Controlled Identifiers recommendation states that the value "MUST start
with the two-byte prefix 0xed01 (the varint expression of 0xed), followed
by the 32-byte public key data". That is 34 bytes, which encode to 48
characters starting `z6Mk` (computed here).

Takeaways. Both syntaxes are small enough to implement exactly.
`SigilGuard.Identity.spiffe_id?/1` and `did_key_public_key/1` do so. The
library still carries identifiers as opaque strings (R.05), because a host
may use identifiers of other schemes and nothing in a decision depends on
the scheme.

### SLSA, GitHub attestations, and SBOM digests

SLSA v1.2 on verification: "Verify that statement's subject matches the
digest of the artifact in question." `gh attestation verify` hashes the
file it is given, fetches attestations for that digest, and validates the
signature, the signer identity, and the predicate type. The CycloneDX
schema requires only `bomFormat` and `specVersion` and names no external
digest for the document. No source specifies comparing a file with a digest
computed from the same file.

Inference. A digest check proves that two things are equal. When both come
from one file in one step, the check cannot fail and proves nothing. The
value has to come from an earlier step or another party: the release
statement written before upload, or the signed attestation.

Takeaways. The consumer-side check of a release is `gh attestation verify`
for the tarball and the SBOM, which binds their bytes to the signed
statement. The structural SBOM check compares the document with a Mix
project and is a producer-side check, runnable by anyone in a checkout of
the released tag. The build job runs the structural check only; the digest
comparison happens in the attestation job against the release statement.

### MCP 2026-07-28 and MCP Apps

Authorization: "MCP servers **MUST** validate that access tokens were
issued specifically for them as the intended audience" and "The MCP server
**MUST NOT** pass through the token it received from the MCP client."
Request metadata lives in `params._meta` and result metadata in
`result._meta`; "Any prefix where the second label is
`modelcontextprotocol` or `mcp` is **reserved** for MCP use." Error codes:
"New error codes for purposes not defined by this specification **SHOULD**
be allocated outside the JSON-RPC reserved range (`-32768` to `-32000`)".

MCP Apps tool visibility is an array of `"model"` and `"app"`. "Host MUST
NOT include tools in the agent's tool list when their visibility does not
include `"model"`" and "Host MUST reject `tools/call` requests from apps for
tools that don't include `"app"` in visibility".

Takeaways. The passthrough check compares the token audience with the
resource and needs no manifest. An App-only tool is refused for a model
origin. The `-31990..-31984` codes stay outside the reserved range (D20).

### OpenTelemetry naming and cardinality

"It is not recommended to use existing OpenTelemetry semantic convention
namespace as a prefix for a new company- or application-specific attribute
name." "Metric attributes that may have high cardinality can only be
defined with `Opt-In` level." `error.type` is stable: it "SHOULD be
predictable, and SHOULD have low cardinality". The MCP and generative-AI
conventions are in development; none is stable. On hashed identifiers the
guidance is that "hashes are reversible in practice if the input space is
small and predictable".

Takeaways. The `sigilguard.*` namespace stays (D16). Digests, opaque ids,
and URIs are emitted only with `include_high_cardinality: true`. Actor and
identity are exported as keyed hashes (`SigilGuard.Audit.hash_field/2` with
the host's field-hash key), or as `redacted-v1` when the host supplies no
key, and never as plain digests, because the input space of actor ids is
small.

## Comparative Analysis

| Question | Option taken | Option rejected | Deciding fact |
|----------|--------------|-----------------|---------------|
| First-seen bundle with a rotation chain | Require a host-supplied genesis root | Pin the root the bundle names | TUF ships the trusted root out of band and provides no bootstrap. |
| Where rollback is checked | Inside `TrustBundle.verify/2`, read-only against the cache | Only when a bundle is cached | TUF compares each verified document with trusted state before accepting it. |
| Who may sign attestations for bundle-based verification | A delegate role named `attestation` | Any key in the bundle `keys` map | DSSE leaves the trusted key set to the verifier; one role per purpose keeps a bundle signer from signing statements. |
| New predicate fields | Add them | Version the profile | in-toto consumers ignore unrecognized fields, and ignoring these never turns a denial into an allowance. |
| Timestamp precision | Three fractional digits always | Clock precision as given | RFC 3339 string order needs equal digit counts. |
| Identifier validation | Optional helpers, opaque by default | Reject identifiers that are not SPIFFE or did:key | No decision depends on the scheme (R.05); hosts use other schemes. |
| SBOM digest in the build job | Structural check only | Compare with a digest of the same file | A value compared with itself proves nothing. |
| Decision correlation id | Host option | Minted by the gate | AGENTS.md: a pure API acquires no hidden random or clock dependency. |
| High-cardinality attributes | Opt-in | Always emitted | OpenTelemetry requires opt-in for them on metrics. |

## Recommendation

**Decision:** adopted.

**Rationale:** each choice follows the cited source where one applies and
the repository contract otherwise. The decisions are recorded as D23 to D45
in the task list and in the owning specs.

## Impact On SigilGuard

- Modules affected: `SigilGuard.TrustBundle` and its `Cache`, `Verify`, and
  `Issuers` modules; `SigilGuard.Attestation` and `Attestation.Digest`;
  `SigilGuard.AgentTrust`; `SigilGuard.Identity`; `SigilGuard.Telemetry`;
  `SigilGuard.ToolGateway`; the publish workflow.
- Specs updated: SP.01, SP.02, SP.03, SP.04, SP.05, SP.07, SP.08, SP.10,
  SP.13, SP.15.
- Migration needed: the gateway `action` digest of a `tool_request`
  attestation differs from the one releases up to 1.0.5 computed, so both
  sides of a gateway upgrade together. MIGRATING-1.0.md states it.
- Breaking changes: that digest; `quarantined` is `true` for more
  `agent_response` statements; `verify_agent_response/3` refuses a payload
  that is not a map.

## Sources

- [The Update Framework specification](https://theupdateframework.github.io/specification/latest/) - sections 2.1.1, 5.3 (update the root role), 5.4 to 5.6 (rollback checks).
- [in-toto attestation framework](https://github.com/in-toto/attestation) - `spec/v1`: README parsing rules, `statement.md`, `digest_set.md`, `field_types.md`.
- [DSSE protocol](https://github.com/secure-systems-lab/dsse) - `protocol.md`.
- [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) - section 5.1.
- [SPIFFE-ID standard](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md) - sections 2.1 to 2.4.
- [did:key method](https://w3c-ccg.github.io/did-key-spec/) and [Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/) - Ed25519 Multikey encoding.
- [SLSA v1.2, verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts).
- [GitHub CLI manual, `gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify).
- [CycloneDX specification](https://github.com/CycloneDX/specification) - `schema/bom-1.6.schema.json`.
- [MCP specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) - basic/authorization, basic/index (`_meta`, error codes).
- [MCP Apps extension](https://github.com/modelcontextprotocol/ext-apps) - `specification/2026-01-26/apps.mdx`.
- [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/) - general naming, attribute requirement levels, `error.type`, `user.hash`.
- [R.03](R.03-trust-bundle-role-model.md), [R.05](R.05-actor-identity-delegation-and-a2a.md), [R.07](R.07-runtime-dependencies-and-interoperability.md), [R.08](R.08-mcp-2026-07-28-and-apps-security.md) - earlier notes these decisions extend.
