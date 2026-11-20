---
sigil_guard:
  id: "SP.01"
  title: "Agent Trust Profile"
  domain: security
  status: implemented
  priority: critical
  created: "2026-07-01"
  updated: "2026-11-20"
  tags: ["agent-trust", "attestation", "dsse", "jcs", "v3", "breaking-change"]
  depends_on: ["R.01", "R.02", "R.05", "R.06", "R.07"]
---

# SP.01 - Agent Trust Profile

## Overview

SigilGuard v3 is a breaking release built around a SigilGuard-owned Agent Trust
Profile: DSSE-enveloped, JCS-canonical, in-toto-style statements signed over
action, payload, context, and manifest digests. Every other v3 spec references
this one. It fixes the envelope and canonical encoding (R.02), the statement
type registry, the exact digest field lists per statement type, the
golden-vector fixtures, the public API sketches, the final v3 configuration
surface, the profile-wide error taxonomy, the replay and expiry defaults, and
the Envelope-to-Attestation migration mapping. The old upstream protocol remains
historical input only.

## V3 Position

| Area | V2/Foundation | V3 End State |
|------|---------------|--------------|
| Public protocol center | SIGIL compatibility idiom | Agent Trust Profile |
| Wire metadata | `_sigil`, `_sigil_confirmation` | `_agent_trust`, `_agent_confirmation` |
| Canonical encoding | Ad hoc compact JSON, embedded signature | DSSE envelope + JCS payload + in-toto Statement |
| Remote discovery | Registry-named compatibility modules | No remote trust by default |
| Tool trust | Optional pattern bundle data | Signed capability manifests |
| Signing | Envelope verdict signing | Typed attestations over action/payload/context/manifest digests |
| Scanning | Regex/staged scanner | Boundary-aware source-to-sink policy pipeline |
| Audit | HMAC chain/checkpoint foundation | Signed evidence exports with Merkle roots |
| Configuration | Open key set, registry/backend keys | Validated closed key set, fail-closed at boot |
| Migration | Runtime compatibility | `MIGRATING-1.0.md` field-by-field mapping |

## Technical Architecture

### Profile Layers

1. **Trust material:** local signed bundles with roots, delegated keys,
   revocations, sequence numbers, and expiry (SP.02).
2. **Capability material:** signed tool manifests with schemas, descriptions,
   annotations, side effects, scopes, and sandbox identity (SP.03).
3. **Runtime binding:** canonical action, payload, context, and manifest
   digests over normalized boundary vocabulary (this spec).
4. **Decision kernel:** deterministic allow/block/confirm/redact/quarantine
   verdicts with matched-rule explanations (SP.04, SP.07).
5. **Evidence:** signed attestations, audit events, checkpoints, exports,
   and optional external anchors (SP.05).

### Data Flow

```mermaid
sequenceDiagram
    participant Host
    participant Bundle as TrustBundle
    participant Gate as Runtime Gate
    participant Attest as Attestation
    participant JCS as Canonical.JCS
    participant Audit

    Host->>Bundle: load local trust bundle
    Bundle-->>Host: roots, manifests, policies, patterns
    Host->>Gate: payload + boundary context
    Gate-->>Host: decision (allow/block/confirm/redact/quarantine)
    Host->>Attest: from_decision(decision, context, payload: payload)
    Attest->>JCS: normalized statement preimages
    JCS-->>Attest: canonical bytes + digests
    Attest->>Attest: PAE + Ed25519 sign (DSSE envelope)
    Attest->>Audit: evidence refs
    Attest-->>Host: envelope attached as `_agent_trust`
```

### Architectural Patterns

| Pattern | Used | Justification |
|---------|------|---------------|
| GenServer | no | Sign/verify are pure functions; no process state. |
| Behaviour | yes | `SigilGuard.Signer` supplies Ed25519 signing. |
| ETS | yes | `SigilGuard.ReplayStore` (`:sigil_guard_replay`) for replay scope. |
| Telemetry | no at this primitive | Direct sign/verify stay pure; the host-facing Agent Trust helpers own operational spans in SP.13. |

## Attestation Envelope And Canonical Encoding

This section is normative. Its constants are defined once in R.02 and copied
here exactly; SP.02, SP.05, and SP.13 reference this section instead of
restating it. Every externally signed v3 artifact - runtime attestation,
trust bundle, audit checkpoint, audit export - MUST be a DSSE envelope
wrapping a JCS-canonical Statement, verified through one shared code path.

### DSSE Envelope

| Field | Type | Content |
|-------|------|---------|
| `payload` | string | base64url (no padding) of the serialized Statement bytes. |
| `payloadType` | string | Exactly `application/vnd.sigilguard+json`. |
| `signatures` | list | One or more `{"keyid": string, "sig": string}` maps. |

- Emission MUST use base64url without padding for `payload` and `sig`;
  parsing tolerates both base64 alphabets, per the DSSE specification.
- Envelopes containing duplicate `keyid` values in `signatures` MUST be
  rejected with `{:error, :duplicate_keyid}`.
- `keyid` is an unauthenticated hint; verifiers MUST resolve keys through
  trust material (never by trusting the `keyid` itself). SigilGuard emits
  `keyid` as `"sha256:" <> hex`, the lowercase-hex SHA-256 of the raw
  32-byte Ed25519 public key. This is a deliberate SigilGuard-local
  convention chosen for simplicity; it is NOT an ecosystem standard and
  differs from TUF, which computes keyids over the canonical-JSON encoding
  of the key object. Because a `keyid` is only a hint, this divergence never
  affects verification — a bundle's key set is authoritative.
- Signatures are Ed25519 via OTP `:crypto` over the PAE bytes below (RFC
  8032 EdDSA; a fixed 32-byte seed yields deterministic signatures, which is
  what makes the golden vectors reproducible). Role thresholds (m-of-n) over
  the `signatures` array are owned by SP.02.

### Pre-Authentication Encoding (PAE)

The signature is never computed over the payload directly and never over the
envelope JSON. It is computed over:

```
PAE(type, body) = "DSSEv1" SP len(type) SP type SP len(body) SP body
```

where `SP` is a single space (0x20) and `len(...)` is the ASCII decimal byte
count of the following field. For SigilGuard's payload type (31 bytes) and an
illustrative 7-byte body `{"x":1}`:

```
DSSEv1 31 application/vnd.sigilguard+json 7 {"x":1}
```

Verifiers MUST base64url-decode `payload`, build PAE from the received
bytes, and verify signatures over those exact bytes. Verifiers MUST NOT
re-serialize or re-canonicalize the payload before signature verification.
The envelope itself MAY be re-serialized in transit.

### Statement Shape

The payload is an in-toto-style Statement:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "action", "digest": {"sha256": "<lowercase-hex-64>"}},
    {"name": "payload", "digest": {"sha256": "<lowercase-hex-64>"}},
    {"name": "context", "digest": {"sha256": "<lowercase-hex-64>"}},
    {"name": "manifest", "digest": {"sha256": "<lowercase-hex-64>"}}
  ],
  "predicateType": "https://sigilguard.dev/attestation/<statement-type>/v1",
  "predicate": {"profile": "sigil_guard_agent_trust/v1", "...": "..."}
}
```

- `_type` MUST be exactly `https://in-toto.io/Statement/v1`.
- `subject` MUST contain exactly `action`, `payload`, and `context` in that
  order, then `manifest` when a manifest digest applies (see Digest
  Computation). No other names are permitted. The digest algorithm key MUST
  be exactly `sha256` with a lowercase-hex 64-character value. Violations
  fail with `{:error, :invalid_profile}`.
- `predicateType` MUST be a registered URI from the Statement Type Registry;
  unknown URIs fail with `{:error, :unknown_statement_type}`, as does a
  `predicate.statement_type` that differs from the `predicateType` segment.
- `predicate.profile` MUST be exactly `sigil_guard_agent_trust/v1`. A
  matching stem with another version fails with
  `{:error, :unsupported_profile_version}`; anything else with
  `{:error, :invalid_profile}`.

Interoperability note: SigilGuard's `subject` entries are LOGICAL digests
(action/payload/context/manifest), not file artifacts. This is permitted by
the in-toto Statement spec, which leaves subject-name semantics to the
producer and consumer, but generic in-toto or cosign tooling that assumes
file/artifact subjects may not interpret these names. A verifier MUST be
SigilGuard-profile-aware (keyed off `predicateType` under
`https://sigilguard.dev/`) before evaluating a SigilGuard attestation; the
DSSE envelope and Ed25519 signature remain verifiable by any DSSE-conformant
tool regardless.

### JCS Constraints (Normative)

Payloads are canonicalized at emission with RFC 8785 (JCS). JCS provides
determinism at emission; DSSE provides integrity at verification, so
signature validity never depends on JCS correctness. Rules for the
`SigilGuard.Canonical.JCS` implementer:

- **Integer range.** Integers outside `[-(2^53 - 1), 2^53 - 1]` MUST be
  carried as JSON strings. The encoder MUST return
  `{:error, :unsupported_number_range}` for integers outside that range
  instead of emitting a lossy double. Schema fields that can grow (sequence
  numbers, sizes, counters) MUST be defined as strings.
- **Key ordering is by UTF-16 code units**, not code points and not UTF-8
  bytes. Converting each key with
  `:unicode.characters_to_binary(key, :utf8, {:utf16, :big})` and comparing
  byte-wise is correct. For ASCII-only keys this equals byte order.
- **No Unicode normalization.** The encoder MUST NOT apply NFC/NFD to keys
  or values; NFC/NFD twin keys are distinct properties and MAY coexist.
- **Number serialization** follows ECMA-262 `Number::toString`: shortest
  round-trip form, `1.0` emits `1`, `-0` emits `0`, exponent form `e+`/`e-`
  starting at `1e+21`.
- **Non-finite numbers are rejected.** BEAM floats are always finite, so the
  Elixir encoder cannot receive `NaN`/`Infinity`; ports of this profile MUST
  reject them with `{:error, :unsupported_number_range}`, never `null`.
- **String escaping is minimal** per RFC 8785: `\"`, `\\`, the control
  shorthands, remaining controls below U+0020 as lowercase `\uXXXX`; all
  other characters emit literally as UTF-8.
- **Decode-side strictness.** Parsing uses the configured JSON library
  (`jason` by default; the stdlib `JSON` module is an acceptable
  alternative); decoders MUST reject duplicate object keys and malformed
  UTF-8.

## Statement Type Registry

The registry is a closed set; verifiers dispatch on `predicateType` with a
closed map. The profile id is `sigil_guard_agent_trust/v1`.

| Statement type | `predicateType` URI | Purpose | Predicate owner |
|----------------|---------------------|---------|-----------------|
| `tool_request` | `https://sigilguard.dev/attestation/tool_request/v1` | Guard a tool/MCP invocation before it executes. | SP.03 |
| `tool_result` | `https://sigilguard.dev/attestation/tool_result/v1` | Guard tool output before it re-enters host or model context. | SP.03 |
| `model_ingress` | `https://sigilguard.dev/attestation/model_ingress/v1` | Guard content entering model context (user input, memory, resources). | SP.04 |
| `model_egress` | `https://sigilguard.dev/attestation/model_egress/v1` | Guard model output leaving toward a sink. | SP.04 |
| `repo_change` | `https://sigilguard.dev/attestation/repo_change/v1` | Guard repository mutations under repo policy. | SP.11 |
| `release` | `https://sigilguard.dev/attestation/release/v1` | Bind release artifacts, SBOM, and provenance to a verdict. | SP.05 |
| `agent_request` | `https://sigilguard.dev/attestation/agent_request/v1` | Guard an outbound agent-to-agent request. | SP.13 |
| `agent_response` | `https://sigilguard.dev/attestation/agent_response/v1` | Guard an inbound agent-to-agent response. | SP.13 |

Two more predicate type URIs are reserved outside this registry:
`https://sigilguard.dev/trust-bundle-state/v1`, owned by SP.02, and
`https://sigilguard.dev/audit-checkpoint-state/v1`, owned by SP.05.
`SigilGuard.TrustProfile` lists neither, so `Attestation.sign/3` and
`Attestation.verify/3` reject a Statement that uses them. The
checkpoint-state Statement is built by `SigilGuard.Audit.Checkpoint` and
signed through `Attestation.Envelope` (SP.05). The trust-bundle-state
Statement was dropped from the design and nothing builds one (SP.02). SP.01
owns the Statement layer, the
digest rules, and this registry; predicate owners define full predicate
schemas without changing the digest inputs below.

## Data Model

### Agent Trust Predicate (Core Fields)

The four digests are carried in the Statement `subject`, not the predicate.
Predicate boundary/actor/tool fields are informational mirrors for human and
audit consumption; the DSSE signature covers the whole Statement, so mirrors
cannot be tampered after signing. `from_decision/3` fills the fields it
emits from the same normalized context that feeds the digests. `sign/3`
signs the predicate it receives and does not compare a mirror with the
digest inputs.

The table lists the profile's predicate fields. The Checked column names the
function that rejects a missing or malformed field. `TrustProfile.validate/1`
runs inside `sign/3`, `from_decision/3`, and `verify/3`, and of these fields
it checks `profile`, `statement_type`, `actor.id`, `verdict`, `issued_at`,
and `expires_at`. The Emitted column states when `from_decision/3` writes
the field. A field that `from_decision/3` does not write reaches a statement
only when the host adds it to the statement map before `sign/3`.

| Field | Type | Checked | Emitted by `from_decision/3` | Description |
|-------|------|---------|------------------------------|-------------|
| `profile` | string | `validate/1` | always | Exactly `sigil_guard_agent_trust/v1`. |
| `statement_type` | string | `validate/1` | always | Equals the `predicateType` type segment. |
| `actor` | map | `validate/1` (`actor.id` only, a non-empty string) | always | `{"id": string, "trust_level": string}`. SPIFFE-shaped ids recommended, opaque strings accepted (R.05). `trust_level` is `context.trust_level`. |
| `tool` | map | no | `tool_request` only | `{"name": string, "mcp_server": string, "manifest_digest": string}` from `context.tool`, `context.mcp_server`, and the `:manifest_digest` option; keys omitted when absent, the map omitted when empty. |
| `resource` | map | no | `tool_request`; agent statements with `:audience` | `{"uri": string, "audience": string, "scope": string}`. `uri` is the `:resource` option, else `context.resource_uri`; `audience` is the `:audience` option, else `context.intended_audience`; `scope` is the `:scopes` option, a list being sorted and joined with single spaces. Keys omitted when absent. An `agent_request` or `agent_response` statement gets `{"audience": string}` when the caller passes `:audience`, which then must be a non-empty string (`:invalid_audience`); it names the recipient the statement is addressed to (SP.13). |
| `boundary` | map | no | always | Mirror of context digest fields: `phase`, `origin`, `sink`, `trust_zone`, `intended_audience`, and `source`, `sandbox_id`, `isolation_level` when present. `from_decision/3` takes the values from the context digest preimage, so the mirror states what the `context` subject binds. The identity fields of that preimage (`actor`, `identity`, `tool`, `mcp_server`, `resource_uri`, `trust_level`) are not in the mirror; `actor`, `tool`, and `resource` carry them. |
| `verdict` | string | `validate/1` (a non-empty string; the value is not compared with the enum) | always | `allow`, `block`, `confirm`, or `quarantine`. The SP.07 enum also has `redact`; `from_decision/3` writes `allow` for a redact decision and records the redaction in `action`. |
| `action` | string | no | always | The decision `action`: `allow`, `redact`, `confirm`, `quarantine`, or `block`. |
| `risk_level` | string | no | always | The decision `risk_level`. |
| `reason` | string | no | when the decision has a `reason` | The decision `reason`. |
| `matched_rules` | list | no | when `decision.matched_rules` is not empty | `[{"id": string, "explanation": string}]`; MAY be empty. `from_decision/3` copies `decision.matched_rules`: `rule_id` is written as `id`, a `nil` explanation as `""`, and an entry whose `rule_id` is not a string is left out. The `tool_request` golden vector carries one entry. |
| `nonce` | string | `verify/3` with `replay: true` | always, unless the `:nonce` option is `false` or `nil` | Profile format: 16 random bytes, lowercase hex (32 characters). `from_decision/3` generates a value in that format from `:crypto.strong_rand_bytes/1` when the caller passes no `:nonce`. A string passed as `:nonce` is written as given, in any format. |
| `issued_at` | string | `validate/1` | always | ISO 8601 UTC. The profile format has millisecond precision, e.g. `2026-07-02T12:00:00.000Z`; see the precision note below. |
| `expires_at` | string | `validate/1` | always | Same format; MUST be later than `issued_at`, else `validate/1` returns `{:error, :invalid_payload}`, in `sign/3` and `from_decision/3` as in `verify/3`. |
| `evidence` | list | `from_decision/3` (`:invalid_evidence`) | with the `:evidence` option, else when `decision.evidence_refs` is not empty | Audit references `[{"kind": "checkpoint" \| "export" \| "anchor", "ref": string}]`. The option wins over `decision.evidence_refs`. Whichever list is written passes `SigilGuard.Audit.Evidence.validate/1` first. |

`tool_result` statements also get the SP.03 fields `request_action_digest`,
`quarantine` (`status` and `indicator_ids`, with built-in atom ids written as
strings), `scanner` (`hit_count`, `redacted`), and `output_schema_sha256`
when that option is given. `agent_request`/`agent_response` predicates extend
this core with SP.13-owned fields (delegation chain, peer trust) without
removing or retyping any core field.

Precision note. `from_decision/3` sets the clock value to millisecond
precision, also when the caller passes `:now`: finer digits are cut off and
a coarser value is padded. It writes `issued_at` as `DateTime.to_iso8601/1`
of that value and `expires_at` as that time plus the TTL in milliseconds, so
both timestamps have three fractional digits: `now: ~U[2026-07-02 12:00:00Z]`
gives `2026-07-02T12:00:00.000Z` and `now: ~U[2026-07-02 12:00:00.123999Z]`
gives `2026-07-02T12:00:00.123Z`. With no `:now` option the clock is
`DateTime.utc_now/0`. `sign/3` treats a `DateTime` passed as `:now` the same
way and writes a string passed as `:now` as given. `validate/1` and
`verify/3` accept any ISO 8601 timestamp with an offset.

A statement without a `nonce` verifies with `replay: false` and fails
`verify/3` with `replay: true` (`{:error, :invalid_payload}`). A statement
from `from_decision/3` carries a generated nonce and can be consumed once,
unless the caller passed `nonce: false` or `nonce: nil`. `sign/3` generates
no nonce. It writes its `:nonce` option when the value is a string and
otherwise leaves the predicate as it is, so one option list can be passed to
both functions.

## Digest Computation (Normative)

This section fixes exactly which bytes each digest covers. All digests are
lowercase-hex SHA-256. Except for the binary payload class below, every
digest is computed over the JCS-canonical bytes of a normalized preimage map.

### Normalization Rules

1. Atom keys and atom values (except `true`, `false`, `nil`) convert to
   strings via `Atom.to_string/1`. Booleans stay JSON booleans.
2. Absent or `nil`-valued optional context fields are omitted from the
   preimage, never emitted as `null`. A missing or `nil` required field
   fails with `{:error, :invalid_payload}`. A payload is stricter: a map
   entry whose value is `nil`, at any depth of a map or list payload, fails
   with `{:error, :invalid_payload}`, because omitting it would make `null`
   equal to absence (SP.18). `nil` list elements are kept as JSON `null`.
   The fixed nullable fields of the `SigilGuard.MCP.SecurityPayload`
   projection and gate wrapper (SP.03) are exempt; the application payload
   inside them is not.
3. A key collision after normalization (an atom key and a string key
   normalizing to the same string) makes the JCS encoder return
   `{:error, :invalid_map}`, surfaced by `SigilGuard.Attestation` as
   `{:error, :invalid_payload}`; `:unsupported_number_range` passes through.
4. `action_digest` and `context_digest` preimages include a
   `statement_type` key as a domain separator, so identical content under
   two statement types can never produce colliding digests.
5. Payload key lookup happens after normalization, by string key only.

### Metadata Strip Rule

Before any digest computation and before action-argument extraction, the
following six keys MUST be removed from (a) the payload top level and (b)
the map under the payload's `params` key when present:

`:_agent_trust`, `"_agent_trust"`, `:_agent_confirmation`,
`"_agent_confirmation"`, `:confirmation_token`, `"confirmation_token"`

This mirrors the v2 gateway's `_sigil`/`_sigil_confirmation`/
`confirmation_token` strip. Deeper nesting (for example inside
`params.arguments`) is user content and is never stripped. A digest computed
with and without attached metadata MUST be identical.

### Context Digest (All Statement Types)

The `context_digest` preimage is the same field list for all eight types,
sourced from the normalized `SigilGuard.Context`:

| Preimage key | Source | Presence |
|--------------|--------|----------|
| `statement_type` | statement type being attested | required |
| `actor` | `context.actor` | omitted when `nil` |
| `identity` | `context.identity` | omitted when `nil` |
| `trust_level` | `context.trust_level` | required (defaults `:low`) |
| `phase` | `context.phase` | required |
| `origin` | `context.origin` | required |
| `source` | `context.source` | omitted when `nil` |
| `sink` | `context.sink` | required |
| `trust_zone` | `context.trust_zone` | required |
| `mcp_server` | `context.mcp_server` | omitted when `nil` |
| `tool` | `context.tool` | omitted when `nil` |
| `resource_uri` | `context.resource_uri` | omitted when `nil` |
| `intended_audience` | `context.intended_audience` | required |
| `sandbox_id` | `context.sandbox_id` (v3 field, SP.04) | omitted when `nil` |
| `isolation_level` | `context.isolation_level` (v3 closed enum, SP.04) | omitted when `nil` |

Sandbox identity is normatively part of the context digest: an attestation
or approval bound to one sandbox can never be replayed against another
(R.06 rows 11 and 21). An omitted `isolation_level` is byte-distinct from
`"none"`; SP.04 policy treats both as untrusted. Two context fields are
normatively excluded: `action` (bound through `action_digest`) and
`metadata` (host-private, unbounded, non-canonical; hosts that need metadata
bound into evidence MUST place it in the payload). The effect binding
of [SP.19](SP.19-physical-effect-authority.md) follows this rule.

### Payload Digest (All Statement Types)

`payload_digest` binds the full guarded payload. Input classes are
disambiguated by the JSON data model (string, object, and array are
mutually distinguishable), so no class prefix is needed:

| Payload class | Digest input |
|---------------|--------------|
| map | strip rule, the `nil`-entry check of normalization rule 2, then normalization, then JCS bytes |
| UTF-8 binary | the raw bytes of the binary, hashed directly (no JCS) |
| list | each map element gets the strip rule at its top level, then the `nil`-entry check, normalization, and JCS bytes of the list |
| any other term (tuples, pids, non-UTF-8 binaries, functions) | `{:error, :invalid_payload}` |

`SigilGuard.Attestation.Digest.payload_digest/1` accepts all three classes.
The action digest narrows them. For every statement type except
`model_ingress` and `model_egress` it reads the payload as a map, so
`from_decision/3`, `Digest.digests/4`, and digest recomputation in
`verify/3` accept a binary or list payload only for those two types and
return `{:error, :invalid_payload}` for the other six. `from_decision/3`
returns the same error for a `:payload` that is not a map, a binary, or a
list.

### Action Digest (Per Statement Type)

The `action_digest` preimage captures intent. Every preimage contains
`statement_type` plus the fields below. Fields marked `r` are required;
unmarked fields are omitted when absent. `arguments` values receive the
strip rule at their top level.

| Statement type | Preimage fields beyond `statement_type` |
|----------------|------------------------------------------|
| `tool_request` | `tool` (`context.tool`, else payload `params.name`, else payload `name`; r), `method` (payload `method`), `arguments` (payload `params.arguments`, else payload `arguments`) |
| `tool_result` | `tool` (`context.tool`; r), `method` (payload `method`), `request_action_digest` (opts `:request_action_digest`, lowercase-hex-64; r; the SP.03 gateway MUST set it) |
| `model_ingress` | `origin` (`context.origin`; r), `source` (`context.source`), `resource_uri` (`context.resource_uri`) |
| `model_egress` | `sink` (`context.sink`; r), `intended_audience` (`context.intended_audience`; r), `resource_uri` (`context.resource_uri`) |
| `repo_change` | `repository` (payload `repository`; r), `ref` (payload `ref`), `operation` (payload `operation`; r), `paths` (payload `paths`, list of strings sorted ascending by raw byte comparison; r, MAY be empty) |
| `release` | `package` (payload `package`; r), `version` (payload `version`; r), `artifacts` (payload `artifacts` as `{"name", "sha256"}` maps sorted ascending by `name` byte comparison; r, MUST be non-empty) |
| `agent_request` | `peer_agent` (payload `peer_agent`; r), `capability` (payload `capability`; r), `arguments` (payload `arguments`) |
| `agent_response` | `peer_agent` (payload `peer_agent`; r), `capability` (payload `capability`; r), `request_action_digest` (opts `:request_action_digest`, lowercase-hex-64; r; the SP.13 flow MUST set it) |

A missing required field fails with `{:error, :invalid_payload}`; there is
no fallback default action name in v3.

For `tool_request` and `tool_result` the preimage reads through the gate
payload that the SP.03 gateways digest. That payload wraps the MCP message:
its keys are `action`, `tool`, `text`, and `binding`, and `binding` is the
projection `{"kind", "method", "protocol_version", "payload"}`. The gateway
writes `null` for a `tool`, `action`, `method`, or `protocol_version` it
does not have, and normalization drops null members, so the payload is
recognized after normalization: a map that has `text` and `binding`, has no
key outside the four, and whose `binding` has `kind` `request` or `result`,
a `payload`, and no key outside the projection. Such a map is replaced by
the message it stands for, in JSON-RPC shape. For a request that is
`{"method": binding.method, "params": binding.payload}`; for a result it is
an empty map, because the result preimage reads nothing from the message.
The fields in the table are then read from that message. A gateway-built
statement therefore has the same action preimage as the raw MCP message:
for `tool_request`, `statement_type`, `tool`, `method`, and `arguments`. Two
calls to one tool with different arguments have different action digests.
Any other map is read as given. The golden vectors digest raw messages and
their bytes are unchanged.

The message is rebuilt and not read in place because a params object may
hold members of any name. Read in place, a member named `params` would be
taken for the message's `params` and its `arguments` would replace the real
ones in the digest, and a result member named `method` would be taken for
the JSON-RPC method.

### Manifest Digest (Applicability)

| Statement type | `manifest_digest` |
|----------------|-------------------|
| `tool_request`, `tool_result` | Capability-manifest digest; the manifest field list is owned by SP.03 and hashed as JCS bytes of its normalized canonical form. |
| `agent_request`, `agent_response` | Agent-card digest; field list owned by SP.13. |
| `model_ingress`, `model_egress`, `repo_change`, `release` | Not applicable; the `manifest` subject entry is omitted. |

The digest is the `:manifest_digest` option when given, else the digest of
the `:manifest` option. When a manifest applies but neither option is given,
the subject entry is omitted; whether that is acceptable for a phase is an
SP.04 policy decision (quarantine default for untrusted origins). For the
four types in the last row both options are ignored.

`verify/3` compares the manifest entry only when it recomputes digests (both
`:payload` and `:context` given). A statement that carries a `manifest`
subject while the caller supplies neither option fails with
`{:error, :unknown_manifest}`. A different digest, or a caller-supplied
manifest against a statement without the subject, fails with
`{:error, :manifest_digest_mismatch}`. Action/payload/context mismatches
fail with `{:error, :digest_mismatch}`. Switch options such as
`:require_manifest` and `:replay` are booleans; another value, `nil`
included, is read as the strict setting (on for a requirement, off for a
relaxation). Without `require_manifest: true` a
statement that has no `manifest` subject verifies when the caller supplies no
manifest. With it, the statement MUST carry a `manifest` subject equal to the
digest of the supplied `:manifest` or `:manifest_digest`, whether or not the
other digests are recomputed: a missing subject, missing or malformed
manifest material, fails with `{:error, :unknown_manifest}`, and a different
digest with `{:error, :manifest_digest_mismatch}`. `SigilGuard.ToolGateway`
has its own `:require_manifest` option for manifest resolution (SP.03).

## Canonical Example And Golden Vectors

One complete worked `tool_request` attestation. Fixed test vector inputs:

- Ed25519 seed: the 32 bytes `0x01, 0x02, ..., 0x20`, i.e. hex
  `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`.
- `issued_at` `2026-07-02T12:00:00.000Z`; `expires_at` +300 s, i.e.
  `2026-07-02T12:05:00.000Z`; nonce `000102030405060708090a0b0c0d0e0f`;
  `keyid` per the `"sha256:" <> hex` convention above.

Every `<computed: ...>` value below is produced at fixture-generation time
and stored under `test/fixtures/agent_trust/`; the surrounding JSON
structure is exact and normative. Examples are pretty-printed with keys
already in JCS order (all keys are ASCII, so JCS order equals byte order);
fixtures store the compact, whitespace-free form.

Guarded payload (an MCP `tools/call` writing a repo file):

```json
{
  "id": 42,
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "arguments": {"content": "## 1.0.0\n", "path": "docs/CHANGELOG.md"},
    "name": "repo_file_write"
  }
}
```

Context digest preimage (normalized context; `resource_uri` is `nil` and
therefore omitted):

```json
{
  "actor": "spiffe://prod.example.org/agents/release-bot",
  "identity": "spiffe://prod.example.org/agents/release-bot",
  "intended_audience": "internal", "isolation_level": "container",
  "mcp_server": "repo-mcp", "origin": "user", "phase": "tool_request",
  "sandbox_id": "sbx-9c2e4d10", "sink": "repo", "source": "session-7f3acb12",
  "statement_type": "tool_request", "tool": "repo_file_write",
  "trust_level": "medium", "trust_zone": "semi_trusted"
}
```

Action digest preimage:

```json
{
  "arguments": {"content": "## 1.0.0\n", "path": "docs/CHANGELOG.md"},
  "method": "tools/call",
  "statement_type": "tool_request",
  "tool": "repo_file_write"
}
```

Decoded Statement (the DSSE payload before base64url encoding). The
`manifest` digest is the digest of the SP.03 `repo_file_write`
capability-manifest fixture. The fixture generator assembles this predicate
directly; `from_decision/3` output differs as the Agent Trust Predicate
table states:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicate": {
    "actor": {"id": "spiffe://prod.example.org/agents/release-bot", "trust_level": "medium"},
    "boundary": {
      "intended_audience": "internal", "isolation_level": "container",
      "origin": "user", "phase": "tool_request", "sandbox_id": "sbx-9c2e4d10",
      "sink": "repo", "source": "session-7f3acb12", "trust_zone": "semi_trusted"
    },
    "expires_at": "2026-07-02T12:05:00.000Z",
    "issued_at": "2026-07-02T12:00:00.000Z",
    "matched_rules": [
      {"explanation": "repo write within approved path set", "id": "repo.write.allow"}
    ],
    "nonce": "000102030405060708090a0b0c0d0e0f",
    "profile": "sigil_guard_agent_trust/v1",
    "statement_type": "tool_request",
    "tool": {
      "manifest_digest": "<computed: manifest_digest>",
      "mcp_server": "repo-mcp", "name": "repo_file_write"
    },
    "verdict": "allow"
  },
  "predicateType": "https://sigilguard.dev/attestation/tool_request/v1",
  "subject": [
    {"digest": {"sha256": "<computed: action_digest>"}, "name": "action"},
    {"digest": {"sha256": "<computed: payload_digest>"}, "name": "payload"},
    {"digest": {"sha256": "<computed: context_digest>"}, "name": "context"},
    {"digest": {"sha256": "<computed: manifest_digest>"}, "name": "manifest"}
  ]
}
```

DSSE envelope around it:

```json
{
  "payload": "<computed: base64url of the compact JCS Statement bytes>",
  "payloadType": "application/vnd.sigilguard+json",
  "signatures": [
    {"keyid": "<computed: sha256:...>", "sig": "<computed: base64url Ed25519 over PAE>"}
  ]
}
```

### Fixture File Set

Each statement type gets one directory; `tool_request` is the worked vector
above and the remaining seven are generated mechanically from the same rules
in milestone M1:

```
test/fixtures/agent_trust/<statement_type>/
  statement.json   # the exact compact JCS payload bytes
  envelope.json    # the DSSE envelope, compact, keys in JCS order
  expected.json    # inputs and expected values (below)
```

`expected.json` fields: `inputs` (source payload, context map, and sign opts
including seed hex, timestamps, nonce), `public_key_hex`, `keyid`,
`action_digest`, `payload_digest`, `context_digest`, `manifest_digest`
(when applicable), `statement_sha256` (SHA-256 of `statement.json` bytes),
`pae_sha256` (SHA-256 of the PAE bytes), and `signature` (base64url). DSSE
does not require envelope canonicalization, but `envelope.json` is stored
compact in JCS key order so fixtures are byte-stable. The generator MUST be
deterministic: regenerating MUST produce byte-identical files. Committed
fixtures are a frozen contract; changing their bytes requires a new
`predicateType` version.

## Public API Sketch

Return-type unions name every error atom; the atoms are defined in the
Error Handling taxonomy below.

```elixir
defmodule SigilGuard.TrustProfile do
  @type statement_type ::
          :tool_request | :tool_result | :model_ingress | :model_egress
          | :repo_change | :release | :agent_request | :agent_response

  @type validate_error ::
          :invalid_profile | :unsupported_profile_version
          | :unknown_statement_type | :invalid_payload

  @spec profile_id() :: String.t()
  # "sigil_guard_agent_trust/v1"

  @spec statement_types() :: [statement_type()]
  # Fixed order: [:tool_request, :tool_result, :model_ingress,
  #  :model_egress, :repo_change, :release, :agent_request, :agent_response]

  @spec predicate_type(statement_type()) ::
          {:ok, String.t()} | {:error, :unknown_statement_type}

  @spec validate(map()) :: {:ok, statement :: map()} | {:error, validate_error()}
  # Structural validation of a decoded Statement: _type, subject names and
  # order, predicateType registry membership, predicate.profile,
  # predicate.statement_type, the core fields below, and for
  # agent_request/agent_response the SP.13 extension fields. Core fields:
  # actor.id and verdict are non-empty strings, issued_at and expires_at
  # are ISO 8601 timestamps with an offset, and issued_at is strictly
  # before expires_at; anything else is :invalid_payload. No other
  # predicate field is checked, and nonce may be absent.
end
```

```elixir
defmodule SigilGuard.Attestation do
  @type sign_error ::
          :invalid_profile | :unsupported_profile_version
          | :unknown_statement_type | :invalid_payload
          | :unsupported_number_range | :invalid_signer | :invalid_envelope

  @type verify_error ::
          :invalid_envelope | :invalid_payload_type | :invalid_base64
          | :duplicate_keyid | :missing_trust_bundle | :unknown_key_id
          | :untrusted_issuer
          | :invalid_signature | :pae_mismatch | :invalid_profile
          | :unsupported_profile_version | :unknown_statement_type
          | :invalid_payload | :digest_mismatch | :manifest_digest_mismatch
          | :unknown_manifest | :expired_attestation | :replay_detected
          | :replay_capacity_exceeded

  @type from_decision_error ::
          :unknown_statement_type | :invalid_payload | :invalid_context
          | :invalid_phase | :invalid_sink | :invalid_origin
          | :invalid_trust_level | :invalid_trust_zone | :invalid_audience
          | :invalid_isolation_level | :invalid_network_posture
          | :invalid_metadata | :invalid_evidence

  @spec sign(statement :: map(), signer :: module(), opts :: keyword()) ::
          {:ok, envelope :: map()} | {:error, sign_error()}
  # signer implements SigilGuard.Signer. opts: :keyid (defaults to the
  # derived "sha256:<hex>" form); :now overwrites predicate.issued_at and
  # :nonce overwrites predicate.nonce, for deterministic tests; :ttl_ms.
  # A DateTime :now is written with millisecond precision, a string :now
  # as given. :nonce is written when it is a string. A statement that then has
  # issued_at and no expires_at gets expires_at = issued_at + ttl, from
  # :ttl_ms, else :attestation_ttl_ms, else 300_000 ms; a stated
  # expires_at is kept. sign/3 then runs TrustProfile.validate/1 and no
  # other check, so a statement without actor.id or verdict, or whose
  # issued_at is not before its expires_at, returns :invalid_payload and
  # is not signed. :invalid_envelope is returned when the envelope would
  # exceed the SigilGuard.Limits input budget.

  @spec verify(
          envelope :: map(),
          trust_material ::
            %{optional(String.t()) => binary()} | SigilGuard.TrustBundle.t(),
          opts :: keyword()
        ) :: {:ok, statement :: map()} | {:error, verify_error()}
  # trust_material maps keyid to a raw 32-byte or base64/base64url Ed25519
  # public key, or is a verified TrustBundle whose "attestation" delegate
  # role names the signing keys (SP.02). opts: :payload and :context (both
  # needed for any digest recomputation), :manifest or :manifest_digest,
  # :require_manifest (default false), :request_action_digest,
  # :max_skew_ms, :replay (default false; :consume is an alias),
  # :replay_ttl_ms, :expected_payload_sha256, :now.

  @spec from_decision(
          SigilGuard.Decision.t(),
          SigilGuard.Context.t() | map() | keyword(),
          opts :: keyword()
        ) :: {:ok, statement :: map()} | {:error, from_decision_error()}
  # opts: :payload (required; a map, or for model_ingress and
  # model_egress also a binary or a list), :statement_type (required for
  # :release, :agent_request, :agent_response), :ttl_ms, :now (written
  # with millisecond precision), :nonce (a string; generated when the
  # option is absent, omitted for false or nil), :request_action_digest,
  # :manifest, :manifest_digest, :evidence (else decision.evidence_refs;
  # both are shape-checked).
  # tool_request also reads :resource, :audience, :scopes. tool_result also
  # reads :output_schema_sha256, :quarantine_status, :indicator_ids,
  # :scanner_hit_count, :redacted (SP.03). The agent types also read
  # :peer_trust, :card_digest, :quarantined (SP.13). The emitted fields are
  # listed under Agent Trust Predicate.

  @spec attach(payload :: map(), envelope :: map()) :: map()
  # Puts the envelope under "_agent_trust". Raises ArgumentError on non-maps.

  @spec fetch(payload :: map()) :: {:ok, envelope :: map()} | :error
  # Reads "_agent_trust" (atom or string key); :error when absent/not a map.

  @spec attach_confirmation(payload :: map(), token :: String.t()) :: map()
  # Puts the confirmation token under "_agent_confirmation".

  @spec fetch_confirmation(payload :: map()) :: {:ok, String.t()} | :error
end
```

```elixir
defmodule SigilGuard.Canonical.JCS do
  @spec encode(term()) ::
          {:ok, binary()} | {:error, :unsupported_number_range | :invalid_map}
  # :invalid_map covers non-JSON-representable terms (tuples, pids,
  # references, functions), non-string-convertible keys, and key collisions
  # after atom-to-string normalization.
end
```

`from_decision/3` derives the statement type from `context.phase` with a
closed map: `:inbound_user -> :model_ingress`, `:tool_request ->
:tool_request`, `:tool_result -> :tool_result`, `:outbound_model ->
:model_egress`, `:repo_change -> :repo_change`. The types `:release`,
`:agent_request`, and `:agent_response` have no phase and require an
explicit `:statement_type` option, which always wins when provided.
`predicate.actor.id` is `context.actor`, falling back to
`context.identity`; both absent fails with `{:error, :invalid_payload}`.

Verification order is normative: trust-material shape, envelope structure,
`payloadType`, signature-entry shape, duplicate-keyid check, base64 decode
of `payload`, `:expected_payload_sha256` check, then for each signature in
envelope order keyid resolution, base64 decode of its `sig`, and Ed25519
over PAE, then Statement parse, `TrustProfile.validate/1`, digest
recomputation from opts, freshness, replay. Trust material that is not a
non-empty map fails first with `:missing_trust_bundle`. At least one
envelope `keyid` MUST resolve in the trust material (else
`:unknown_key_id`); every signature whose keyid resolves MUST verify (any
resolved-but-invalid signature fails with `:invalid_signature`); unresolved
keyids are tolerated to support witness cosigning (R.02), and their `sig`
values are not decoded. Role thresholds are owned by SP.02.

Trust material is a keyid-to-public-key map or a verified
`%SigilGuard.TrustBundle{}`. With a bundle, the signing keys are the keys of
its delegate role named `"attestation"`, less every key the bundle or the
cache lists as revoked. A key signs only what its role covers, so the root
keys, the `"bundle"` keys and the `"agent_card"` keys do not sign
attestations, and a bundle without the role authorizes none. `verify/3`
then fails with `{:error, :untrusted_issuer}` when a signature comes from a
revoked key or from a key the bundle holds for another role, when fewer
distinct `"attestation"` keys signed than the role's `threshold`, or when
the role, the bundle document or the root role is past `expires_at` (`:now`,
`:max_skew_ms`). A `:now` that is not a `DateTime` or a `:max_skew_ms` that
is not a non-negative integer fails with `{:error, :invalid_payload}` before
the issuer check, with a bundle as with a key map. A signature from a key the bundle does not hold is
`{:error, :unknown_key_id}`. If a newer snapshot of the same `bundle_id` is
cached, its document is the one consulted.

Digest recomputation runs only when both `:payload` and `:context` are
given. With one or neither, `verify/3` checks the signatures, the Statement
shape, freshness, and replay, and compares no digest.

## Public API Surface

### New Public Modules

| Module | Purpose |
|--------|---------|
| `SigilGuard.TrustProfile` | Profile id, statement type registry, statement validation. |
| `SigilGuard.TrustBundle` | Load, validate, verify, inspect, and cache local bundles (SP.02). |
| `SigilGuard.CapabilityManifest` | Canonical tool/agent capability manifests (SP.03). |
| `SigilGuard.Attestation` | DSSE sign, verify, `from_decision`, `_agent_*` metadata helpers. |
| `SigilGuard.Canonical.JCS` | RFC 8785 encoder with the adversarial corpus. |
| `SigilGuard.Boundary` | Normalize source/sink/phase/actor/tool context (SP.04). |
| `SigilGuard.BoundaryPolicy` | Deterministic source-to-sink policy decisions (SP.04). |

### Public Modules Removed In V3

Removal mechanics and sequencing are owned by SP.12; the replacements are
fixed here. All removals are deletions, not hidden shims; `MIGRATING-1.0.md`
carries the 1:1 mapping.

| Current Surface | V3 Action |
|-----------------|-----------|
| `SigilGuard.Registry` | Deleted; replaced by `SigilGuard.TrustBundle` (SP.02). |
| `SigilGuard.Registry.Bundle` | Deleted; provenance checks move into `TrustBundle` verification (SP.02). |
| `SigilGuard.Registry.Cache` | Deleted; replaced by `TrustBundle.Cache` (SP.02). |
| `SigilGuard.Profile` | Deleted; replaced by `SigilGuard.TrustProfile`. |
| `SigilGuard.Envelope` | Deleted; replaced by `SigilGuard.Attestation` (mapping table in Migration). |
| Legacy config keys | Removed per the V3 Configuration Surface tables below. |

### Module Map

| Path | Purpose |
|------|---------|
| `lib/sigil_guard/trust_profile.ex` | Registry constants and statement validation. |
| `lib/sigil_guard/attestation.ex` | Public sign/verify/from_decision/attach/fetch. |
| `lib/sigil_guard/attestation/envelope.ex` | DSSE envelope encode/decode and PAE. |
| `lib/sigil_guard/attestation/statement.ex` | Statement build/parse and subject rules. |
| `lib/sigil_guard/attestation/digest.ex` | Normalization, strip rule, digest computation. |
| `lib/sigil_guard/canonical/jcs.ex` | RFC 8785 encoder. |
| `lib/sigil_guard/config.ex` | Closed key set validation, `SigilGuard.ConfigError`. |
| `test/sigil_guard/trust_profile_test.exs` | Registry and validation tests. |
| `test/sigil_guard/attestation_test.exs` | Sign/verify, tamper, replay, expiry tests. |
| `test/sigil_guard/canonical/jcs_test.exs` | RFC 8785 appendix and adversarial corpus. |
| `test/fixtures/agent_trust/` | Golden vectors for all eight statement types. |

## V3 Configuration Surface

Exactly one `SigilGuard.Runtime` MUST own the default rate, replay, and
trust-bundle ETS tables. The library application starts it automatically by
default because unstable ownership would weaken replay and rollback protection.
A host MAY set `runtime: false` and supervise `SigilGuard.Runtime` itself to
control failure placement. The runtime accepts explicit configuration through
its `:config` option; when omitted, it reads the `:sigil_guard` application
environment.

`SigilGuard.Config.validate!/1` (or `validate!/0` for the environment fallback)
runs during runtime initialization and fails closed: malformed or non-keyword
input and any key outside the kept set below raise `SigilGuard.ConfigError`
whose message names the offending key and points at `MIGRATING-1.0.md`,
with reason `:legacy_contract_removed` for removed keys and
`:unknown_config_key` for unrecognized keys.

### Kept And New Keys

| Key | Type | Default | Validation |
|-----|------|---------|------------|
| `:runtime` | `boolean()` | `true` | `false` disables automatic startup so the host can supervise `SigilGuard.Runtime`. |
| `:trust_bundle` | `SigilGuard.TrustBundle.source()` | `:none` | Closed constructor set owned by SP.02; invalid source raises `SigilGuard.ConfigError`. |
| `:scanner_patterns` | `:built_in \| :bundle` | `:built_in` | `:bundle` requires `:trust_bundle` other than `:none`; `:registry` raises with reason `:legacy_contract_removed`. |
| `:http_client` | `module() \| nil` | `nil` | When set, MUST implement `SigilGuard.HTTPClient` (SP.05). Sole consumer: the audit anchor HTTP store. `nil` disables it; local file anchors are unaffected. |
| `:attestation_ttl_ms` | `pos_integer()` | `300_000` | Non-positive or non-integer raises. |
| `:max_skew_ms` | `non_neg_integer()` | `60_000` | Negative or non-integer raises. |
| `:replay_ttl_ms` | `pos_integer()` | `300_000` | Non-positive or non-integer raises. |
| `:vault_master_key` | `binary() \| nil` | `nil` | Consumed by `SigilGuard.Vault.InMemory`; semantics owned by SP.10. |
| `:trust_mappings` | `[{String.t(), :low \| :medium \| :high}]` | `[]` | Ordered actor-to-trust table, first match wins. A pattern is an exact string or a prefix ending in a single `*`; any other entry raises. Read only by `SigilGuard.Identity.Static` (SP.10). |

Core runtime dependencies are minimal and individually justified, not zero
(D9, R.07): `:telemetry`, `:nimble_options`, and a JSON library (`jason`).
`nimble_options` supplies validated config/option schemas (see below); `jason`
stays (ubiquitous and already present in consumers), with the stdlib `JSON`
module an acceptable but not required alternative; `finch` is removed because
its only consumer, the legacy remote bundle path, is deleted, so the only
sanctioned HTTP seam is the `SigilGuard.HTTPClient` behaviour (a security and
host-owns-transport decision, not dependency avoidance). The Elixir floor is
`~> 1.18`, justified by OTP 27 crypto and set-theoretic types. Test and dev
dependencies are exempt from the runtime rule.

Configuration and option validation MUST use NimbleOptions schemas rather
than hand-rolled checks. `SigilGuard.Config` declares the closed key set
below as a NimbleOptions schema; unknown keys, wrong types, and removed
legacy keys are rejected fail-closed as `SigilGuard.ConfigError` per the
error taxonomy, and the schema doubles as the generated configuration
documentation.

### Removed Keys

Each raises `SigilGuard.ConfigError` (reason `:legacy_contract_removed`) at
boot, naming the key and `MIGRATING-1.0.md`.

| Removed key | Replacement |
|-------------|-------------|
| `:backend` | None; the native Elixir backend is the only backend. |
| `:protocol_profile` | None; v3 has one profile, `sigil_guard_agent_trust/v1`. |
| `:registry_url`, `:registry_ttl_ms`, `:registry_timeout_ms`, `:registry_retry_ms` | `:trust_bundle` local sources (SP.02). |
| `:registry_enabled` | None; no registry runtime path exists. |
| `:registry_require_signed_bundles`, `:registry_bundle_public_keys` | Bundle roots and thresholds inside the trust bundle (SP.02). |
| `:registry_bundle_max_age_seconds`, `:registry_bundle_clock_skew_seconds` | Bundle expiry and skew fields inside the trust bundle (SP.02). |
| `scanner_patterns: :registry` (value) | `scanner_patterns: :bundle`. |

## Replay And Expiry Semantics

Defaults are configuration, not hardcoded constants. For
`SigilGuard.Attestation` the resolution order is per-call option, then
application env key, then the default below. `TrustBundle.verify/2` and
`AgentCard.verify/3` resolve `:max_skew_ms` from the per-call option and
then the fixed default `60_000`; they do not read the application
environment (SP.02, SP.13).

| Setting | Default | Semantics |
|---------|---------|-----------|
| Attestation TTL | `300_000` ms | `from_decision/3` derives `expires_at = issued_at + ttl` from `:ttl_ms`, else `:attestation_ttl_ms`. `sign/3` derives it the same way for a statement that has `issued_at` and no `expires_at`. It keeps an `expires_at` the statement states, also when its `:now` option replaces `issued_at`. |
| Max clock skew | `60_000` ms | `Attestation.verify/3`: from `:max_skew_ms` opt, else config. Matches the v2 envelope `max_skew_ms` convention. |
| Replay protection | off | Opt-in per verify call with `replay: true` (alias `consume: true`), exactly as today. |
| Replay scope | `{identity, nonce}` | Key is `{"attestation:" <> predicate.actor.id, nonce}` in `SigilGuard.ReplayStore.check_and_put/3` on the existing `:sigil_guard_replay` ETS table. |
| Replay entry TTL | at least `300_000` ms | `max(expires_at - now + S + 1, requested TTL, 1)` ms. The requested TTL resolves from `:replay_ttl_ms`, otherwise `:ttl_ms`, then application `:replay_ttl_ms`, then `300_000` ms. |

The shape of the lifetime is checked by `TrustProfile.validate/1`, and so by
`sign/3`, `from_decision/3`, and `verify/3`: `issued_at >= expires_at` is
structurally invalid and fails with `{:error, :invalid_payload}`, as does a
missing or unparseable `issued_at` or `expires_at`. `sign/3` therefore
refuses an inverted lifetime, and `verify/3` refuses one that was signed
without `sign/3`. Freshness rules are evaluated by `verify/3` only, with
`now` (or the `:now` opt) and skew `S`: `now > expires_at + S` fails with
`{:error, :expired_attestation}`; `issued_at > now + S` (future-dated) also
fails with `{:error, :expired_attestation}`. A second `verify` with
`replay: true` for a live `{actor, nonce}` pair fails with
`{:error, :replay_detected}`; when the replay table already holds 100,000
entries the claim fails with `{:error, :replay_capacity_exceeded}`.

Consuming verification retains the nonce through the inclusive
`expires_at + S` acceptance boundary. A shorter requested replay TTL cannot
reduce that window. Longer retention does not extend attestation validity;
freshness is checked independently before the replay claim.

The replay table is per boot and per node. A nonce consumed before the
runtime restarts, or on another node, is not known afterwards.
[SP.19](SP.19-physical-effect-authority.md) records these limits and what a
host needs in addition when a request has an external physical effect.

### Operational Defaults Rationale (Normative Anchor)

The table gives the norm or reason behind each cross-cutting default; the owning
specs reference it instead of restating the reason. All are overridable
defaults. Application keys exist only where the configuration table above lists
one, and only `SigilGuard.Attestation` reads `:max_skew_ms` from the application
environment.

| Default | Value | Rationale / norm | Owner |
|---------|-------|------------------|-------|
| Attestation TTL | `300_000` ms (5 min) | Short-lived like an OAuth authorization code (single-use, ≤10 min per RFC 6749); a tool call's approval window is minutes, not hours. | SP.01 |
| Max clock skew | `60_000` ms (60 s) | The conventional JWT/`nbf`/`exp` leeway (RFC 7519 practice); tolerates NTP drift without widening the replay window meaningfully. | SP.01 |
| Replay entry TTL | at least the remaining accepted lifetime | The default requested retention is `300_000` ms. Retention also covers expiry skew and its inclusive boundary, even when the requested TTL is shorter; it may outlive signature acceptance. | SP.01 |
| Confirmation TTL | `300_000` ms (5 min) | Same as attestation TTL; a human approval window (SP.03). | SP.03 |
| Hook timeout | `5_000` ms (5 s) | Conservative synchronous-call budget (HTTP client norm); on a blockable phase a timeout fails closed (blocks). | SP.04 |
| Delegation max depth | `8` | Pragmatic bound (no RFC standard); deeper agent-delegation chains are treated as abuse (`:delegation_too_deep`). | SP.13 |

Replay-store key prefixes (`"attestation:"`, `"confirmation:"`) and audit
hash prefixes (`"fh1:"` for HMAC field hashes, `"redacted-v1"` for redaction
placeholders, SP.05) are deliberately versioned so future encodings
(`"fh2:"`, `"redacted-v2"`) can be introduced without ambiguity. They share
one `SigilGuard.ReplayStore` ETS table, and the distinct prefixes keep the
attestation and confirmation namespaces from colliding.

## Migration: Envelope To Attestation

This table feeds `MIGRATING-1.0.md` mechanically and MUST be reproduced
there 1:1. The v2 verdict mapping is `:allowed -> "allow"`,
`:blocked -> "block"`, and `:scanned -> "allow"`; v2 `:scanned` was
advisory. A v3 `%SigilGuard.Decision{}` records the rules behind its
verdict in `matched_rules`. `Attestation.from_decision/3` copies the
decision `reason` into the predicate, and `matched_rules` when the list is
not empty.

| V2 Envelope surface | V3 Attestation surface |
|---------------------|------------------------|
| `identity` | `predicate.actor.id` (issuer is the resolved signing key via `keyid`). |
| `verdict` (`allowed`/`blocked`/`scanned`) | `predicate.verdict` per the mapping above. |
| `timestamp` | `predicate.issued_at` (`expires_at` is new and required). |
| `nonce` (16-byte hex) | `predicate.nonce`. `from_decision/3` generates a 16-byte hex value unless `nonce:` is passed; `nonce: false` omits the field. A string passed as `nonce:` is written as given; the library does not require the hex format. |
| `signature` (single base64url string) | `signatures[0].sig` in the DSSE envelope, plus new `keyid`. |
| `reason` | `predicate.reason`, copied from the decision. |
| Canonical bytes `{identity,nonce,timestamp,verdict}` | DSSE PAE over the payload type and the JCS statement bytes. |
| `profile:`/`wire_verdict_format:` options | Removed; one profile, one wire form. |
| `Envelope.sign(identity, verdict, opts)` | `Attestation.from_decision/3` + `Attestation.sign/3`. |
| `Envelope.verify(envelope, public_key_b64u, opts)` | `Attestation.verify(envelope, trust_material, opts)`. |
| `_sigil` | `_agent_trust` (`Attestation.attach/2`, `fetch/1`). |
| `_sigil_confirmation` | `_agent_confirmation` (`attach_confirmation/2`, `fetch_confirmation/1`). |
| Legacy envelope fixtures | Moved to `test/fixtures/historical/` (SP.06). |

For a `tool_result`, `from_decision/3` records scanner evidence in
`predicate.scanner` (SP.03). A statement built from a decision without
matched rules has no `matched_rules` field.

## Integration Points

| System | Integration | Direction | Protocol |
|--------|-------------|-----------|----------|
| Host app | `attach`/`fetch`, `sign`/`verify`, `from_decision` | inbound | Elixir API |
| MCP gateway (SP.03) | digest computation, request/result binding | internal | Elixir API |
| TrustBundle (SP.02) | `Attestation.verify/3` accepts a verified bundle as trust material and resolves the `"attestation"` delegate role's keys, less revocations, with the role threshold | inbound | Elixir API |
| Audit (SP.05) | evidence refs; checkpoints/exports as DSSE envelopes | internal | Elixir API |

## Telemetry And Observability

Direct `SigilGuard.Attestation` and `Attestation.Envelope` operations are pure
and emit no event. Host-facing agent operations use the
`[:sigil_guard, :agent_trust, :attest | :verify, :start | :stop | :exception]`
spans owned by SP.13. Trust bundles and audit artifacts that reuse the same DSSE
primitive retain their own component-level events, so one logical operation is
not double-counted. The exact public list is `SigilGuard.Telemetry.events/0`;
OpenTelemetry attribute-prefix reconciliation (D16) is owned by SP.05.

## Error Handling

This table is the profile-wide shared taxonomy; SP.02-SP.13 reference these
atoms instead of inventing artifact-specific ones.

| Error | Trigger | Recovery | User Impact |
|-------|---------|----------|-------------|
| `:invalid_profile` | `predicate.profile` stem unrecognized; `_type` not the Statement URI; payload bytes not a Statement-shaped JSON object; subject names/order violated | reject | no trust decision emitted |
| `:unsupported_profile_version` | profile stem matches, version segment is not `v1` | upgrade SigilGuard or re-issue at `v1` | statement rejected |
| `:unknown_statement_type` | `predicateType` not in the registry, or `statement_type` field mismatch | use a registered type | statement rejected |
| `:invalid_envelope` | envelope not a map; `payload`/`payloadType` not strings; `signatures` not a non-empty list of `{keyid, sig}` string maps | fix producer | envelope rejected |
| `:invalid_payload_type` | `payloadType` differs from `application/vnd.sigilguard+json` | re-emit with the exact constant | envelope rejected |
| `:invalid_base64` | `payload`, or the `sig` of a signature whose keyid resolves, is not decodable base64/base64url | fix producer | envelope rejected |
| `:duplicate_keyid` | two `signatures` entries share a `keyid` | re-issue the envelope | envelope rejected |
| `:missing_trust_bundle` | verify called with trust material that is not a non-empty map | pass a non-empty keyid-to-public-key map | host decides |
| `:unknown_key_id` | no envelope `keyid` resolves in the trust material | pass a map, or a bundle, that contains the signer's keyid | verification fails closed |
| `:untrusted_issuer` | trust material is a bundle and the signing key is revoked, belongs to another role, falls short of the `"attestation"` role threshold, or the role, bundle or root has expired | sign with a current `"attestation"` key | verification fails closed |
| `:invalid_signature` | Ed25519 verification fails for a resolved keyid, or a signature is not 64 bytes | re-sign; investigate tamper | request blocked |
| `:pae_mismatch` | decoded payload bytes differ from the caller-supplied `:expected_payload_sha256` (conformance and cross-artifact checks) | reject the substituted payload; regenerate fixtures | verification fails |
| `:digest_mismatch` | recomputed action/payload/context digest differs from its subject entry | reject | tamper detected |
| `:manifest_digest_mismatch` | recomputed manifest digest differs from the `manifest` subject entry | refresh and re-sign the manifest | request blocked |
| `:unknown_manifest` | `Attestation.verify/3` recomputes digests, the statement carries a `manifest` subject, and the caller supplies neither `:manifest` nor `:manifest_digest`; or `require_manifest: true` and the statement has no `manifest` subject or the caller supplies no usable manifest material; in `SigilGuard.ToolGateway`, `:require_manifest` is in force and no manifest resolves (SP.03) | supply the signed manifest | request blocked |
| `:expired_attestation` | `now > expires_at + skew`, or `issued_at > now + skew` | re-issue a fresh attestation | request blocked |
| `:replay_detected` | `{actor, nonce}` already live in `SigilGuard.ReplayStore` | re-issue with a fresh nonce | request blocked |
| `:replay_capacity_exceeded` | consuming verification while `SigilGuard.ReplayStore` already holds 100,000 entries | retry after entries expire | request blocked |
| `:unsupported_number_range` | integer outside `[-(2^53 - 1), 2^53 - 1]` reached the JCS encoder | carry the value as a string | encoding rejected |
| `:invalid_map` | JCS input not JSON-representable, or key collision after normalization | fix the input map | encoding rejected (surfaced as `:invalid_payload` by `Attestation`) |
| `:invalid_payload` | payload/context cannot produce digest preimages; required action field missing; a map entry with a `nil` value in a payload; a `:payload` given to `from_decision/3` that is not a map, a binary, or a list, or a binary or list for a statement type whose action preimage reads a map; actor id unresolvable; in `TrustProfile.validate/1`, and so in `sign/3`, `from_decision/3`, and `verify/3`, an `actor.id` or `verdict` that is not a non-empty string, a missing or unparseable `issued_at` or `expires_at`, or `issued_at >= expires_at`; at `verify/3`, `replay: true` on a statement without a string `nonce` | supply the required fields | no attestation emitted, or verification fails |
| `:invalid_signer` | signer module does not export `sign/1` or returned a non-64-byte signature | implement `SigilGuard.Signer` | signing fails |
| `:legacy_contract_removed` | removed v2 API or config key used | follow `MIGRATING-1.0.md` | boot/call fails with a migration pointer |
| `:unknown_config_key` | unrecognized `:sigil_guard` key at boot | remove or fix the key per `MIGRATING-1.0.md` | boot fails closed |

## Security Considerations

- No live public discovery in the default path; trust material is local and
  signed (SP.02). No registry-named modules exist in v3.
- Canonicalization is out of the trust path: verifiers check signatures over
  received PAE bytes and never re-canonicalize (R.02). A JCS bug can break
  vector stability but can never make a forged artifact verify.
- Every digest preimage is domain-separated by `statement_type`, and the
  metadata strip rule guarantees attached evidence never perturbs digests.
- Sandbox identity (`sandbox_id`, `isolation_level`) is inside the context
  digest, so approvals and attestations cannot cross sandboxes (R.06).
- Tool metadata is untrusted until signed or bundle-bound; manifest digests
  bind descriptions and schemas against poisoning, drift, and rug pulls
  (R.06 rows 2-5).
- Replay protection binds `{actor, nonce}` with the remaining attestation
  lifetime; confirmation tokens additionally bind exact action digests.
- Legacy fixtures live in `test/fixtures/historical/` and MUST NOT pass
  Agent Trust Profile checks.

## Testing Strategy

| Test | Module | What It Verifies |
|------|--------|------------------|
| golden vectors | `AttestationTest` + conformance suite | All eight fixture sets round-trip byte-identically: `statement.json` signs to `envelope.json` and verifies back. |
| digest tamper | `AttestationTest` | Flipping action/payload/context bytes yields `:digest_mismatch`; manifest yields `:manifest_digest_mismatch`. |
| envelope tamper | `AttestationTest` | Wrong `payloadType`, duplicate keyid, unresolvable keyid, corrupted signature, malformed base64 each yield their named atom. |
| strip rule | `AttestationTest` | Digests identical with and without the six stripped keys attached. |
| replay | `AttestationTest` | Nonce reuse with `replay: true` yields `:replay_detected`. |
| expiry and skew | `AttestationTest` | Expired and future-dated statements yield `:expired_attestation` exactly at the skew boundaries. |
| malformed JCS inputs | `Canonical.JCSTest` | RFC 8785 appendix vectors, surrogate-pair keys, NFC/NFD twins, `-0`, `1e+21`, integers at and beyond the range bound, duplicate-key rejection, encode-decode-encode property. |
| statement validation | `TrustProfileTest` | Unknown types, wrong profile/version, subject order violations fail with named atoms. A missing or empty `actor.id` or `verdict`, a missing or unparseable timestamp, and `issued_at >= expires_at` fail with `:invalid_payload`. |
| statement content | `AttestationFromDecisionTest` | `from_decision/3` generates a nonce that can be consumed once, writes timestamps with three fractional digits for any clock precision, copies matched rules and checked evidence references from the decision, writes `released_sanitized` after a confirmed release, and accepts a text or list payload for `model_egress`. |
| sign-time lifetime | `AttestationSignVerifyTest` | `sign/3` derives a missing `expires_at` from the TTL, keeps a stated one, refuses an inverted lifetime and a statement without an actor, writes a `DateTime` `:now` with millisecond precision, and writes `:nonce` only when it is a string. |
| gateway action preimage | `Attestation.DigestTest`, `ToolGatewayTest` | The `tool_request` and `tool_result` preimages of a gate payload equal those of the raw message, also when the payload's `tool` is null; different arguments give different action digests; a params member named `params` or `method` and a result member named `method` do not change the preimage; a map outside the gate payload shape is read as given. |
| legacy removal | `ConfigTest` + migration tests | Removed keys/APIs raise `SigilGuard.ConfigError`/`:legacy_contract_removed` naming `MIGRATING-1.0.md`. |

## Acceptance Criteria

- [x] `TrustProfile.profile_id/0` returns `"sigil_guard_agent_trust/v1"`;
      `statement_types/0` returns the eight types in the fixed order.
- [x] All 8 statement types validate and round-trip golden vectors
      byte-identically from `test/fixtures/agent_trust/`.
- [x] Verification rejects each tampered digest class with its named atom
      (`:digest_mismatch` x3 classes, `:manifest_digest_mismatch`).
- [x] Envelope negatives produce `:invalid_payload_type`, `:duplicate_keyid`,
      `:unknown_key_id`, `:invalid_signature`, `:invalid_base64`,
      `:invalid_envelope`.
- [x] The JCS encoder passes the RFC 8785 appendix vectors and adversarial
      corpus; out-of-range integers return `:unsupported_number_range`.
- [x] Digest equality is proven with and without `_agent_trust`,
      `_agent_confirmation`, and `confirmation_token` keys present.
- [x] Replay reuse yields `:replay_detected`; expiry and future-dating
      beyond skew yield `:expired_attestation`.
- [x] Configuration and option validation is done through NimbleOptions
      schemas; unknown/wrong-type/removed keys fail closed as
      `SigilGuard.ConfigError`.
- [x] Runtime dependency set is `:telemetry`, `:nimble_options`, and `jason`;
      Elixir floor `~> 1.18`.
- [x] Removed config keys raise typed errors naming `MIGRATING-1.0.md`;
      unknown keys fail boot with `:unknown_config_key`.
- [x] The Envelope-to-Attestation table is reproduced 1:1 in `MIGRATING-1.0.md`.
- [x] Every error atom in this spec's taxonomy is produced by at least one test.

## Implementation Roadmap

Aligned with task milestones (the task list owns task IDs): encoding and
statement work lands in M1; legacy removal and config enforcement land in
M6 per SP.12.

- [x] M1: adopt `:nimble_options`; keep `jason` as the JSON library.
- [x] M1: `SigilGuard.Canonical.JCS` with RFC 8785 appendix vectors and the
      adversarial corpus.
- [x] M1: DSSE envelope encode/decode, PAE, multi-signature verification.
- [x] M1: Statement builder, `TrustProfile` registry, structural validation.
- [x] M1: digest computation for all eight statement types with the strip
      and normalization rules.
- [x] M1: generate and commit golden vectors under `test/fixtures/agent_trust/`.
- [x] M1: `_agent_trust`/`_agent_confirmation` attach and fetch helpers.
- [x] M6: closed config key set with `SigilGuard.ConfigError`; delete
      `SigilGuard.Envelope`/`Profile`/`Registry.*` per SP.12 and
      `MIGRATING-1.0.md`.

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Coverage | >= 95% | `mix test --cover`. |
| Golden vectors | byte-stable across OTP/Elixir releases | conformance suite in CI matrix. |
| Runtime dependencies | `:telemetry`, `:nimble_options`, `jason` | dependency-set assertion test. |
| Config validation | NimbleOptions schema, fail-closed | `ConfigTest`. |
| Legacy public names | zero in v3 public docs | local scan. |
| Migration table | reproduced 1:1 in `MIGRATING-1.0.md` | completeness script (M6). |
| Error taxonomy | every atom exercised by a test | coverage review. |

## Sources

- [R.01 - Embedded Agent Trust Profile](../research/R.01-embedded-mcp-trust-profile.md)
- [R.02 - Attestation Envelope And Canonical Encoding](../research/R.02-attestation-envelope-and-canonical-encoding.md)
- [R.05 - Actor Identity, Delegation, And A2A](../research/R.05-actor-identity-delegation-and-a2a.md)
- [R.06 - Agentic Threat Model And Control Mapping](../research/R.06-agentic-threat-model-and-control-mapping.md)
- [R.07 - Runtime Dependency Selection, Detection Placement, And Interoperability](../research/R.07-runtime-dependencies-and-interoperability.md)
- [DSSE Protocol Specification v1.0](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- [RFC 8785 - JSON Canonicalization Scheme](https://www.rfc-editor.org/info/rfc8785)
- [in-toto Statement v1 Specification](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [in-toto Attestation Framework](https://github.com/in-toto/attestation)
