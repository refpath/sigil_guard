---
sigil_guard:
  id: "SP.03"
  title: "MCP And Tool Attestation Gateway"
  domain: security
  status: implemented
  priority: critical
  created: "2026-07-01"
  updated: "2026-11-20"
  tags:
    ["mcp", "attestation", "capability-manifest", "confirmation", "json-rpc",
     "oauth", "v3"]
  depends_on: ["R.01", "R.02", "R.05", "R.06", "SP.01", "SP.02"]
---

# SP.03 - MCP And Tool Attestation Gateway

## Overview

V3 turns the current MCP helpers into a first-class, transport-neutral tool
gateway. This spec is normative for four artifacts: the CapabilityManifest
canonical form and its `manifest_digest` field list (referenced but not
defined by SP.01), the `tool_request`/`tool_result` predicate bindings, the
confirmation-token lifecycle, and the JSON-RPC error registry. MCP is the
first adapter target; the same contract serves HTTP MCP, stdio MCP, and
in-process tool runners. `SigilGuard.MCP.Gateway` remains permanently as a
thin facade over `SigilGuard.ToolGateway` (D14).

## Technical Architecture

### Overview

Four verified surfaces: the capability manifest (canonical form below,
verified at `tools/list` time and re-checked at every guarded request);
the `tool_request` attestation over the SP.01 action, payload, context,
and manifest digests; the `tool_result` attestation binding result digest,
output-schema digest, quarantine status, scanner summary, evidence refs,
and the request back-reference; and the confirmation token, an
exact-action approval bound to the action, payload, context (including
`sandbox_id`), and manifest digests.

### Data Flow

```mermaid
sequenceDiagram
    participant Server as MCP Server
    participant Host
    participant TG as ToolGateway
    participant Gate as Runtime Gate

    Server->>Host: tools/list definitions
    Host->>TG: verify_manifest per listed tool (pinned via TrustBundle)
    TG-->>Host: verified manifest or typed denial
    Note over Host: unverified definitions never reach model context
    Host->>TG: guard_request(request, context, opts)
    TG->>Gate: strip rule, digests, manifest/audience/sandbox checks
    Gate-->>TG: allow/block/confirm/redact/quarantine
    alt executable
        Host->>Server: tools/call
        Server-->>Host: result
        Host->>TG: guard_result(result, context, opts)
        TG-->>Host: safe result or typed denial
    else denied
        TG-->>Host: JSON-RPC error (-31990..-31984)
    end
    Note over TG: each decision carries audit metadata and emits one MCP event
```

### Architectural Patterns

| Pattern | Used | Justification |
|---------|------|---------------|
| GenServer | no | Guard calls are pure; pinned manifests come from the bundle or host. |
| Behaviour | no | `ToolGateway` is concrete; transports adapt by shaping maps. |
| ETS | yes | `SigilGuard.ReplayStore` consumes single-use confirmation nonces. |
| Telemetry | yes | One consolidated MCP decision event plus the runtime-gate event. The MCP event carries the deny reason and the manifest and result facts listed under Telemetry And Observability; there are no separate event families. |

## CapabilityManifest Canonical Form

This section is this spec's data model and the normative owner of the
`manifest_digest` referenced by SP.01's Digest Computation section.

`%SigilGuard.CapabilityManifest{}` has 33 fields, one more than the 32 at
which the BEAM stores a map as a hash map instead of a flat map. The struct
is a v3 consumer contract (`manifest.title_sha256` and its siblings are
read by hosts), so the fields stay; nesting the seven `*_sha256` fields is a
candidate for the next major version. The wire form, the preimage and the
digest do not depend on the struct layout.

### Digest Field List (Normative)

The preimage field list is exact and closed. Table order is canonical
(JCS) key order, which for these ASCII keys equals byte order.
Normalization follows SP.01 (atoms to strings, omit absent/`nil` optional
fields, never emit `null`). All digests are lowercase-hex SHA-256.

| Field | Type | Required | Rule |
|-------|------|----------|------|
| `allowed_sink_zones` | list | no | Sink trust zones the tool's output may reach; sorted ascending by byte order; consumed by SP.04 output contracts. Omitted = unrestricted, delegated to SP.04 policy. |
| `allowed_source_zones` | list | no | Trust zones allowed to invoke the tool; sorted ascending; omitted = delegated to SP.04 policy. |
| `annotations_sha256` | string | no | SHA-256 of the JCS bytes of the normalized annotations map; omitted when no annotations are declared. |
| `audience` | list | no | RFC 8707-style audience/resource identifiers the tool's upstream credentials are minted for; sorted ascending; omitted when the tool uses no upstream credentials. |
| `description_sha256` | string | yes | SHA-256 of the raw UTF-8 description bytes (SP.01 binary payload class; no JCS). |
| `expires_at` | string | yes | ISO 8601 UTC with millisecond precision, per SP.01. |
| `icons_sha256` | string | no | SHA-256 of the JCS bytes of the MCP icon list; omitted when no icons are declared. |
| `input_schema_sha256` | string | yes | SHA-256 of the JCS bytes of the JSON Schema document. |
| `input_sensitivity` | string | yes | Closed: `public`, `internal`, `private`. |
| `issuer_keyid` | string | yes | `"sha256:" <> hex` per SP.01's keyid rule. It names the issuer for the host's records and is covered by the manifest digest. The library checks its format and does not compare it with a bundle's keys: a manifest in a bundle's `tools` section is authenticated by the bundle signature, and a manifest in `:manifests` by the host that pinned it. |
| `manifest_format` | string | yes | Constant `sigil_guard_capability_manifest/v2`; the digest domain separator. |
| `name` | string | yes | Tool name; MUST be byte-equal to the `tools/list` name. |
| `network_access` | string | yes | Closed: `none`, `outbound`, `bidirectional`. |
| `output_schema_sha256` | string | no | SHA-256 of the JCS bytes of the output schema; omitted when none is declared. |
| `output_sensitivity` | string | yes | Closed: `public`, `internal`, `private`. |
| `reversibility` | string | yes | Closed: `reversible`, `irreversible`. |
| `sandbox` | map | yes | `{"required": boolean}`, plus `{"min_isolation": "container" \| "vm" \| "remote_attested"}` exactly when `required` is `true`. Level ordering is owned by SP.04. |
| `scopes` | list | no | Required OAuth/local scopes; sorted ascending; omitted when none. |
| `server` | string | yes | Canonical MCP server URI for network transports; host-assigned local runner id for stdio and in-process tools. |
| `side_effects` | list | yes | Closed: `none`, `read`, `write`, `delete`, `execute`, `privileged`; sorted ascending; non-empty; `none` MUST be the sole element when present. |
| `suspicious_params` | list | yes | Recomputable disclosure list (next subsection); MAY be empty; deduplicated, sorted ascending. |
| `title_sha256` | string | no | SHA-256 of raw UTF-8 MCP title bytes; omitted when no title is declared. |
| `ui_sha256` | string | no | SHA-256 of normalized MCP Apps UI metadata (`resource_uri`, sorted `visibility`); omitted for non-App tools. |
| `version` | string | yes | Tool implementation version being pinned. |

`manifest_digest` is the lowercase-hex SHA-256 over the compact JCS bytes
of this preimage map; it fills the `manifest` subject entry of
`tool_request` and `tool_result` statements (SP.01 Digest Computation).

Sandbox identity binding: the manifest declares the requirement; the
concrete `sandbox_id` and `isolation_level` are per-execution context
facts. The gateway reads `Context.sandbox_id` and `Context.isolation_level`
(an atom or its string name) and, for a field that is unset, falls back to
`sandbox_id` and `isolation_level` under `context.metadata` (atom or string
keys). When `sandbox.required` is `true`, a request whose context names no
`sandbox_id`, or whose isolation level ranks below `min_isolation`, MUST be
denied with `:sandbox_required`. The ranking is `container` < `vm` <
`remote_attested`; `none`, an absent level, and an unknown name rank below
all three.

Only the `Context` fields enter the SP.01 context digest. Values carried
only under `context.metadata` satisfy the requirement but are outside the
context digest, and so outside an attestation's `context` subject. A
confirmation token still covers them through its `action_digest`, which
digests the whole context including `metadata` (Confirmation Lifecycle).

Carried form: the distributed document carries `description`, `title`,
`icons`, `annotations`, `input_schema`, `output_schema`, and normalized `ui`
in full; normalization substitutes the `*_sha256` preimage fields. Carried
`*_sha256` fields MUST match recomputation, else
`{:error, :invalid_manifest}`. The gateway pins what the host passes: an
entry of the `:manifests` map, or a `tools` entry of the `:trust_bundle`
value (a `%SigilGuard.TrustBundle{}`, a map with a `tools` list, or a bare
list). `:manifests` is consulted first. The gateway verifies no bundle
signature at guard time. Loading and verifying the bundle (SP.02) before the
call is the host's step, and a manifest passed through `:manifests` carries
only the trust the host gives it. Standalone manifest signing is not a v3
surface.

Manifest v2 validates every `x-mcp-header` annotation found in
`input_schema`: the header name is a valid HTTP field-name token, the property
type is `boolean`, `integer`, or `string`, and names are unique
case-insensitively. Suspicious credential parameter names are rejected even
when optional. Header transport and value serialization remain host-owned.

### Suspicious Required Parameters

Schema-injection defense (R.06 row 4, TM.04) binds indicators into the
signed digest. `suspicious_params` is computed deterministically from the
input schema: collect every string element of every list found under a map
key exactly equal to `"required"`, at any depth; lowercase each name and
replace `-` with `_`; a name is suspicious when the normalized form
contains any substring from the closed built-in set `suspicious-params-v1`:

```
access_key, api_key, apikey, authorization, bearer, cookie, credential,
passwd, password, private_key, secret, session_id, token
```

The field records the original schema-declared names. Verifiers MUST
recompute the set from the carried schema with this built-in set only;
bundle pattern extensions feed SP.04 policy indicators, never this field.
A mismatch fails with `{:error, :suspicious_required_param}` (the manifest
lies about its own schema). A matching, non-empty disclosure forces a
`{:confirm, _}` verdict at `guard_request` unless the caller passes
`allow_suspicious_params: true`. A decision that is already blocked stays
blocked.

### Canonical Example

The `repo_file_write` manifest referenced by SP.01's worked `tool_request`
vector, pretty-printed with keys in JCS order (fixtures store compact
bytes). `audience` and `output_schema` are absent, therefore omitted:

```json
{
  "allowed_sink_zones": ["semi_trusted", "trusted"],
  "allowed_source_zones": ["semi_trusted", "trusted"],
  "annotations": {"destructiveHint": false, "title": "Repo File Write"},
  "description": "Write one UTF-8 text file inside the repository working tree.",
  "expires_at": "2027-01-01T00:00:00.000Z",
  "input_schema": {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {"content": {"type": "string"}, "path": {"type": "string"}},
    "required": ["content", "path"],
    "type": "object"
  },
  "input_sensitivity": "internal",
  "issuer_keyid": "sha256:<computed: issuer public key digest>",
  "manifest_format": "sigil_guard_capability_manifest/v2",
  "name": "repo_file_write",
  "network_access": "none",
  "output_sensitivity": "internal",
  "reversibility": "reversible",
  "sandbox": {"min_isolation": "container", "required": true},
  "scopes": ["repo:write"],
  "server": "repo-mcp",
  "side_effects": ["write"],
  "suspicious_params": [],
  "version": "1.4.2"
}
```

The digest preimage is this document with `annotations`, `description`,
and `input_schema` replaced by `annotations_sha256`, `description_sha256`,
and `input_schema_sha256`; all other fields are unchanged. Fixture
convention, mirroring SP.01's generator rules (deterministic,
byte-identical on regeneration, frozen once committed):

```
test/fixtures/capability_manifest/<name>.manifest.json
test/fixtures/capability_manifest/<name>.preimage.json
test/fixtures/capability_manifest/<name>.expected.json
```

`repo_file_write` is the first fixture; its `manifest_digest` is the value
SP.01's `tool_request` golden vector carries in its `manifest` subject.

## Request And Result Attestation Binding

Subject digests (action, payload, context, manifest) follow SP.01's Digest
Computation, including the per-type action-digest preimages and the
metadata strip rule. `attest_request/3` and `attest_result/3` compute them
with `Attestation.Digest.digests/4` over the gate payload that
`MCP.SecurityPayload.for_gate/3` builds from the `:payload` option. That is
the same value `guard_request/3` verifies an inbound attestation against.
The action preimage reads through that gate payload to the MCP message it
wraps (SP.01, Action Digest). The tables fix where each bound item lives.

Both helpers write the statement for the boundary the guard function
evaluated, not for the host context alone. `attest_request/3` uses
`MCP.SecurityPayload.context(payload, :request, context)` and
`attest_result/3` the same with `:result`: the gateway's defaults for phase,
origin, and sink, and the tool, action, and server it reads from the
message, fill the fields the host context leaves unset, and a host value
wins. The context digest and the `boundary` mirror therefore describe the
decision's boundary, and a gateway that guards the request under the same
host context accepts the attestation, also when that context names only the
actor. A verifier that calls `Attestation.verify/3` directly with `:context`
passes that derived context.

### tool_request Binding

`attest_request/3` writes the SP.01 predicate fields `profile`,
`statement_type`, `actor` (`id`, `trust_level`), `verdict`, `issued_at`,
`expires_at`, and `nonce`, which is generated unless the caller passes one.
It adds `action`, `risk_level`, `tool`, `resource`, `reason` when the
decision has one, `matched_rules` when the decision has matched rules, and
`evidence` from the `:evidence` option, else from the decision's
`evidence_refs` when that list is not empty. It writes the `boundary`
mirror of the context digest fields (SP.01).
Granted scopes bind as the ascending-sorted, single-space-joined string in
`resource.scope`.

| Bound item | Where it binds |
|------------|----------------|
| Actor | `predicate.actor.id` (the context `actor`, else `identity`) + `actor` key of the context digest. `guard_request/3` compares the id of an inbound statement with its own context (check order, step 6). |
| Tool identity (tool digest) | `manifest` subject entry = `manifest_digest`, written when the caller passes `:manifest` (a `%CapabilityManifest{}`) or `:manifest_digest`; `predicate.tool` mirror (`name`, `mcp_server`, `manifest_digest`). |
| Action | `action` subject entry. The SP.01 `tool_request` preimage reads through the gate payload to the message it wraps, so it holds `statement_type`, the context `tool`, the request `method`, and the `arguments`. It is the same preimage as for the raw MCP message. Two calls to one tool with different arguments have different action digests. The `payload` subject binds method and arguments too. |
| Full guarded payload | `payload` subject entry. |
| Boundary context incl. `sandbox_id` | `context` subject entry (SP.01 field list; the `Context` fields, not `context.metadata`). |
| Resource / audience | `predicate.resource` `{"uri", "audience", "scope"}`, from the `:resource`, `:audience`, and `:scopes` options; `uri` falls back to the context `resource_uri` and `audience` to the context `intended_audience`. |
| Scopes | `predicate.resource.scope`, joined as above. |
| Nonce | `predicate.nonce`. `Attestation.from_decision/3` generates 16 random bytes as 32 lowercase hex characters unless the caller passes `:nonce`. A caller's string is written as given; its format is not checked. `nonce: false` or `nonce: nil` omits the field, and a statement without a nonce fails `Attestation.verify/3` with `replay: true` (`:invalid_payload`). |
| Expiry | `predicate.expires_at` (TTL default per SP.01). Both timestamps have three fractional digits, with or without `:now`. The helper passes `:now` to `from_decision/3` and to `sign/3`, and both write a `DateTime` with millisecond precision. |

An attestation that a gateway signed while the action preimage held
`statement_type` and `tool` only carries a different `action` digest. It
fails digest recomputation with `:digest_mismatch`, so both sides of a
gateway run a version with the same preimage.

The context passed to `attest_request/3` must name the `tool` and an `actor`
or `identity`; otherwise the call returns `{:error, :invalid_payload}`. The
function casts the context as given. It does not apply the `origin: :model`
and `sink: :tool` request defaults that `guard_request/3` applies. A context
that leaves `origin` or `sink` unset is attested as `:unknown` and
`:internal`, and the inbound check of that envelope then fails with
`:invalid_attestation`. The caller passes a context with explicit `origin`,
`sink`, and `tool` that matches what `guard_request/3` evaluates.

### tool_result Binding

The last four rows are the SP.03-owned `tool_result` predicate extension
fields, additive to the SP.01 core. `attest_result/3` also needs a context
that names the `tool` and an `actor` or `identity`, and it requires
`:request_action_digest`.

| Bound item | Where it binds |
|------------|----------------|
| Result content (result digest) | `payload` subject entry over the stripped result. |
| Action | `action` subject entry. The SP.01 `tool_result` preimage reads through the gate payload as the request preimage does. The gateway's result projection has a `nil` method, so the preimage holds `statement_type`, the context `tool`, and `request_action_digest`, as for the raw JSON-RPC response. A member of the result object named `method` is application data and does not enter the preimage; the `payload` subject binds it. |
| Sink | `sink` key of the context digest + `predicate.boundary.sink`. The `boundary` map is the SP.01 mirror with all its fields; `sink` is one of them. |
| Evidence refs | `predicate.evidence` (SP.01 shape), from the caller's `:evidence` option, else from `Decision.evidence_refs` when that list is not empty; either list is shape-checked (`:invalid_evidence`). `guard_result/3` returns a decision with an empty list, so the field is written only when the caller passes the option or fills the list. |
| Manifest | `manifest` subject entry, written when the caller passes `:manifest` or `:manifest_digest`. `guard_result/3` records the digest of the manifest it resolved in `audit_metadata.manifest_digest`; `attest_result/3` does not read it, so passing the manifest is the caller's step. |
| Request back-reference | `predicate.request_action_digest` (string, required) mirroring the `request_action_digest` inside the action-digest preimage (SP.01). The gateway does not compute it: the caller supplies the `:request_action_digest` option, 64 lowercase hex characters. The `action` subject of the paired `tool_request` statement covers that request's method and arguments, so passing it ties the result to them and not to the tool name alone. |
| Output schema digest | `predicate.output_schema_sha256` (string). It MUST equal the manifest field when the manifest declares one. When `:manifest` is a `%CapabilityManifest{}` that declares an output schema, `attest_result/3` writes the manifest's `output_schema_sha256`; a caller's `:output_schema_sha256` has to be that value or `nil`, and any other value returns `{:error, :schema_digest_mismatch}` and nothing is signed. Without such a manifest (none, one passed as a digest, or one that declares no output schema) the caller's option is written when given and compared with nothing; it must be 64 lowercase hex characters (`:invalid_payload` otherwise), and the field is omitted when the option is absent or `nil`. `attest_request/3` applies the same comparison and writes no such field. |
| Quarantine status | `predicate.quarantine` (map, required): `{"status": "none" \| "quarantined" \| "released_sanitized", "indicator_ids": [string]}`. `status` comes from the `:quarantine_status` option when the caller passes one. Otherwise a decision whose `audit_metadata.release_status` is `:confirmed_sanitized` gives `"released_sanitized"`. `guard_result/3` sets that value when a confirmation releases a quarantined result, and leaves `quarantine_status` at `:quarantined`. For any other decision `audit_metadata.quarantine_status` decides: `:quarantined` gives `"quarantined"`, `:released_sanitized` gives `"released_sanitized"`, and any other value gives `"none"`. `indicator_ids` are the indicator ids as strings, deduplicated and sorted. |
| Scanner summary | `predicate.scanner` (map, required): `{"hit_count": integer, "redacted": boolean}`; summary only, never raw content. |

## Confirmation Lifecycle

Normative resolution of the v2 open lifecycle questions. Tokens are
HMAC-SHA256, host-internal, and never cross a trust boundary; DSSE is not
used here. The token body is the base64url (no padding) of the canonical
bytes of the claims map; the MAC is computed over those same bytes; the
token is `body <> "." <> base64url(mac)`. The canonical bytes come from the
legacy canonical JSON encoder (`SigilGuard.Canonical.LegacyJSON`: compact
JSON, object keys sorted by byte order, values encoded by Jason). They do
not come from the RFC 8785 JCS encoder that SP.01 digests use. Verification
re-encodes the decoded claims and rejects a body whose bytes differ with
`:invalid_token`.

### Claims (Authoritative v3 List)

This table is the complete, authoritative v3 confirmation-token claim set;
SP.08 references it and never restates it. The token wire-format version
stays `2` (`v: 2`, `typ: "sigil_guard.confirmation.v2"`) - v3 keeps the HMAC
format and adds the `manifest_digest` and sandbox-aware `context_digest`
bindings below.

| Claim | Value |
|-------|-------|
| `v` / `typ` / `alg` | `2`, `"sigil_guard.confirmation.v2"`, `"HS256"`. |
| `actor` | Approving actor id: the context `actor` when it is a non-empty string, else the context `identity`, else the `:actor` option, else `"unknown"`. The option does not override a context value. |
| `action_digest` | Legacy action digest from `SigilGuard.Confirmation.fetch_action_digest/2`: SHA-256 over the legacy canonical JSON of `{"context": <every Context field>, "payload": <payload after the strip rule>}`. It is not `Attestation.Digest.action_digest/4`; the two values differ for the same request (Action Digest Decision below). |
| `payload_digest` | SP.01 payload digest (`Attestation.Digest.payload_digest/1`). |
| `context_digest` | SP.01 context digest (`Attestation.Digest.context_digest/2`); `Context.sandbox_id` and `Context.isolation_level` are inside it, so a changed sandbox invalidates the token. |
| `manifest_digest` | Pinned manifest digest, written when the issuer passes `:manifest` (a `%CapabilityManifest{}` or its digest) or `:manifest_digest`, and omitted otherwise. `guard_request/3` expects the claim to equal the resolved manifest's digest: a token without the claim fails when a manifest resolves, and a token with the claim fails when none resolves, both with `:manifest_digest_mismatch`. A drifted or re-listed manifest therefore invalidates the token. `guard_result/3` compares the claim only when the token carries it (Defaults And Rules, manifest binding). |
| `decision` / `action` / `reason` | `"confirm"`; the gate action string; the decision reason (MAY be empty). |
| `issued_at` / `expires_at` | ISO 8601 UTC ms; `expires_at` later than `issued_at`. |
| `nonce` | 16 random bytes, lowercase hex. |

### Action Digest Decision

The `action_digest` claim is the legacy digest, and that is the contract
(D36). It is not replaced by the SP.01 attestation action digest. The
confirmation preimage is frozen for issued tokens and existing consumers.
The two digests also bind different things: the token digest binds the
whole context struct and the payload, and the attestation `action` subject
binds the method, the tool, and the arguments. The SP.01 computations supply
the token's separate `payload_digest` and `context_digest` claims.

### Defaults And Rules

- **TTL:** default `300_000` ms via `:ttl_ms`; no application env key (the
  closed v3 config surface is owned by SP.01).
- **Single-use by default:** verification consumes the nonce through
  `SigilGuard.ReplayStore` (key `"confirmation:" <> actor`, TTL = the
  remaining token lifetime); a second verification fails with
  `:replay_detected`. Pass `consume: false` to `Confirmation.verify/5`, or
  `consume_confirmation: false` to the gateway, for stateless verification.
- **Digest recomputation:** verification recomputes the action, payload,
  and context digests from the live request and context, and compares the
  `manifest_digest` claim with the digest of the manifest the gateway
  resolved. Any change - arguments, sink, actor, `sandbox_id`,
  `isolation_level`, or manifest - fails with `:digest_mismatch` or
  `:manifest_digest_mismatch`. An expired token fails with `:expired`.
  Tokens are never renewed; any change or expiry requires re-issue.
- **Manifest binding:** `Confirmation.verify/5` takes `manifest: digest`
  and `manifest_binding: :exact | :when_claimed` (default `:exact`). With
  `:exact` the token's `manifest_digest` claim must equal the digest, and a
  token without the claim is refused. With `:when_claimed` the digest is
  compared only when the token carries the claim. In both modes a token
  that carries the claim must match, and it is refused when no `:manifest`
  is given. Every refusal is `:manifest_digest_mismatch`. The gateway
  passes `:exact` for a request token and `:when_claimed` for a result
  token. The mode follows the function, not the phase: `guard_request/3`
  always verifies with `:exact`, also when the host context states another
  phase, and `guard_result/3` always with `:when_claimed`. Each sets the
  mode itself and discards a `:manifest_binding` the caller passes.
- **Phases:** `context_digest` uses the context phase as the SP.01 statement
  type. `Confirmation.issue/5` therefore issues tokens for `tool_request`,
  `tool_result`, and `repo_change` contexts and returns
  `{:error, :invalid_payload}` for `inbound_user` and `outbound_model`.
- **Strip rule:** exactly SP.01's six keys, removed from the payload top
  level and from the map under `params` before digest computation:
  `:_agent_trust`, `"_agent_trust"`, `:_agent_confirmation`,
  `"_agent_confirmation"`, `:confirmation_token`, `"confirmation_token"`.
  The gateways apply it in `MCP.SecurityPayload.for_gate/3` before they hand
  the payload to `SigilGuard.Confirmation`, and `Confirmation` applies it
  again: `fetch_action_digest/2` strips through
  `Attestation.strip_metadata/1`, and `payload_digest` strips through
  `Attestation.Digest.payload_digest/1`. `action_digest/2`, `issue/5`, and
  `verify/5` therefore give a host that calls `Confirmation` directly the
  same digests before and after it attaches a token, and a token verifies
  against the request that carries it. A deeper occurrence of one of the
  keys, for example under `params.arguments`, is application data and stays
  bound.
- **Token carriers:** the `:confirmation_token` option, or the
  `_agent_confirmation` or `confirmation_token` key at the request root or
  under `params`.

### Multi-Step Approval Flow

1. `guard_request/3` returns a `{:confirm, reason}` decision.
2. Host calls `ToolGateway.issue_confirmation/5`, passing `manifest:` when
   a pinned manifest applies to the request; the token binds the digests
   above. For a result token (`direction: :result`) `manifest:` is
   optional.
3. Host renders its approval UI from the matched rules and
   `action_digest`; raw payload display is host policy, never required.
4. The approver accepts; the host re-submits the identical request with
   the token under `_agent_confirmation`.
5. `guard_request/3` (with `:confirmation_key`) verifies and consumes the
   token; the decision upgrades to allowed and takes the action recorded in
   `Decision.effect` (`:allow`, `:redact`, or `:quarantine`). On the result
   side `guard_result/3` does the same; confirmed quarantined results
   release only as sanitized text, never raw output.
6. Any change since issuance fails verification, blocks the request, and
   requires a fresh gate pass plus re-issue.

## Threat Coverage And Host-Owned Exclusions

Rows align 1:1 with R.06's control mapping; `TM.xx` names the M5 test
family that MUST be green before 1.0.0.

| Attack (R.06 row) | SP.03 control | Family |
|-------------------|---------------|--------|
| Tool poisoning via descriptions/metadata (2) | Manifest digest pinning over description, annotations, and schema digests; drift denies. | TM.02 |
| Line jumping (3) | `verify_manifest/2` at `tools/list` time, BEFORE any definition enters model context and before any invocation. | TM.03 |
| Schema injection (4) | Schema digests inside the manifest digest + `suspicious_params` disclosure bound into the signed digest and recomputed at verify. | TM.04 |
| Rug pull / TOFU drift (5) | Drift rejection; `notifications/tools/list_changed` forces full re-verification, and re-listed manifests invalidate cached approvals because tokens bind `manifest_digest`. | TM.05 |
| Confused deputy incl. consent replay (6) | Audience/resource binding into attestations and manifests; nonce + expiry on tokens and statements. OAuth consent itself is host-owned. | TM.06 |
| Token passthrough (7) | Explicit deny: a credential whose audience is the host itself is never forwarded upstream (`:token_passthrough_denied`). | TM.07 |
| Stale authorization across stateless requests/list changes (8) | Host-owned subscription transport; SigilGuard independently gates each action and assists with nonce/replay scope plus relisted-manifest re-verification. | TM.07 |

Host-owned exclusions (R.06): OAuth flows, token issuance, and consent
storage; TLS, subscription delivery, and request routing; sandbox creation
and escape-hardening; model behavior. SigilGuard binds the results
(audience, resource, sandbox identity) and records evidence; it never
runs these systems.

## Public API Sketch

Return-type unions name the SP.03 error atoms; spec-local atoms are defined
in Error Handling below, shared atoms in SP.01. SP.16 adds
`:invalid_header_annotation` and `:sensitive_header_param` to the manifest
unions of `verify_manifest/2`, `CapabilityManifest.new/1`, and
`CapabilityManifest.verify/2`.

```elixir
defmodule SigilGuard.ToolGateway do
  @type ctx :: SigilGuard.Context.t() | map() | keyword()

  @type manifest_deny ::
          :unknown_manifest | :manifest_digest_mismatch
          | :schema_digest_mismatch | :manifest_expired
          | :suspicious_required_param | :invalid_manifest

  @type attest_error ::
          SigilGuard.Attestation.from_decision_error()
          | SigilGuard.Attestation.sign_error()
          | :schema_digest_mismatch

  @spec guard_request(term(), ctx(), keyword()) :: SigilGuard.Decision.t()
  # opts: :manifests (%{name => manifest}) | :trust_bundle, :server,
  #  :require_manifest (default true when either is given, else false),
  #  :allow_suspicious_params (default false),
  #  :attestation (:off | :optional | :required, default :off),
  #  :trust_material (SP.01), :confirmation (:honor | :off, default
  #  :honor), :confirmation_key, :confirmation_token, :consume_confirmation
  #  (default true), :audience, :resource, :self_resource, :now,
  #  :max_skew_ms. Denials are block decisions carrying the deny atom in
  #  reason and audit_metadata.

  @spec guard_result(term(), ctx(), keyword()) :: SigilGuard.Decision.t()
  # opts: :request_action_digest (64 lowercase hex; any other value denies
  #  with :invalid_payload), :manifests | :trust_bundle, :server, :now,
  #  :max_skew_ms (the pinned manifest for the tool the host context names,
  #  best effort),
  #  the confirmation options (:confirmation, :confirmation_key,
  #  :confirmation_token, :consume_confirmation, :now), and the
  #  runtime-gate options. guard_result/3 denies nothing for a manifest and
  #  verifies no attestation: :require_manifest, :attestation,
  #  :trust_material, :audience, :resource, and :self_resource have no
  #  effect on a result.

  # guarded_request/3 and guarded_result/3 wrap the same guards in the v2
  # wire shapes: {:ok, decision} | {:error, response, decision} and
  # {:ok, response, decision} | {:error, response, decision}. The stream
  # trio (stream_result/2, guarded_result_chunk/3,
  # finish_guarded_result_stream/2) and response_for_decision/3 keep their
  # v2 signatures over Runtime.Stream.

  @spec verify_manifest(observed :: map(), opts :: keyword()) ::
          {:ok, SigilGuard.CapabilityManifest.t()}
          | {:error, manifest_deny()}
  # observed: one tools/list entry (string keys "name", "description",
  # "inputSchema", "outputSchema", "annotations"; snake_case twins are
  # accepted) or a carried manifest map. opts: :manifests | :trust_bundle
  # (one required), :server (required), :now, :max_skew_ms.

  @spec attest_request(SigilGuard.Decision.t(), ctx(), keyword()) ::
          {:ok, envelope :: map()} | {:error, attest_error()}
  # opts: :payload (required), :signer (required), :keyid, :manifest,
  # :manifest_digest, :resource, :audience, :scopes, :ttl_ms, :now, :nonce
  # (generated when absent), :evidence. Builds and signs a tool_request
  # statement via Attestation.from_decision/3 + Attestation.sign/3 (SP.01);
  # both receive the options. The statement is written for the context
  # guard_request/3 evaluates: SecurityPayload.context(payload, :request,
  # ctx), in which the gateway's defaults for origin and sink and the tool
  # and server it reads from the request fill what ctx leaves unset. The
  # result must name a tool and an actor or identity.

  @spec attest_result(SigilGuard.Decision.t(), ctx(), keyword()) ::
          {:ok, envelope :: map()} | {:error, attest_error()}
  # As attest_request/3, for the context guard_result/3 evaluates, plus
  # required :request_action_digest (missing fails with
  # {:error, :invalid_payload}) and :output_schema_sha256. Both
  # helpers return {:error, :schema_digest_mismatch} when that option
  # differs from the digest a :manifest struct declares.

  @spec issue_confirmation(term(), ctx(), SigilGuard.Decision.t(),
          key :: binary(), keyword()) ::
          {:ok, String.t()}
          | {:error, :invalid_key | :not_confirmable | :invalid_ttl
             | :invalid_actor | :invalid_nonce | :invalid_now
             | :invalid_payload}
  # opts: :direction (:request | :result, default :request), :manifest
  # (a %CapabilityManifest{} or its digest) or :manifest_digest, :actor
  # (used only when the context has no actor or identity), :ttl_ms
  # (default 300_000), :now, :nonce.
end

defmodule SigilGuard.CapabilityManifest do
  @type t :: %__MODULE__{}  # one struct field per canonical-form row

  @spec new(map()) ::
          {:ok, t()}
          | {:error, :invalid_manifest | :suspicious_required_param
             | :unsupported_number_range}
  # Validates required fields, closed enums, and list sorting; computes
  # inner digests and suspicious_params from carried documents; checks
  # caller-supplied *_sha256 and suspicious_params against recomputation.

  @spec digest(t() | map()) ::
          {:ok, String.t()}
          | {:error, :invalid_manifest | :unsupported_number_range}
  # manifest_digest over the compact JCS bytes of the normalized preimage.

  @spec verify(pinned :: t(), observed :: map()) ::
          :ok
          | {:error, :manifest_digest_mismatch | :schema_digest_mismatch
             | :suspicious_required_param | :invalid_manifest}
  # Pure comparison; trust resolution and expiry live in
  # ToolGateway.verify_manifest/2.

  @spec drifted_fields(pinned :: t() | map(), observed :: t() | map()) ::
          {:ok, [String.t()]} | {:error, :invalid_manifest}
  # The digest preimage field names in which the two manifests differ,
  # sorted; [] when the digests are equal. Both manifests are validated
  # first, and one that does not validate gives :invalid_manifest.
end
```

Check order inside `guard_request/3` is normative: (1) strip rule and
structured projection (`MCP.SecurityPayload.for_gate/3` and `context/3`);
the later steps compute their digests from that projection; (2) manifest
resolution and verification when required, then manifest expiry; (3)
passthrough, resource, audience checks - `:token_passthrough_denied` when
`opts[:self_resource]` equals `opts[:audience]` or is one of its entries,
with or without a resolved manifest; with a resolved manifest,
`:resource_mismatch` when `opts[:resource]` differs from the manifest
`server`, and `:audience_mismatch` when `opts[:audience]` matches neither
the manifest `server` nor any `audience` entry; (4) caller visibility
(SP.16), denying with `:app_visibility_denied` or `:app_server_mismatch`;
(5) sandbox requirement; (6) inbound attestation verification per
`:attestation`; (7) runtime gate evaluation (SP.04, SP.07), then the
suspicious-parameter confirmation; (8) confirmation application. The first
failing step denies. [SP.19](SP.19-physical-effect-authority.md) places its
`:effect_binding` checks around these steps without reordering them.

Step 1 does not deny on the context shape. A `ctx` that is not a context
struct, map, or keyword list is replaced by the direction defaults
(`phase: :tool_request`, `origin: :model`, `sink: :tool`, and the `Context`
defaults for the rest) before the later steps run.

Step 6 reads the envelope from `_agent_trust` at the request root. An
envelope under `params` is not read, and `attestation: :required` then
denies with `:invalid_attestation`. The deny reason of every step 6 denial
is `:invalid_attestation`. When `Attestation.verify/3` refuses the envelope,
`audit_metadata.attestation_error` keeps its error atom, for example
`:unknown_key_id`, `:expired_attestation`, or `:digest_mismatch`. A denial
with no envelope to verify, or for an `:attestation` value outside the
three modes, records no `attestation_error`.

A verified statement is evidence for a request only when it names the actor
the host identified. After verification, step 6 compares
`predicate.actor.id` with the context `actor`, or with the context
`identity` when no actor is set. A different id denies with
`:invalid_attestation` and `attestation_error: :actor_mismatch`. A context
that sets neither field is not compared. The comparison runs in the
`:optional` mode too when the request carries an envelope. The context
digest already binds the context actor, so a statement that
`attest_request/3` built from the same context passes; the comparison
refuses a statement whose predicate names another actor than its `context`
subject binds. An empty-string `actor` does not count as set: the
comparison then uses the `identity`, as the attest helpers do when they
write the statement.

At step 7 the gateway passes the resolved manifest's digest and
`side_effects` to the gate as the `:manifest_facts` option and discards a
caller-supplied `:manifest_facts`. Without a resolved manifest the gate
treats the tool as class `execute` (SP.07, Sandbox default).

`guard_result/3` runs none of steps 2 to 6 as a check. It validates
`:request_action_digest`, resolves the pinned manifest for the tool the host
context names, evaluates the gate, records the protocol, manifest, and
result binding metadata (`request_action_digest`, `scanner_summary`,
`quarantine_status`), and applies confirmation.

Manifest resolution for a result is best effort. The tool is the `tool`
the host passes in its context, a non-empty string. A tool name inside the
result message (`tool` or `name` at its root, or `name` under `params`) is
never used for the lookup: it is the tool's own output, and taking the
manifest from it would let a result choose its sandbox class. That name
still enters the result context as before when the host context has no
`tool` key. The lookup uses `:manifests`, `:trust_bundle`, and `:server` as
for a request. An empty `:server` string counts as no server everywhere:
`guard_request/3` and `guard_result/3` then resolve a bundle manifest by tool
name alone, and `verify_manifest/2`, which needs a server, returns
`{:error, :unknown_manifest}`. A host context without a tool, no pinned manifest, an
expired manifest, an invalid manifest, and a `{pinned, observed}` pair that
fails verification all mean no manifest. None of them blocks the result,
and `:require_manifest` has no effect.

With a manifest, the gateway passes its digest and `side_effects` to the
gate as `:manifest_facts`, so the sandbox matrix uses the declared classes
for the result, and the decision's `audit_metadata` carries
`manifest_digest`, `manifest_name`, and `suspicious_params`. Without one
the result is class `execute`. A caller-supplied `:manifest_facts` is
discarded in both cases. The audience and resource checks, caller
visibility, the sandbox requirement, and the suspicious-parameter
confirmation are request checks and do not run for a result.

A result confirmation token may bind the manifest. The gateway verifies it
with `manifest_binding: :when_claimed` (Confirmation Lifecycle): a token
issued without `:manifest` verifies whether or not a manifest resolves, and
a token that carries the claim must equal the resolved manifest's digest.
It fails with `:manifest_digest_mismatch` when the digest differs or when
no manifest resolves.

### MCP.Gateway Facade (D14)

`SigilGuard.MCP.Gateway` REMAINS in v3 as a permanent thin facade over
`ToolGateway` - not deprecated (D14). It stays the discoverable MCP entry
point and keeps the JSON-RPC shaping. Every current helper is kept with its
name and arity. The request, result, confirmation, and stream helpers
delegate to `ToolGateway` with an identical return shape.

The six signed helpers are fail-closed, and that is the contract (D37).
They verify no attestation. They delegate to `SigilGuard.ToolGateway.Base`,
which has no accepting path for signed request metadata: the guards always
return a block decision, and the token helper never issues a token. They
are kept so that a caller of the removed `_sigil` envelope path gets a
refusal and not an unverified pass. The signed-request path is
`ToolGateway.guard_request/3` or `guarded_request/3` with
`attestation: :required`. The facade's `guard_request/3` and
`guard_confirmed_request/3` forward that option unchanged.

| Facade function (kept) | V3 delegation target |
|------------------------|----------------------|
| `guard_request/3` | `ToolGateway.guard_request/3` with `confirmation: :off`. |
| `guarded_request/3` | `ToolGateway.guarded_request/3` with `confirmation: :off`. |
| `guard_confirmed_request/3` | `ToolGateway.guard_request/3`. |
| `guarded_confirmed_request/3` | `ToolGateway.guarded_request/3`. |
| `guard_signed_request/3` | `ToolGateway.Base.guard_signed_request/3`: always a block decision. No attestation is verified and the runtime gate does not run. |
| `guarded_signed_request/3` | `ToolGateway.Base.guarded_signed_request/3`: always `{:error, response, decision}` with code `-31990`. |
| `guard_signed_confirmed_request/3` | `ToolGateway.Base.guard_signed_confirmed_request/3`: always a block decision. The confirmation token is not read. |
| `guarded_signed_confirmed_request/3` | `ToolGateway.Base.guarded_signed_confirmed_request/3`: always `{:error, response, decision}` with code `-31990`. |
| `verify_request_envelope/2` | `ToolGateway.Base.verify_request_envelope/2`: always `{:error, reason}`. It does not call `Attestation.verify/3`. |
| `issue_confirmation_token/5` | `ToolGateway.issue_confirmation/5` (`direction: :request`). |
| `issue_signed_confirmation_token/5` | `ToolGateway.Base.issue_signed_confirmation_token/5`: returns the `verify_request_envelope/2` error and never issues a token. |
| `issue_result_confirmation_token/5` | `ToolGateway.issue_confirmation/5` (`direction: :result`). |
| `guard_result/3` | `ToolGateway.guard_result/3` with `confirmation: :off`. |
| `guarded_result/3` | `ToolGateway.guarded_result/3` with `confirmation: :off`. |
| `guard_confirmed_result/3` | `ToolGateway.guard_result/3`. |
| `guarded_confirmed_result/3` | `ToolGateway.guarded_result/3`. |
| `stream_result/2` | `ToolGateway.stream_result/2`. |
| `guarded_result_chunk/3` | `ToolGateway.guarded_result_chunk/3`. |
| `finish_guarded_result_stream/2` | `ToolGateway.finish_guarded_result_stream/2`. |
| `response_for_decision/3` | `ToolGateway.response_for_decision/3`. |

`verify_request_envelope/2` looks for `_agent_trust` at the request root and
under `params`. It returns `{:error, :missing_envelope}` when the key is
absent, `{:error, :invalid_envelope}` when the value is not a map,
`{:error, :missing_identity}` when the map has no string `identity` field,
and `{:error, :legacy_envelope_removed}` otherwise. An SP.01 DSSE envelope
has no `identity` field and gets `:missing_identity`. The signed guards turn
the reason into a block decision whose `audit_metadata` carries
`envelope_status: :invalid` and `envelope_reason`, and emit the MCP
telemetry event. The response code is `-31990` with `data.status`
`"blocked"`; a missing envelope on these helpers does not map to `-31985`.

The unsigned request and result helpers without `confirmed` in their name
force `confirmation: :off`, so they return a `{:confirm, _}` decision
unchanged even when the request carries a token.

## JSON-RPC Error Registry

Codes sit in an application-defined range outside JSON-RPC's reserved
server-error band. `data` is a
string-keyed map; `nil`-valued fields are omitted. Common `data` fields for
every code: `status`, `action`, `reason`, `phase`, `risk_level`,
`trust_level`, `hit_count`, `indicator_ids`, `content_hash`, and, when the
decision's `audit_metadata` carries them, `action_digest`, `scanner_error`,
`confirmation_status`, `confirmation_reason`, and `evidence` (list of
`{"kind", "ref"}` maps, SP.01 evidence shape). The gate records
`action_digest` on a confirm decision; SP.19 extends that. No gateway path
sets `evidence`, so the field appears only when a host adds an `:evidence`
list to the metadata before it shapes the response.

MCP `2026-07-28` treats `-32000..-32019` as a legacy allocation and reserves
`-32020..-32099`. SigilGuard therefore uses `-31990..-31984`, outside the
complete `-32768..-32000` reserved server-error band. This is
a v3 change from v0.2's `-32001..-32003` and supersedes the pre-release D19
allocation (Decision D20, SP.16).

| Code | `data.status` | Trigger | Additional `data` fields |
|------|---------------|---------|--------------------------|
| `-31990` | `"blocked"` | Any other block verdict, including `:audience_mismatch`, `:resource_mismatch`, `:token_passthrough_denied`, `:invalid_manifest`, the SP.16 visibility denials (named in `reason`), a rejected confirmation token, and the signed `MCP.Gateway` helpers. | `scanner_error` on a scanner failure; `confirmation_status` (`"invalid"`) and `confirmation_reason` on a rejected token. |
| `-31989` | `"confirmation_required"` | `{:confirm, _}` when no token was read: none supplied, or `confirmation: :off`. A rejected token is a block (`-31990`). | None. `confirmation_status` and `confirmation_reason` do not occur on this code. |
| `-31988` | `"quarantined"` | `action: :quarantine`, or a pending confirm whose `effect` is `:quarantine`. | `sanitized_text` only when `include_sanitized: true`. |
| `-31987` | `"manifest_drift"` | `:manifest_digest_mismatch`, `:schema_digest_mismatch`, `:suspicious_required_param`, and the SP.16 atoms `:invalid_header_annotation` and `:sensitive_header_param`. | `tool`, `server` (the context `mcp_server`, when set), `drifted_fields`, and for a `{pinned, observed}` manifest entry `expected_manifest_digest` and `received_manifest_digest` (Denial Facts below). |
| `-31986` | `"unknown_manifest"` | `:unknown_manifest`, `:manifest_expired`. | `tool`, `server` (as above), `manifest_status` (`"unknown"` \| `"expired"`), and `expires_at` for an expired manifest. |
| `-31985` | `"invalid_attestation"` | `attestation: :required` with a missing envelope; `:required` or `:optional` with an envelope that fails SP.01 verification or names another actor than the context; an `:attestation` value outside the three modes. | `attestation_error`: the verification error atom as a string, `"actor_mismatch"`, or `"invalid_attestation"` when no verification ran. |
| `-31984` | `"sandbox_required"` | `:sandbox_required`. | `tool`, `required_isolation`, `received_isolation`, `sandbox_id_present` (boolean). |

### Denial Facts

A gateway denial records the facts below in `Decision.audit_metadata`, and
the response shaper copies them into `data`.

- Manifest drift (`-31987`): a request whose manifest entry is a
  `{pinned, observed}` pair carries `expected_manifest_digest` (the pinned
  digest), `received_manifest_digest` (the observed digest), and
  `drifted_fields`: the digest preimage field names in which the two
  differ, sorted, from `CapabilityManifest.drifted_fields/2`, for example
  `["description_sha256"]` or `["input_schema_sha256", "side_effects"]`.
  The three values need both manifests of the pair to validate and to
  differ in at least one field. A pair whose manifests are equal and name
  another tool than the request has nothing to report. That denial, and
  any other drift denial, records none of the three, and
  `data.drifted_fields` then holds one coarse label that the shaper
  derives from the deny reason: `["manifest"]`,
  `["schema"]`, `["suspicious_params"]`, or `["input_schema"]`. A malformed
  observed manifest is denied with `:invalid_manifest` (`-31990`); that
  denial has no received digest and no field list.
- Expired manifest (`-31986`): `expires_at` is the resolved manifest's
  `expires_at` string. The shaper adds `manifest_status` `"expired"` to
  `data`.
- Attestation (`-31985`): `attestation_error` is the atom
  `Attestation.verify/3` returned, or `:actor_mismatch`; `data` carries it
  as a string. A denial with no verification error has no
  `attestation_error` in the metadata, and `data.attestation_error` is
  `"invalid_attestation"`. That is the case for a missing envelope, an
  envelope under `params` or one that is not a map, and an `:attestation`
  value outside the three modes.

`ToolGateway.verify_manifest/2` returns the bare error atom at `tools/list`
time. A host that wants the field names for a refreshed listing calls
`CapabilityManifest.drifted_fields/2` with the pinned manifest and the
observed manifest in carried form. A bare `tools/list` entry is not a
manifest and returns `{:error, :invalid_manifest}`.

[SP.19](SP.19-physical-effect-authority.md) adds the `:effect_binding`
option and three block reasons: `:effect_binding_required`,
`:invalid_effect_binding`, and `:effect_replay_protection_required`. They map
to `-31990` and mint no code. With the option at its default `:off`,
`guard_request/3` verifies an inbound attestation without consuming its
nonce. With `:required` the nonce is consumed once, on the pass that allows
execution, and a failed consumption returns `-31985` with
`attestation_error` set to the SP.01 atom.

## Agent-To-Agent Pointer

This spec is tool-focused. The `agent_request`/`agent_response` statement
types, agent cards (the capability-manifest analog, sharing the
manifest-digest family), delegation-chain validation, and peer trust rules
live in SP.13 on the R.05 groundwork. `ToolGateway` does not accept agent
statements.

## Module Map

| Module | Purpose |
|--------|---------|
| `lib/sigil_guard/tool_gateway.ex` | Transport-neutral guard, manifest verification, attest helpers. |
| `lib/sigil_guard/tool_gateway/base.ex` | JSON-RPC response shaping, stream helpers, and the fail-closed signed helpers. |
| `lib/sigil_guard/capability_manifest.ex` | Canonical form, inner digests, `manifest_digest`, verify. |
| `lib/sigil_guard/mcp/gateway.ex` | Permanent MCP facade (D14) and JSON-RPC shaping. |
| `lib/sigil_guard/mcp/protocol.ex` | MCP revision and successful-result discrimination. |
| `lib/sigil_guard/mcp/security_payload.ex` | Structured request/result security projection. |
| `lib/sigil_guard/mcp/app_resource.ex` | Offline MCP Apps resource verification. |
| `lib/sigil_guard/confirmation.ex` | v2 claims, four-digest binding, single-use default. |
| `test/sigil_guard/tool_gateway_test.exs` | Guard, drift, audience, sandbox, ordering tests. |
| `test/sigil_guard/capability_manifest_test.exs` | Canonical form, digest, suspicious-param tests. |
| `test/sigil_guard/mcp/gateway_test.exs` | Facade parity and JSON-RPC registry tests. |
| `test/fixtures/capability_manifest/repo_file_write.*.json` | Golden manifest, preimage, and expected digest vector. |

## Integration Points

| System | Integration | Direction | Protocol |
|--------|-------------|-----------|----------|
| Host MCP adapter | `tools/list` verification, guarded calls/results | inbound | Elixir API |
| Runtime gate (SP.04, SP.07) | boundary decisions | internal | Elixir API |
| Attestation (SP.01) | digests, sign/verify, `_agent_*` helpers | internal | Elixir API |
| TrustBundle (SP.02) | pinned manifests, issuer keys | internal | Elixir API |
| Audit (SP.05) | `Decision.audit_metadata` for the host to log; the gateway writes no audit event and fills no evidence refs | internal | Elixir API |

## Telemetry And Observability

The stable 1.0 gateway event is `[:sigil_guard, :mcp, :request]`, with
`%{system_time: integer}` measurements. `guard_request/3` and
`guard_result/3` each emit it once per call. Its metadata is the decision's
`audit_metadata` filtered through a fixed allow-list: phase, origin, sink,
actor, identity, tool, `mcp_server`, `resource_uri`, `protocol_version`,
`mcp_result_type`, trust zone, trust level, risk level, verdict, action, hit
and indicator counts, indicator ids, `content_hash`, `action_digest`,
`action_digest_error`, `scanner_error`, `runtime_input_error`, envelope
status/reason, confirmation status, reason, actor, nonce hash, and
issue/expiry times, the SP.19 effect-binding fields, the repo-policy
verdict, rules, unmatched paths, and `repo_policy_digest`, and
`deny_reason`, `manifest_digest`, `manifest_name`,
`request_action_digest`, `quarantine_status`, `decision_id`, `sandbox_id`,
and `matched_rule_ids`.

A key is on the event only when the decision's metadata has it:

- `deny_reason` is set by a gateway denial and by a rejected confirmation
  (`:confirmation_failed`), so a handler can tell a manifest, sandbox, or
  attestation denial from another block. The suspicious-parameter
  confirmation sets it to `:suspicious_required_param` too. That value
  stays in the decision's audit metadata after the token is accepted, as
  the record of why confirmation was asked for, and the event of the
  allowed decision leaves it out: an event with verdict `allowed` has no
  `deny_reason`.
- `manifest_digest` and `manifest_name` are present when a manifest
  resolved and the gate ran. A denial before the gate carries neither.
- `request_action_digest` and `quarantine_status` come from
  `guard_result/3`.
- `decision_id` and `sandbox_id` are on every event whose call set them,
  a denial before the gate included: the gateway copies the `:decision_id`
  option and the context `sandbox_id` onto such a denial.
  `matched_rule_ids` comes from the gate (SP.07), so a denial before the
  gate has none.

The allow-list drops every other key. `suspicious_params`,
`scanner_summary`, `release_status`, `attestation_error`, `expires_at`, the
drift digests and `drifted_fields`, and the sandbox denial fields stay on
`Decision.audit_metadata` and do not reach the event; a host that needs
them reads the returned decision.

`protocol_version` and `mcp_result_type` are on the MCP event only (D40).
The gate receives the security projection, not the MCP message, and the
gateway attaches both fields after the gate has emitted its event.

The runtime gate also emits `[:sigil_guard, :runtime, :gate]` for the
underlying boundary decision. A denial before the gate emits only the MCP
event, and the stream helpers emit only the gate event. There are no
separate `:tool_gateway` event families. SP.16 extends the MCP event
metadata for MCP v2 and Apps without renaming the event. Raw request/result
content and credential material never enter metadata. The exact public list
is `SigilGuard.Telemetry.events/0`; prefix reconciliation (D16) is owned by
SP.05.

## Error Handling

Spec-local atoms. Shared atoms (`:digest_mismatch`, `:expired_attestation`,
`:replay_detected`, `:invalid_signature`, `:unknown_key_id`,
`:invalid_payload`, and the rest of SP.01's taxonomy) are reused unchanged.

| Error | Trigger | Recovery | User Impact |
|-------|---------|----------|-------------|
| `:unknown_manifest` | Manifest required and no pinned manifest exists for `(server, name)` (gateway trigger for the SP.01 shared atom) | load a signed bundle carrying the manifest | request blocked; definition withheld |
| `:manifest_digest_mismatch` | Recomputed preimage digest differs from the pinned digest, the attestation `manifest` subject, or the token `manifest_digest` claim | re-verify listing; re-sign the manifest deliberately | request blocked; approvals invalidated |
| `:schema_digest_mismatch` | Observed input/output schema JCS digest differs from the pinned `*_sha256` field; or the `:output_schema_sha256` option of an attest helper differs from the digest its `:manifest` declares | treat as drift and re-sign deliberately; pass the manifest's value or omit the option | request blocked; no statement signed |
| `:manifest_expired` | `now > expires_at + max_skew_ms` for the pinned manifest | issue a manifest with a fresh expiry | request blocked |
| `:suspicious_required_param` | Recomputed suspicious set differs from the signed `suspicious_params` field | fix or honestly disclose the schema | manifest rejected |
| `:invalid_manifest` | Missing required field, unknown enum value, unsorted list, or carried digest that fails recomputation | fix the manifest document | manifest rejected |
| `:audience_mismatch` | Supplied credential audience matches neither the manifest `server` nor any `audience` entry | acquire a credential for the right audience | request blocked |
| `:resource_mismatch` | RFC 8707 resource indicator differs from the manifest `server` | request tokens with the correct resource | request blocked |
| `:token_passthrough_denied` | Attached credential audience equals `:self_resource` - an inbound token forwarded upstream | run a proper OAuth flow for the upstream | request blocked |
| `:sandbox_required` | `sandbox.required` and the context lacks `sandbox_id` or `isolation_level` is below `min_isolation` | execute in a compliant sandbox and bind its identity | request blocked |

## Security Considerations

- Tool descriptions, schemas, and annotations are supply-chain material:
  digest-verified before entering model context, policy inputs only, and
  trusted only as far as the manifests the host pins. Verifying the bundle
  that carries them (SP.02) is the host's step before the guard call;
  unknown or unverifiable definitions MUST be withheld from model context.
- A changed tool listing delivered by the host subscription path MUST trigger
  full re-verification; cached approvals die structurally because tokens bind
  `manifest_digest`.
- Token passthrough is forbidden by the MCP specification; the gateway
  enforces the deny deterministically rather than trusting servers.
- Confirmation tokens cannot approve changed arguments, sinks, actors,
  sandboxes, manifests, or contexts; single-use is the default. For the
  manifest this holds for a request token, and for a result token that
  carries the `manifest_digest` claim. A result token issued without the
  claim does not bind the manifest.
- Privileged tools fail closed without required sandbox identity; tool
  output is untrusted until scanned and source-to-sink policy allows it
  (SP.04); quarantined output releases only as sanitized text.

## Testing Strategy

| Test | Module | What It Verifies |
|------|--------|------------------|
| manifest golden vector | `CapabilityManifestTest` | `repo_file_write` fixture digests reproduce byte-identically. |
| drift matrix | `ToolGatewayTest` | Changed name, description, annotations, scopes, `side_effects`, `network_access` each fail `:manifest_digest_mismatch`; changed input/output schema fails `:schema_digest_mismatch` (TM.02, TM.05). |
| list-before-invoke | `ToolGatewayTest` | Verification at `tools/list` time rejects a poisoned listing before any `guard_request` (TM.03). |
| suspicious params | `CapabilityManifestTest` | Undisclosed suspicious required param fails `:suspicious_required_param`; disclosed non-empty set forces confirm (TM.04). |
| list_changed | `ToolGatewayTest` | Post-`list_changed` drift invalidates prior verification and outstanding tokens (TM.05). |
| wrong audience/resource | `ToolGatewayTest` | `:audience_mismatch` and `:resource_mismatch` block (TM.06). |
| token passthrough | `ToolGatewayTest` | Audience equal to `:self_resource` blocks with `:token_passthrough_denied` (TM.07). |
| unsandboxed privileged tool | `ToolGatewayTest` | Missing/insufficient sandbox blocks with `:sandbox_required` (TM.09). |
| poisoned result | `ToolGatewayTest` | Injected result content quarantines; release is sanitized-only (TM.01). |
| confirmation binding | `ConfirmationTest` | Token cannot approve a changed action, payload, context (incl. `sandbox_id`), or manifest; second use fails `:replay_detected`; expiry honored (TM.06). |
| attested actor | `ToolGatewayTest` | A verified statement whose `predicate.actor.id` is not the context actor is denied with `:invalid_attestation`. |
| denial facts | `ToolGatewayTest`, `CapabilityManifestTest` | An attestation denial keeps the `Attestation.verify/3` atom in `attestation_error`; an expired-manifest denial carries `expires_at`; a drift denial for a `{pinned, observed}` entry carries both digests and the preimage fields from `drifted_fields/2`. |
| result manifest | `ToolGatewayTest` | `guard_result/3` uses the pinned manifest of the context tool for the sandbox matrix class and records its digest and name; without a pinned manifest, or with an expired one, the result is class `execute` and carries no manifest metadata. |
| direct confirmation | `ConfirmationTest` | `action_digest/2` is the same with and without the stripped keys at the root and under `params`; a token attached to its request verifies in a direct `verify/5` call; `manifest_binding: :exact` refuses a token without the claim and `:when_claimed` accepts it; a token with the claim must match in both modes. |
| result token | `ToolGatewayTest` | A result token issued with the pinned manifest and one issued without it are both accepted; a token bound to another manifest is refused with `:manifest_digest_mismatch`. |
| output schema digest | `ToolGatewayTest` | A result statement carries the output schema digest of its `:manifest`; another caller value returns `:schema_digest_mismatch`. |
| action binding | `ToolGatewayTest`, `Attestation.DigestTest` | The `action` subject of a gateway-built `tool_request` statement changes with the arguments, and the gateway accepts its own attestation; the preimage of the gate payload equals that of the raw message, also when the params object has a member named `params` or `method`. |
| released result | `AttestationFromDecisionTest`, `ToolGatewayTest` | A decision with `release_status: :confirmed_sanitized` attests `released_sanitized`; `guard_result/3` sets that status on a confirmed release. |
| facade parity | `MCP.GatewayTest` | Every facade helper delegates per the mapping table with identical return shapes and JSON-RPC codes. |

Every module includes negative, tamper, replay, expiration, and
malformed-input cases per repository rule 9.

## Acceptance Criteria

- [x] `CapabilityManifest.digest/1` reproduces the committed
      `repo_file_write` golden vector; SP.01's `tool_request` vector
      references that exact digest.
- [x] Every drift-matrix mutation is rejected with its named atom; none
      falls through to a generic error.
- [x] `tools/list` verification runs before any definition reaches model
      context; `list_changed` forces re-verification and invalidates
      outstanding tokens via `manifest_digest`.
- [x] `suspicious_params` recomputation uses only `suspicious-params-v1`;
      a lying manifest fails `:suspicious_required_param`; a disclosed
      non-empty set forces confirm by default.
- [x] Passthrough, audience, resource, and sandbox denials produce their
      named atoms and documented JSON-RPC codes.
- [x] Confirmation tokens: `300_000` ms default TTL, single-use by
      default, four-digest binding, re-issue required on any change.
- [x] Codes `-31990..-31984` are selected per the registry, and `data`
      omits `nil` fields.
- [x] Gateway denials populate the registry fields. A drift denial for a
      `{pinned, observed}` entry carries `expected_manifest_digest`,
      `received_manifest_digest`, and the differing preimage keys in
      `drifted_fields`; an expired-manifest denial carries `expires_at`; an
      attestation denial carries the `Attestation.verify/3` atom in
      `attestation_error` (`ToolGatewayTest`: "a drift denial names both
      digests and the fields that changed", "an expired manifest denial
      says when it expired", "a denial says which verification step refused
      the attestation"; `CapabilityManifestTest`, "drifted_fields/2").
- [x] The unsigned `MCP.Gateway` request, result, confirmation, and stream
      helpers delegate per the facade table with an identical return shape
      (parity tests).
- [x] The signed `MCP.Gateway` helpers are fail-closed (D37): every signed
      guard blocks, `verify_request_envelope/2` returns an error, and
      `issue_signed_confirmation_token/5` issues no token
      (`MCP.GatewayTest`: "guard_signed_request/3",
      "guard_signed_confirmed_request/3", "verify_request_envelope/2",
      "issue_signed_confirmation_token/5"). The signed-request path is
      `ToolGateway.guard_request/3` with `attestation: :required`.
- [x] A verified inbound statement that names another actor than the
      context is denied (`ToolGatewayTest`, "a verified statement about
      another actor is not evidence for this request").
- [x] Gateway digests are identical with and without the six stripped keys
      present at root and under `params`.
- [x] `Confirmation.issue/5` and `verify/5` called directly produce the
      same `action_digest` with and without the stripped keys
      (`ConfirmationTest`, "strip rule": "the digest is the same before and
      after trust metadata is attached", "a token attached to the request it
      confirms verifies in a direct call"). The test uses the string forms
      of the three keys.
- [x] `guard_result/3` resolves the pinned manifest of the context tool
      without blocking for a missing or expired one, and a result token may
      bind it or omit it (`ToolGatewayTest`: "a result whose context names a
      pinned tool uses that manifest", "a result token may bind the pinned
      manifest, and one issued without it still works"; `ConfirmationTest`,
      "manifest binding").
- [x] A `tool_result` statement carries the output schema digest of its
      `:manifest`, and a different caller value returns
      `:schema_digest_mismatch` (`ToolGatewayTest`, "a result attestation
      carries the manifest's output schema digest and no other").
- [x] Every spec-local error atom is produced by at least one test.

## Implementation Roadmap

Aligned with the task milestones (the task list owns task IDs): gateway
and manifest work lands in M3; the threat suite lands in M5; legacy strip
removal lands in M6.

- [x] M3: `SigilGuard.CapabilityManifest` canonical form, inner digests,
      and the `repo_file_write` golden fixture.
- [x] M3: `suspicious-params-v1` extraction in creation and verification.
- [x] M3: `verify_manifest/2` with the `tools/list`-time flow and
      `list_changed` re-verification.
- [x] M3: `guard_request/3` and `guard_result/3` with the normative check
      order and deny atoms.
- [x] M3: `attest_request/3` and `attest_result/3` over SP.01 Attestation.
- [x] M3: confirmation v2 claims, single-use default; transition
      dual-strips `_sigil*` alongside `_agent_*`.
- [x] M3: JSON-RPC codes `-31990..-31984` and `data` shapes.
- [x] M3: `MCP.Gateway` rewired as the permanent facade per the table.
- [x] M5: threat-model modules for the TM rows owned here.
- [x] M6: remove `_sigil*` reading; the strip rule reduces to SP.01's six
      keys.

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Tamper rejection | 100% of drift/tamper vectors | gateway and manifest tamper tests. |
| Facade parity | 100% of helpers delegate identically | parity test suite. |
| Golden vectors | byte-stable across releases | conformance suite in CI. |
| Transport lock-in | none | no required MCP adapter dependency. |
| Coverage | >= 95% | `mix test --cover`. |

## Sources

- [R.01 - Embedded Agent Trust Profile](../research/R.01-embedded-mcp-trust-profile.md)
- [R.02 - Attestation Envelope And Canonical Encoding](../research/R.02-attestation-envelope-and-canonical-encoding.md)
- [R.05 - Actor Identity, Delegation, And A2A](../research/R.05-actor-identity-delegation-and-a2a.md)
- [R.06 - Agentic Threat Model And Control Mapping](../research/R.06-agentic-threat-model-and-control-mapping.md)
- [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [RFC 8707 - Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/info/rfc8707)
- [RFC 9728 - OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8785 - JSON Canonicalization Scheme](https://www.rfc-editor.org/info/rfc8785)
- [JSON Schema 2020-12](https://json-schema.org/specification)
