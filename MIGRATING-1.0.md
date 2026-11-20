# Migrating To SigilGuard 1.0

## Dependency Update

Update the package requirement when you are ready to adopt the 1.0 breaking
surface. Historical 0.2.x docs used "v2" and the 1.0 development docs used
"v3"; this guide otherwise uses release-line names.

```elixir
# 0.2.x line
{:sigil_guard, "~> 0.2"}

# 1.0 line
{:sigil_guard, "~> 1.0"}
```

For pre-release validation against a local checkout, use a path dependency so
the consumer exercises the exact branch under review:

```elixir
{:sigil_guard, path: "../sigil_guard", override: true}
```

Keep that path dependency out of production branches. Replace it with `~> 1.0`
when moving production code to the 1.0 release line.

## Migration Checklist

- Rename policy files to the <code>SIGILGUARD</code> filename family.
- Move MCP trust metadata from `_sigil` to `_agent_trust`.
- Move MCP confirmation metadata from `_sigil_confirmation` to
  `_agent_confirmation`.
- Replace the removed registry namespace with local or embedded
  `SigilGuard.TrustBundle` sources.
- Replace verdict envelopes with Agent Trust attestations.
- Replace profile compatibility calls with `SigilGuard.TrustProfile`.
- Remove deleted 0.2.x configuration keys before booting 1.0.
- Update expected error atoms and boot-error handling.
- Re-check socket, channel, or session-auth code that previously carried
  `_sigil`; it must now carry or verify `_agent_trust`.
- Reissue all confirmation tokens and attestations; MCP action binding now
  covers the complete structured payload instead of extracted string values.
- Regenerate pinned capability manifests as
  `sigil_guard_capability_manifest/v2`.
- Move MCP denial handling to `-31990..-31984` and continue branching on
  `error.data.status`.
- Pass `protocol_version: "2026-07-28"` from adapters that want modern
  `resultType` behavior.
- Treat MCP Apps rendering, CSP enforcement, and browser sandboxing as
  host-owned after `SigilGuard.MCP.AppResource` verification.
- Leave host-owned sigil-prefixed boot keys untouched unless they configure
  SigilGuard itself.

## Policy Filenames

SigilGuard 1.0 renames repository policy files from the old
<code>SIGIL</code> filename family to the <code>SIGILGUARD</code> filename
family. Legacy filenames fail closed with
`{:error, {:legacy_policy_filename, found, use}}` and are never parsed as
fallbacks.

| 0.2.x filename | 1.0 filename |
|-------------|-------------|
| `SIGIL_POLICY` | `SIGILGUARD_POLICY` |
| `.sigil-policy` | `.sigilguard-policy` |
| `.sigil/policy` | `.sigilguard/policy` |
| `.github/sigil-policy` | `.github/sigilguard-policy` |

## MCP Trust Metadata

Use `_agent_trust` instead of `_sigil` for Agent Trust attestations attached to
MCP payloads. `SigilGuard.Attestation.attach/2` writes the envelope at the
JSON-RPC payload root, and `SigilGuard.Attestation.fetch/1` and the gateways
read it only there. 1.0 strips `_agent_trust` at the root and inside `params`
before computing action digests, so an envelope left inside `params` is not
verified: `attestation: :required` blocks the request with
`:invalid_attestation`, and `attestation: :optional` treats the request as
carrying no attestation. 1.0 does not strip `_sigil`.

Before:

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "method": "tools/call",
  "params": {
    "name": "repo_file_write",
    "arguments": {
      "path": "docs/guide.md",
      "content": "updated"
    },
    "_sigil": {
      "identity": "spiffe://prod.example.org/agents/release-bot",
      "verdict": "allowed",
      "timestamp": "2026-07-02T12:00:00.000Z",
      "nonce": "000102030405060708090a0b0c0d0e0f",
      "signature": "legacy-base64url-signature"
    }
  }
}
```

After:

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "method": "tools/call",
  "params": {
    "name": "repo_file_write",
    "arguments": {
      "path": "docs/guide.md",
      "content": "updated"
    }
  },
  "_agent_trust": {
    "payloadType": "application/vnd.sigilguard+json",
    "payload": "base64url-jcs-in-toto-statement",
    "signatures": [
      {
        "keyid": "sha256:65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8",
        "sig": "base64url-dsse-signature"
      }
    ]
  }
}
```

Mixed-traffic rollout: do not send both metadata keys to the same 1.0 endpoint.
Upgrade producers and consumers as a pair, or route 0.2.x traffic to the old
0.2.x deployment until both sides emit and verify `_agent_trust`. In 1.0, `_sigil` is
ordinary user content for digest purposes and can change the signed action
digest instead of being treated as transport metadata.

Check both common attachment sites during migration:

- **Tool-call arguments**: replace any code that inserts `_sigil` into MCP
  `params` or `arguments` with `SigilGuard.Attestation.attach/2`, which puts
  `_agent_trust` at the payload root.
- **Socket or session authentication**: replace any code that accepts `_sigil`
  as an auth payload with `SigilGuard.Attestation.fetch/1` and
  `SigilGuard.Attestation.verify/3`, using trust material from a verified
  bundle or host-owned authentication.

## MCP Confirmation Metadata

Use `_agent_confirmation` instead of `_sigil_confirmation` for confirmation
metadata. Like `_agent_trust`, 1.0 strips `_agent_confirmation` at the JSON-RPC
payload root and inside `params` before computing action digests.

`SigilGuard.Confirmation.issue/5`, `verify/5`, and `action_digest/2` apply
the same strip rule themselves, so a host that calls them without the
gateway can verify a token against the request it is attached to. Releases
up to 1.0.5 stripped only in the gateways, and a direct caller had to remove
the token before verifying. A payload that carries none of the stripped
keys has the same digest as before.

Before:

```json
{
  "jsonrpc": "2.0",
  "id": "call-2",
  "method": "tools/call",
  "params": {
    "name": "send_webhook",
    "arguments": {
      "url": "https://hooks.example.invalid/deploy",
      "body": "deploy"
    },
    "_sigil_confirmation": "legacy-confirmation-token"
  }
}
```

After:

```json
{
  "jsonrpc": "2.0",
  "id": "call-2",
  "method": "tools/call",
  "params": {
    "name": "send_webhook",
    "arguments": {
      "url": "https://hooks.example.invalid/deploy",
      "body": "deploy"
    },
    "_agent_confirmation": "1.0-confirmation-token"
  }
}
```

When the token is already held out-of-band, pass it through the existing
`:confirmation_token` option instead of embedding transport metadata. Pass the
context the token was issued for and the key that signed it:

```elixir
SigilGuard.MCP.Gateway.guard_confirmed_request(
  request,
  context,
  confirmation_token: token,
  confirmation_key: confirmation_key
)
```

Without `:confirmation_key` the token cannot be verified and the decision is
`:block` with `audit_metadata.deny_reason` set to `:confirmation_failed`. The
same options apply to `guarded_confirmed_request/3`,
`guard_confirmed_result/3`, and `guarded_confirmed_result/3`.

A request token must carry the digest of the pinned manifest when one
resolves for the tool. A result token may carry it or omit it: the result
guards compare the manifest only when the token has the claim
(`manifest_binding: :when_claimed` in `SigilGuard.Confirmation.verify/5`).
Releases up to 1.0.5 rejected a result token issued with `manifest:`.

The signed variants never read a token. 1.0 has no accepting path for
envelope-shaped request metadata, so `guard_signed_request/3`,
`guarded_signed_request/3`, `guard_signed_confirmed_request/3`, and
`guarded_signed_confirmed_request/3` always return a block decision, and
`issue_signed_confirmation_token/5` always returns an error. Use
`SigilGuard.ToolGateway.guard_request/3` with `attestation: :required` for
signed requests.

## Registry To Trust Bundles

The `SigilGuard.Registry` namespace is removed. Migrate to verified trust bundle
sources loaded by `SigilGuard.TrustBundle`.

### Fetch Bundle

`SigilGuard.Registry.fetch_bundle/1` maps to `SigilGuard.TrustBundle.load/1`.

Before:

```elixir
{:ok, bundle} = SigilGuard.Registry.fetch_bundle("agent-policy")
```

After, for a bundle file managed by the host:

```elixir
source = {:file, "/etc/sigil_guard/trust_bundle.json"}
{:ok, bundle} = SigilGuard.TrustBundle.load(source)
```

After, for a bundle shipped in an OTP application's `priv/` directory:

```elixir
source = {:priv, :my_app, "sigil_guard/trust_bundle.json"}
{:ok, bundle} = SigilGuard.TrustBundle.load(source)
```

After, for bytes fetched by host-owned transport and accepted as the bundle
envelope JSON:

```elixir
source = {:binary, verified_bundle_json}
{:ok, bundle} = SigilGuard.TrustBundle.load(source)
```

`TrustBundle.load/1` verifies the DSSE envelope and bundle metadata before the
bundle enters the runtime. SigilGuard 1.0 does not fetch bundles from a registry;
if a host downloads bundle bytes, that transport, caching, authentication, and
retry policy live outside SigilGuard and feed only the `{:binary, bytes}` source.

### Resolve DID And Key

`SigilGuard.Registry.resolve_did/2` moves to host authentication or verified
bundle issuer lookup. `SigilGuard.Registry.resolve_key/2` moves to verified
bundle root/delegation lookup.

Before:

```elixir
{:ok, did_doc} = SigilGuard.Registry.resolve_did("did:web:agent.example", [])
{:ok, public_key} = SigilGuard.Registry.resolve_key("sha256:key-id", [])
```

After, for DID or actor identity flows, authenticate the principal in the host
and compare it with verified issuer policy from the bundle:

```elixir
{:ok, bundle} = SigilGuard.TrustBundle.load({:file, bundle_path})

allowed_issuers =
  bundle
  |> SigilGuard.TrustBundle.identity_issuers()
  |> MapSet.new()

if MapSet.member?(allowed_issuers, host_authenticated_actor_id) do
  {:ok, host_authenticated_actor_id}
else
  {:error, :actor_not_allowed}
end
```

After, for key material used to verify attestations, resolve by `keyid` from the
verified bundle document and only accept keys authorized by the root or delegated
bundle roles:

```elixir
document = bundle.document
keys = Map.fetch!(document, "keys")
root_keyids = get_in(document, ["roles", "root", "keyids"]) || []

delegate_keyids =
  document
  |> get_in(["roles", "delegates"])
  |> List.wrap()
  |> Enum.flat_map(&Map.get(&1, "keyids", []))

authorized_keyids = MapSet.new(root_keyids ++ delegate_keyids)

trust_material =
  for {keyid, %{"public_key" => public_key}} <- keys,
      MapSet.member?(authorized_keyids, keyid),
      into: %{} do
    {keyid, public_key}
  end

SigilGuard.Attestation.verify(envelope, trust_material)
```

There is no DID resolver in 1.0 core. Network DID resolution, OAuth/resource
server identity, SPIFFE/SVID validation, and account-to-actor mapping remain
host-owned inputs to SigilGuard.

### Fetch Policies

`SigilGuard.Registry.fetch_policies/1` maps to the verified trust bundle
`policies` section.

### Bundle Signing And Cache

`SigilGuard.Registry.Bundle.sign/2` maps to trust-bundle provenance signing.
`SigilGuard.Registry.Cache` maps to `SigilGuard.TrustBundle.Cache`.

## Envelope To Attestation

`SigilGuard.Envelope` is removed. Use `SigilGuard.Attestation` and Agent Trust
DSSE envelopes.

The 0.2.x verdict mapping is `:allowed -> "allow"`, `:blocked -> "block"`, and
`:scanned -> "allow"`; 0.2.x `:scanned` was advisory. A 1.0
`%SigilGuard.Decision{}` records the rules behind its verdict in
`matched_rules`. `Attestation.from_decision/3` copies the decision `reason`
into the predicate, and `matched_rules` when the list is not empty.

| 0.2.x Envelope surface | 1.0 Attestation surface |
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
| Legacy envelope fixtures | Moved to `test/fixtures/historical/`. |

Statements from `from_decision/3` carry more after 1.0.5 than before: a
generated `nonce`, `matched_rules` and `evidence` when the decision has
them, and the `boundary` mirror, which states the phase, origin, sink, trust
zone, and intended audience that the `context` subject binds, with the
source, sandbox id, and isolation level when the context sets them. These
are additions. `TrustProfile.validate/1` rejects only the fields it names,
in 1.0.5 as now, so a verifier of either version accepts the statement of
the other. The one exception is the gateway `action` digest under
[Structured Action Binding](#structured-action-binding).

An `agent_response` statement sets `quarantined` to `true` when the
decision's action or effect is `:quarantine` or when it carries quarantine
indicators. Releases up to 1.0.5 set it only for `action: :quarantine`. A
gate decision reports a quarantine as `action: :confirm, effect: :quarantine`
or blocks it, so those releases attested a response with injection
indicators as not quarantined. A requester that acts on the flag sees
`true` in those cases now.

To bind an agent response to its requester, the responder passes
`audience:` to `AgentTrust.attest_agent_response/3` and the requester passes
its own identity as `audience:` to `verify_agent_response/3`, which returns
`{:error, :invalid_audience}` for a response addressed elsewhere.
`verify_agent_response/3` also takes `capability:` and `context:`, and
returns `{:error, :invalid_payload}` for a `payload:` that is not a map; it
used to skip the digest check for one.

### Signing A Tool Request

Before:

```elixir
{:ok, envelope} =
  SigilGuard.Envelope.sign("spiffe://prod.example.org/agents/release-bot", :allowed,
    reason: "repo write approved"
  )

request =
  update_in(request, ["params"], &Map.put(&1, "_sigil", envelope))
```

After:

```elixir
{:ok, statement} =
  SigilGuard.Attestation.from_decision(decision, context,
    payload: request,
    statement_type: :tool_request
  )

{:ok, envelope} =
  SigilGuard.Attestation.sign(statement, MyApp.AgentSigner,
    keyid: "sha256:65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8"
  )

request = SigilGuard.Attestation.attach(request, envelope)
```

`from_decision/3` gives the statement a nonce: 16 random bytes written as 32
lowercase hex characters. Pass `nonce:` to supply your own string, or
`nonce: false` to build a statement without one. Verification with
`consume: true` rejects a statement without a nonce with `:invalid_payload`.

`sign/3` validates the statement before it signs. Its `now:` option replaces
`issued_at`, and a statement with `issued_at` and no `expires_at` gets the
configured lifetime: `ttl_ms:`, else the `:attestation_ttl_ms` application
key, else `300_000` ms. A statement that then lacks `actor.id`, `verdict`,
or `issued_at`, or whose `issued_at` is not before its `expires_at`, returns
`{:error, :invalid_payload}`. A statement from `from_decision/3` has all four
fields.

### Verifying An Attached Request

Before:

```elixir
with {:ok, envelope} <- Map.fetch(request["params"], "_sigil"),
     {:ok, claims} <- SigilGuard.Envelope.verify(envelope, public_key_b64u) do
  {:ok, claims}
end
```

After:

```elixir
trust_material = %{
  "sha256:65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8" =>
    public_key_b64u
}

with {:ok, envelope} <- SigilGuard.Attestation.fetch(request),
     {:ok, statement} <-
       SigilGuard.Attestation.verify(envelope, trust_material,
         payload: request,
         context: context,
         consume: true
       ) do
  {:ok, statement}
end
```

`consume: true` consumes the nonce, so a second verification of the same
envelope returns `{:error, :replay_detected}`. The trust material can be a
direct `%{keyid => public_key}` map or a map derived from a verified trust
bundle as shown in the registry lookup migration section.

`SigilGuard.ToolGateway.guard_request/3` with `attestation: :required` runs
this verification and one more check: the statement's `predicate.actor.id`
must equal the `actor` of the host context, or its `identity` when no actor
is set. A context that sets neither is not compared. Every such denial has
`audit_metadata.deny_reason` set to `:invalid_attestation`, and
`audit_metadata.attestation_error` names the cause: the
`Attestation.verify/3` error atom, or `:actor_mismatch`.

## Profile To TrustProfile

`SigilGuard.Profile` is removed. Use `SigilGuard.TrustProfile` for the 1.0 Agent
Trust profile. 1.0 has one profile id and one wire form:
`sigil_guard_agent_trust/v1`.

| 0.2.x Profile surface | 1.0 replacement |
|--------------------|----------------|
| `SigilGuard.Profile.profiles/0` | `SigilGuard.TrustProfile.statement_types/0` plus `predicate_type/1` for the closed statement registry. |
| `SigilGuard.Profile.normalize!/1` | Removed. Build or verify a 1.0 Statement and call `SigilGuard.TrustProfile.validate/1`; invalid profiles return typed errors instead of normalizing. |
| `SigilGuard.Profile.wire_verdict_format/1` | Removed. 1.0 uses one predicate verdict vocabulary in Agent Trust statements. |
| `SigilGuard.Profile.verdict_acceptance/1` | Removed. `SigilGuard.Attestation.verify/3` and `SigilGuard.TrustProfile.validate/1` enforce the 1.0 profile. |
| `SigilGuard.Profile.require_blocked_reason_on_verify?/1` | Removed. `Attestation.from_decision/3` writes the blocking rationale to `predicate.reason`. |
| `SigilGuard.Profile.registry_identity_endpoints/1` | Removed. DID/network identity discovery is host-owned; verified bundle issuer policy is available through `SigilGuard.TrustBundle.identity_issuers/1`. |
| `:protocol_profile` config | Removed. Use `SigilGuard.TrustProfile.profile_id/0` when code needs the constant. |

Before:

```elixir
profile = SigilGuard.Profile.normalize!(:auto)
format = SigilGuard.Profile.wire_verdict_format(profile)
```

After:

```elixir
profile_id = SigilGuard.TrustProfile.profile_id()
statement_types = SigilGuard.TrustProfile.statement_types()
{:ok, predicate_type} = SigilGuard.TrustProfile.predicate_type(:tool_request)
```

For validation, do not normalize legacy profile names. Validate the produced or
received Agent Trust Statement:

```elixir
case SigilGuard.TrustProfile.validate(statement) do
  {:ok, statement} -> {:ok, statement}
  {:error, :unsupported_profile_version} -> {:error, :upgrade_required}
  {:error, reason} -> {:error, reason}
end
```

## Configuration Keys

Remove deleted 0.2.x keys before booting 1.0. Removed keys fail closed with
`SigilGuard.ConfigError` naming `MIGRATING-1.0.md`, with reason
`:legacy_contract_removed`.

| Removed key | Replacement |
|-------------|-------------|
| `:backend` | None; the native Elixir backend is the only backend. |
| `:protocol_profile` | None; 1.0 has one profile, `sigil_guard_agent_trust/v1`. |
| `:registry_url`, `:registry_ttl_ms`, `:registry_timeout_ms`, `:registry_retry_ms` | `:trust_bundle` local sources. |
| `:registry_enabled` | None; no registry runtime path exists. |
| `:registry_require_signed_bundles`, `:registry_bundle_public_keys` | Bundle roots and thresholds inside the trust bundle. |
| `:registry_bundle_max_age_seconds`, `:registry_bundle_clock_skew_seconds` | Bundle expiry and skew fields inside the trust bundle. |
| `scanner_patterns: :registry` (value) | `scanner_patterns: :bundle`. |

Accepted 1.0 keys are `:runtime`, `:trust_bundle`, `:scanner_patterns`,
`:http_client`, `:attestation_ttl_ms`, `:max_skew_ms`, `:replay_ttl_ms`,
`:vault_master_key`, and `:trust_mappings`. Unknown keys fail closed with
reason `:unknown_config_key`.

Only remove keys that configure SigilGuard. Host application boot keys may
still use sigil-prefixed names for unrelated local concerns; 1.0 does not reserve
or inspect those names outside the `:sigil_guard` application environment.

## Error Changes

Some 0.2.x error atoms were reconciled for 1.0 trust-bundle and configuration
contracts.

| 0.2.x / draft atom | 1.0 atom | Meaning |
|-----------------|---------|---------|
| `:rollback_detected` | `:sequence_below_floor` | The signed bundle sequence/root version is below the accepted floor. |
| `:expired_bundle` | `:bundle_expired` | Bundle document freshness failed. |
| `:unknown_issuer` | `:unknown_key_id` | No envelope signature key id resolves to an authorized trust-bundle key. |
| `:invalid_schema` | `:invalid_bundle_format` | Bundle payload shape or strict schema validation failed. |
| `:invalid_bundle` | `:invalid_bundle_format` | Bundle payload shape or strict schema validation failed. |
| `:missing_signature` | `:invalid_envelope` | DSSE envelope shape is missing or invalid. |
| `:unsigned_bundle` | `:invalid_envelope` | Unsigned bundles are not a 1.0 trust-bundle format. |

Configuration errors changed from permissive fallback behavior to boot-time
failure. Removed keys raise `SigilGuard.ConfigError` with reason
`:legacy_contract_removed`; unknown keys raise `SigilGuard.ConfigError` with
reason `:unknown_config_key`. Both error messages name `MIGRATING-1.0.md`.

### Errors Without A Running Runtime

The replay, rate, and bundle tables belong to `SigilGuard.Runtime`. Releases
up to 1.0.5 created a missing table in whichever process asked first, and the
table vanished when that process exited. With `runtime: false` and no runtime
in the host's supervision tree, one confirmation token then verified from
several short-lived processes. The stateful functions no longer create
tables, and they fail closed when the runtime is not running:

| Call | Result without a runtime |
|------|--------------------------|
| `Confirmation.verify/5` (single use), `Attestation.verify/3` with `replay: true`, `ReplayStore.check_and_put/4` | `{:error, :replay_store_unavailable}` |
| `Policy.rate_check/2` with the default table | `{:error, :rate_limited}` |
| `TrustBundle.load/2` with caching, `TrustBundle.Cache.put/1` | `{:error, :cache_unavailable}` |
| `TrustBundle.Cache.get/1`, `floor/1`, `TrustBundle.verify/2` | as for an empty cache |

A host that sets `runtime: false` adds `SigilGuard.Runtime` to its own
supervision tree. Stateless verification (`consume: false`,
`TrustBundle.load/2` with `cache: false`) needs no table.

### Confirmation Tokens At The Model Phases

`Confirmation.issue/5` and `verify/5` returned `{:error, :invalid_payload}`
at `:inbound_user` and `:outbound_model`, where `Runtime.Gate` returns
confirm verdicts. They now bind the context digest under the statement type
`Attestation` uses for that phase (`model_ingress`, `model_egress`), from
`Attestation.Digest.phase_statement_type/1`. Tokens at `:tool_request`,
`:tool_result`, and `:repo_change` are byte-for-byte unchanged.

An attestation digest input of the shape `{:error, reason}` (for example a
`sandbox_id` taken from a failed lookup) is refused with `:invalid_payload`.
Releases up to 1.0.5 left it out, which attested "no sandbox".

### Redacted Results Keep Their Shape

A result the gateway releases with `action: :redact` keeps its `content`
items and `structuredContent`, with each string redacted in place.
Releases up to 1.0.5 replaced the content with one text item holding the
gate's scan projection: field names and values on separate lines. A
decision with output-contract transforms or quarantine indicators still
releases the gate's sanitized text.

### Switch Options

Boolean options are read one way. `true` and `false` behave as documented;
any other value, `nil` included, is the strict setting: on for a
requirement or protection, off for a relaxation. Releases up to 1.0.5 read
most switches by truthiness, so `nil` forwarded from an unset host setting
turned `:cache`, `:quarantine` and `:output_contracts` off, and `"true"`
left `require_manifest:` off. Pass booleans.

### Policy File Errors

`BoundaryPolicy.File.load/2` returns `{:error, :unreadable_policy}` for a
policy file that exists and cannot be read. Releases up to 1.0.5 returned
`{:error, :not_found}`, so a host that falls back to defaults when no policy
file exists also did so for a file it could not read.

### Confirmation Option Values

`Confirmation.verify/5` reads `consume:` as a boolean. `false` skips the
replay store, `true` or no option consumes the nonce, and any other value
returns `{:error, :invalid_consume}`. Releases up to 1.0.5 read the option by
truthiness, so a `nil` forwarded from an unset host option switched single
use off. The gateway's `consume_confirmation:` follows the same rule; a
gateway decision for another value is blocked with
`confirmation_reason: :invalid_consume`.

## Version Pinning

`~> 0.2` users do not auto-upgrade to 1.0. The 1.0 release is intentionally a
major-version break, so existing 0.2.x consumers stay on the `0.2.x` line until
they edit their dependency requirement.

For the 1.0 release line, use:

```elixir
{:sigil_guard, "~> 1.0"}
```

That requirement admits compatible `1.x` releases according to normal Hex
semver rules and remains separate from the `0.2.x` line.

## MCP JSON-RPC Rejection Codes

SigilGuard 1.0 moves MCP gateway rejection codes from the v0.2
`-32001..-32003` range to the application-defined `-31990..-31984` range,
outside JSON-RPC's reserved server-error band. An earlier 1.0 development draft
used `-32050..-32056`; those values are reserved by MCP `2026-07-28` and never
ship as the 1.0 contract. MCP v2 also treats `-32000..-32019` as a legacy range
where new codes should not be allocated.

| 0.2.x code | 1.0 code | Status |
|-----------|---------|--------|
| `-32001` | `-31990` | `blocked` |
| `-32002` | `-31989` | `confirmation_required` |
| `-32003` | `-31988` | `quarantined` |
| n/a | `-31987` | `manifest_drift` |
| n/a | `-31986` | `unknown_manifest` |
| n/a | `-31985` | `invalid_attestation` |
| n/a | `-31984` | `sandbox_required` |

Clients should key retry, approval, quarantine, manifest refresh, attestation,
and sandbox handling off `error.data.status` rather than the older three-code
bucket.

Three codes carry more in `error.data` than in releases up to 1.0.5:

- `-31985`: `attestation_error` names the check that failed, for example
  `"expired_attestation"`, `"digest_mismatch"`, or `"actor_mismatch"`. A
  statement that failed verification was reported as
  `"invalid_attestation"` before; a request with no envelope still is.
- `-31986`: an expired manifest adds `expires_at`.
- `-31987`: when the host passes the manifest entry as a
  `{pinned, observed}` pair, the denial adds `expected_manifest_digest` and
  `received_manifest_digest`, and `drifted_fields` lists the manifest
  preimage fields that differ, such as `"description_sha256"`. It held one
  class label such as `"manifest"` before, and still does for a drift
  denial without the pair.

A client that matched on `"invalid_attestation"` or on a class label in
these fields needs the new values.
`SigilGuard.CapabilityManifest.drifted_fields/2` returns the same field
names for two manifests.

## MCP v2 (`2026-07-28`)

### Structured Action Binding

`ToolGateway`, its MCP facade, confirmation tokens, and gateway attestations
now bind a canonical structured projection. The projection retains method,
parameter names, nested maps/lists, numbers, booleans, nulls, MRTR
`inputResponses`, and `requestState`. It excludes JSON-RPC correlation fields
(`id`, `request_id`, and `jsonrpc`), fixed SigilGuard metadata, and operational
progress, logging, subscription, and trace metadata. Client capabilities and
unknown extension metadata remain bound because they may alter behavior. The
protocol revision is extracted and bound separately.

This deliberately invalidates tokens, action digests, and attestation vectors
created by the earlier string-flattening draft. Pass the original raw MCP
request or result to `ToolGateway.issue_confirmation/5`,
`attest_request/3`, and `attest_result/3`; the helpers apply the shared
projection. Do not pre-flatten payloads into `tool`/`action`/`text` maps.

The `action` subject of a gateway `tool_request` attestation covers the tool
name, the request method, and the arguments. It is the digest the raw MCP
message gives. Releases up to 1.0.5 computed it from the statement type and
the tool name, so every call to one tool had the same action digest and a
result attestation could be paired with any call of that tool. An
attestation signed by such a release fails digest recomputation:
`Attestation.verify/3` returns `{:error, :digest_mismatch}`, and
`guard_request/3` with `attestation: :required` blocks the request with
`:invalid_attestation`. The `request_action_digest` a result names changes
with it. Upgrade both sides of a gateway together and sign again.

`ToolGateway.attest_request/3` and `attest_result/3` write the statement for
the boundary the guard function evaluated: the origin, sink, tool, and
server the gateway reads from the message fill what the host context leaves
unset. Releases up to 1.0.5 digested the host context as given, so a
gateway refused its own attestation unless the host context spelled out the
origin, the sink, and the tool, and the statement described another
boundary than the decision. A host context that names those fields gives
the same context digest as before. One that does not gives a different one:
verify such a statement through `guard_request/3`, or pass
`SigilGuard.MCP.SecurityPayload.context(request, :request, context)` as
`context:` to `Attestation.verify/3`.

### Protocol Version And Results

SigilGuard remains transport-neutral and does not negotiate MCP. Adapters may
pass `protocol_version: "2026-07-28"` to guarded response helpers, or leave the
standard version value in request `_meta`. MCP v2 requests also require
client-capabilities metadata, which the host must supply and validate.
Malformed or missing required metadata uses JSON-RPC `-32602`; the host uses
MCP `-32021` for a required capability the client did not declare and `-32022`
for an unsupported protocol revision. These are protocol errors, not SigilGuard
policy denials.
Successful v2 responses add `resultType: "complete"` when absent and preserve
any existing discriminator, including malformed or extension values, for the
host validator to reject or interpret. Earlier responses retain their prior
shape, and unknown future revisions are not silently treated as v2.

Every MRTR retry is a new guarded action. Forward the retry's new request,
`inputResponses`, and opaque `requestState` through the gateway; never treat
state from the server as authorization.

### Capability Manifest v2

Regenerate every pinned manifest with
`manifest_format: "sigil_guard_capability_manifest/v2"`. The new digest
preimage additionally binds:

- optional `title` and canonical `icons`;
- normalized UI metadata with a `ui://` `resource_uri` and sorted
  `visibility`;
- the complete `input_schema`, including validated `x-mcp-header`
  annotations.

Icon entries are closed maps. Sources must use HTTPS or a valid image data URL;
optional MIME types must be `image/*`, sizes are `any` or positive `WxH`
tokens, and themes are `light` or `dark`. The host still owns image fetching,
same-origin and redirect enforcement, credential omission, content sniffing,
decoding, byte and dimension limits, and renderer safety.

An `x-mcp-header` annotation is valid only on a primitive `boolean`, `integer`,
or `string` field that is statically reachable through a chain consisting
solely of JSON Schema `properties`. Header names must use HTTP token
characters and be unique case-insensitively; sensitive parameter names are
rejected. SigilGuard does not emit MCP `HeaderMismatch` (`-32020`): header
construction and mismatch handling remain the host transport adapter's
responsibility.

Manifest v1 documents fail closed. Tool listings must supply display/UI fields
when the pinned v2 manifest contains them; changing those fields is manifest
drift and invalidates approvals.

`ToolGateway.attest_result/3` writes the output schema digest of the
`manifest:` struct it is given, when that manifest declares one. An
`output_schema_sha256:` option that differs from that digest returns
`{:error, :schema_digest_mismatch}` and nothing is signed; `attest_request/3`
applies the same comparison. Releases up to 1.0.5 wrote the option as given.
Pass the manifest's value or omit the option.

### MCP Apps

Use `origin: :app` with a trusted `mcp_server` for calls originating in an MCP
App. App calls are accepted only for app-visible tools on that same server.
Every other origin is held to the tool's model visibility, so a caller that
is not an App is denied an app-only tool.

Call `SigilGuard.MCP.AppResource.verify/2` on the direct `resources/read`
content before handing bytes to a renderer. Pin `expected_sha256` and allow
only reviewed CSP origins, dedicated app domains, and browser permissions.
Both MCP Apps `text` and Base64 `blob` resources are supported. Content is
limited to 1 MiB by default; use `:max_bytes` only for a reviewed renderer
limit. Options are closed and duplicate keys fail. Dedicated app domains use a
host-defined format and therefore require an exact `:allowed_app_domains`
match.

The stable Apps extension predates MCP v2 examples. The host maps the
negotiated UI extension capability into v2 per-request metadata and discovery;
SigilGuard consumes only the resulting app origin, server, visibility, and
resource metadata. The host still owns resource fetching, HTML5 validation,
iframe origins and sandboxing, CSP and Permissions Policy enforcement,
authorization, and rendering.

## Decision Struct And The Unified Verdict

The runtime gate now evaluates through `SigilGuard.BoundaryPolicy`, and
`%SigilGuard.Decision{}` carries the unified verdict enum on `:action`:

- **`:action` is the unified verdict** `:allow | :redact | :confirm | :quarantine
  | :block`. A confirming decision's `:action` is `:confirm`; the executable
  action to run after confirmation moves to the new `:effect` field
  (`:allow | :redact | :quarantine | nil`). Code that read `decision.action` to
  decide what to execute after a confirmation must read `decision.effect`. In
  particular, a `tool_result` prompt-injection decision that used to report
  `action: :quarantine` now reports `action: :confirm, effect: :quarantine`.
- **`:verdict`**, the legacy dual vocabulary
  (`:allowed | :blocked | {:confirm, reason}`), is still populated for
  compatibility.
- **New fields**: `matched_rules` (`[%{rule_id, explanation}]`), `evidence_refs`,
  `effect`, and the boundary labels `source`, `sink`, `trust_zone`, `actor`,
  `resource`. The `:require_approval` repo action is closed to `:confirm`.
- **Facades remain unchanged**: `SigilGuard.scan/1`, `scan_and_redact/1`, and
  `policy_verdict/3` return shapes are byte-identical; hit maps gained additive
  optional keys only.
- **Sandbox matrix** applies in the gate only when the context declares an
  `isolation_level` (opt-in by presence); it does not auto-quarantine tool
  calls that declare none. `ToolGateway.guard_request/3` selects the matrix
  row from the side effects of the pinned manifest. `guard_result/3` does
  the same when the host context names a tool that has a pinned manifest;
  releases up to 1.0.5 used the `execute` row for every result, so a result
  of a tool that declares only `read` no longer needs confirmation at
  `:container`. Without a pinned manifest the row is `execute`, and a result
  is never blocked for lacking one.
- The confirmation token's informational `"action"` claim now records the
  unified action (`"confirm"` for confirming decisions); the token's
  cryptographic binding is unchanged.

## Audit hardening of v3 acceptance

The security audit preserves signed v3 byte contracts while narrowing unsafe
acceptance paths. Application null-valued map fields now fail `:invalid_payload`
instead of colliding with absent fields. Nullable profile fields and null array
elements keep their defined meanings. MCP key scanning uses a separate scan view
so existing confirmation preimages do not acquire scanner-generated keys.

Root rotations that introduce delegate authority require the new root quorum to
countersign the successor envelope. Existing frozen payload bytes remain valid;
append root signatures with `SigilGuard.Attestation.Envelope.add_signature/3`.
Unsigned authority changes, expired or revoked issuers, and stale replay claims
fail closed. Review the [strict deployment guide](guides/strict-deployment.md)
for work limits, explicit bundle scanner selection and streaming retention.

## Boundary validation corrections

Unambiguous v1 audit bytes and Agent Trust payload bytes are unchanged. JSON
objects with duplicate decoded keys (including escaped aliases), envelopes with
atom/string aliases of the same field, and audit maps whose keys collide after
normalization are rejected. Supply each object member exactly once. Native
JSON booleans, nulls, arrays, integers and floats retain their existing meaning.

Envelope signing rejects duplicate key IDs with `:duplicate_keyid` and
verifier-capacity overflow with `:invalid_envelope`. Keep multisignatures
within 64 entries and the existing envelope input budget. Cosigning an
atom-keyed envelope replaces its signature field without retaining an alias.

Checkpoint constructors now return checked errors for malformed events and
metadata that cannot be serialized as unambiguous JSON. Valid native JSON
values retain their types. Export verification checks the entire embedded
checkpoint statement, inclusion tree size, and every supplied consistency
proof. Witness cosigning validates the current statement and binds the prior
and current chain IDs and tree sizes to the consistency proof. These are
consistency checks; hosts still authenticate operator keys and persist prior
witness state themselves. Optional evidence remains optional.

Local anchor stores apply `:max_line_bytes` to the complete encoded entry on
both writes and reads. Oversized writes return `:log_line_too_large` before
creating or appending a file. Receipt URIs now escape reserved filename
characters. Anchor versions and copied checkpoint identities use exact types.
Trust-bundle file and priv reads stop after the existing 1 MiB budget plus one
sentinel byte; rejected loads preserve the last valid cached bundle.

`Vault.InMemory.encrypt/2` returns `:invalid_plaintext` or
`:invalid_description` for malformed arguments without losing existing entries.
Plaintext remains arbitrary binary data; descriptions are UTF-8 strings.

`Runtime.Stream.new/2` now raises a deliberate `ArgumentError` for malformed
option containers or uncompiled patterns instead of failing later with a field
access error. Invalid window values still select the conservative default.

Integration examples now preserve the original structured value on `:allow`
and refuse `:redact` until the host supplies a validated schema-specific
transformation. Update copied Hermes/Jido/LangChain/ReqLLM examples, including
`Jido.Exec.run/3` and ReqLLM's `:parameter_schema` option. The Hermes notebook
follows the same contract. The former Tidewave Plug wrapper was unusable with
Tidewave 0.6.1's body-parsing contract and has been removed from the guide;
only the tested authorization helper is provided, with transport adaptation
explicitly left to the host.

Envelope key checks also reject numeric/string and character-list/string
collisions after JSON key normalization, including extension fields. Malformed Unicode keys produce checked errors at envelope and audit storage
boundaries. Unique serializable keys keep their existing behavior.
