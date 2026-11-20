# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## Unreleased

- The HTTP anchor store judges an IPv6 receipt host that embeds an IPv4
  address (IPv4-mapped, IPv4-compatible, NAT64 `64:ff9b::/96`, 6to4
  `2002::/16`) by that address, and refuses multicast, broadcast, reserved
  and site-local addresses. `[::ffff:127.0.0.1]` and
  `[::ffff:169.254.169.254]` reached the HTTP client.
- `SigilGuard.BoundaryPolicy.evaluate/2` blocks a `:policy` that is neither
  nil nor a map as malformed options. It matched no rule and contributed no
  default, so the boundary was decided as if no policy were loaded.
- Repository policy patterns are checked after backslashes become slashes,
  so `..\\secrets` is refused as a traversal; a drive-letter prefix such as
  `C:` counts as an absolute path.
- A refused confirmation token through `SigilGuard.ToolGateway.Base` records
  `deny_reason: :confirmation_failed`, as through `SigilGuard.ToolGateway`;
  both now block with the reason "Confirmation verification failed".
- A redacted result released by `ToolGateway.guarded_result/3` and the
  `MCP.Gateway` result helpers keeps its original shape: each string in
  `content` and `structuredContent` is redacted in place. It was released as
  the gate's scan projection, one text item listing field names such as
  `kind`, `method` and `protocol_version` beside the redacted values.
- The repository tasks `mix sigil.docs_lint`, `mix sigil.livebook_check` and
  `mix sigil.migration_gate` are now `mix sigil_guard.docs_lint`,
  `mix sigil_guard.livebook_check` and `mix sigil_guard.migration_gate`, in
  the package's own namespace, so they cannot clash with a package named
  `sigil` in a host project.
- Switch options are read one way everywhere. A boolean is taken as
  given; any other value, `nil` included, is the strict setting: on for a
  requirement or protection (`:require_manifest`, `:require_worm`,
  `:require_receipt_signature`, `:require_signature`, `:require_anchor`,
  `:require_peer_card`, `:replay`, `:cache`, `:quarantine`,
  `:output_contracts`, `:strict_quarantine`, `:enforce_declared_threshold`),
  off for a relaxation (`:allow_private_receipt_url`,
  `:allow_suspicious_params`, `:include_sanitized`). Before, the same
  malformed value was on in one function, off in another, and raised in a
  third; `:require_receipt_signature` was read two ways in one module.
- `SigilGuard.Runtime.Gate.evaluate/3` checks `:indicator_sets` with the new
  `SigilGuard.Quarantine.valid_indicator_sets?/1` and blocks a malformed
  value as malformed options. It used to rescue the exception from the
  quarantine inspector and block with `scanner_error: :scanner_failed`.
- Add `SigilGuard.Scanner.scan_result/2`, which returns `{:error, reason}`
  where `scan/2` raises. The gate and output contracts use it instead of
  rescuing every exception around the scanner.
- `SigilGuard.Scanner` is a behaviour with one callback, `scan/3`, for
  `:pipeline` modules; `SigilGuard.Scanner.Pipeline` implements it.
- Add `SigilGuard.TrustBundle.Cache.fetch/1`. `get/1` returns the same
  result and is marked deprecated in the documentation, since a `get`
  returns a value or a default.
- The behaviour implementations hosts call directly (`Vault.InMemory`,
  `Signer.Ed25519`, both anchor stores, `Backend.Elixir`) have documentation
  and specs.
- `SigilGuard.BoundaryPolicy.File.load/2` returns `{:error, :unreadable_policy}`
  for a policy file that exists and cannot be read. It returned `:not_found`,
  the answer for no policy file.
- The HTTP anchor store refuses a `:max_body_bytes` that is not a
  non-negative integer with `{:error, :invalid_options}`. It used the 1 MiB
  default.
- `mix sigil_guard.sbom` lists a dependency whose `:only` option has an
  unexpected shape, and stops on a `mix.lock` dependency entry it cannot
  read. Both were left out of the document without a message.
- `SigilGuard.Confirmation.issue/5` and `verify/5` work at the `:inbound_user`
  and `:outbound_model` phases. The gate returns confirm verdicts there, and
  no token could be issued for them. Tokens at the other phases are unchanged.
- A pattern that can match the empty string (`z*`) no longer makes the gate,
  the stream and `scan_and_redact/2` raise. A match of no bytes is not a hit.
- `SigilGuard.TrustBundle.verify/2` and `load/2` return an error for a
  rotation chain entry that is not a map and for a `:genesis_root` that lists
  a key id without a key. Both raised.
- The HTTP anchor store refuses a receipt URL whose host is not valid UTF-8
  with `:unsafe_receipt_url`. It raised.
- A context or payload value of the shape `{:error, reason}` is refused by
  the attestation digests like any other tuple. It was left out of the
  digest, so a failed sandbox lookup was attested as no sandbox.
- A suspicious-parameter confirmation over a request whose action digest
  cannot be computed is a block, as on the gate's own confirm path.
- The replay, rate and bundle tables are created by `SigilGuard.Runtime`
  only. A stateful call used to create a missing table in the calling
  process, where it vanished with that process: without a running runtime
  one confirmation token verified from several processes. Those calls now
  fail closed (`:replay_store_unavailable`, `:rate_limited`,
  `:cache_unavailable`), and readers of the bundle cache see it as empty.
- `SigilGuard.Confirmation.verify/5` accepts `consume: true | false` and
  returns `{:error, :invalid_consume}` for anything else. A `nil` switched
  single use off.
- `SigilGuard.BoundaryPolicy.File.parse/1` no longer raises on a `redact`
  or `quarantine` rule in a VM that has not loaded another module using
  those atoms. Decision names, matcher fields and context keys are resolved
  through closed lookups, and the gateway finds an atom-keyed manifest
  without turning the tool name into an atom.
- `SigilGuard.Audit.Export.create/2` checks for `:issuer` before it calls
  the signer. A `KeyError` raised inside a host signer was reported as
  `:missing_issuer`.
- A hook or adaptive detector callback now stops when its caller does. It
  ran in an unlinked process that only the caller could stop.
- Add `SigilGuard.Patterns.compile_all/1`, which refuses a list with an
  entry that does not compile. `compile/1` drops such entries, and its
  documentation says so.
- Add `SigilGuard.Runtime.attestation_options/1` and `trust_mappings/1`, and
  `SigilGuard.Identity.Static.trust_level/2`. Values given to the runtime as
  explicit `config:` were validated and then not used by `Attestation` and
  `Identity.Static`, which read the application environment; these functions
  hand them to those calls.
- Credo runs 102 checks over `lib/`, `test/`, `bench/`, `bin/`, `config/`,
  `mix.exs` and the tool configuration files.
- `SigilGuard.ToolGateway.attest_request/3` and `attest_result/3` write the
  statement for the boundary the guard function evaluated. They digested the
  host context as given, so the gateway refused its own attestation unless
  that context named the origin, sink and tool, and the statement described
  another boundary than the decision.
- `SigilGuard.Attestation.from_decision/3` writes `resource.audience` as a
  string when it comes from the context. It was an atom in the returned
  map and a string in the signed bytes.
- Benchmarks are ten suites, one per area, each with a report in the
  documentation: scanner, gate, stream, gateway, confirmation, attestation,
  trust bundle, agent trust, audit and primitives (BM.01 to BM.31).
  `mix bench.<suite>` runs one. A smoke run writes under
  `bench/output/smoke/` and no longer replaces the published reports. Each
  suite checks its fixtures before timing; that check found the earlier
  BM.05 verification timing an expired statement.
- `SigilGuard.ToolGateway.guard_result/3` takes the manifest of the tool
  the host context names and never of a tool the result names. A result is
  the tool's own output, and a name inside it could otherwise select a
  manifest with a milder sandbox class.
- `guard_request/3` verifies a confirmation token with exact manifest
  binding whatever phase the host context states, and discards a
  `:manifest_binding` option from the caller.
- The inbound attestation actor check treats an empty `actor` as unset and
  uses the `identity`, as the attest helpers do.
- The MCP event of an accepted confirmation carries no `deny_reason`. The
  audit metadata keeps the reason the confirmation was asked for.
- `:decision_id` is 1 to 128 visible ASCII characters, and every decision
  of a call carries it, including a gateway denial made before the gate ran
  and a refusal of malformed input. Those two also carry `sandbox_id`.
- A drift denial reports digests and fields only when the two manifests
  differ.
- The publish workflow's build job runs the structural SBOM check without a
  digest it computed from the same file.
- `SigilGuard.ToolGateway.attest_request/3` and `attest_result/3` return
  `{:error, :schema_digest_mismatch}` when `:output_schema_sha256` differs
  from the digest the `:manifest` declares. The caller's value was written
  as given before.
- A gateway denial for a manifest that drifted from its pin carries
  `expected_manifest_digest`, `received_manifest_digest` and the preimage
  fields that differ in `drifted_fields`, in the decision's audit metadata
  and in the JSON-RPC error data. `drifted_fields` named a class such as
  `manifest` or `schema` before.
- `SigilGuard.AgentTrust.verify_agent_response/3` takes `:capability`,
  `:audience` and `:context`, checks that the peer's card declares the
  response's capability, refuses a `:payload` that is not a map instead of
  skipping the digest check, and accepts a trust bundle as key material when
  no peer card is given.
- The agent attest helpers take `:audience` and write it as
  `resource.audience`, so a response can be bound to its requester and a
  request to its responder.
- An `agent_response` statement has `quarantined: true` when the decision's
  action or effect is `:quarantine` or it carries quarantine indicators,
  whatever the verdict. It was `true` only for `action: :quarantine`, which a
  gate decision never has, so a gate-blocked or gate-confirmed injection was
  attested as not quarantined.
- Add `SigilGuard.AgentTrust.peer_trust_zone/1`: the zone of a verified
  card, `:untrusted` without one.
- Every statement from `SigilGuard.Attestation.from_decision/3` carries the
  `boundary` mirror: phase, origin, sink, trust zone and intended audience,
  and source, sandbox id and isolation level when set, with the values that
  enter the context digest. Only `tool_result` had it, with `sink` alone.
- The `[:sigil_guard, :agent_trust, :attest | :verify, :stop]` events carry
  `statement_type`.
- The `action` subject of a gateway statement reads the method, tool and
  arguments from the message the gate payload stands for, in its JSON-RPC
  shape. Reading the params object in place let a member of that object
  named `params` or `method` be taken for the message's own, so a request
  could carry decoy arguments into the action digest. A result object's
  `method` member no longer enters it either. A gate payload whose tool or
  action is null is read the same way.
- `SigilGuard.Attestation.from_decision/3` and `sign/3` write timestamps
  with three fractional digits whatever the precision of `:now`. `sign/3`
  writes its `:nonce` option only when it is a string, so `nonce: false`
  means the same to both functions; the `SigilGuard.AgentTrust` helpers
  forward `nonce: nil` instead of dropping it.
- `SigilGuard.Decision.evidence_refs` holds `SigilGuard.Audit.Evidence`
  references, and `from_decision/3` checks them as it checks the `:evidence`
  option (`:invalid_evidence`).
- The benchmark harness checks each fixture before timing it and stops when
  a fixture takes another path than its scenario names. Two did: the BM.04
  stream halted at its first secret and timed one evaluation, and the BM.03
  quarantine fixture was blocked. Both now measure what they are named for,
  and numbers from earlier runs are not comparable for those rows.
- Benchmark fixtures the methodology names: a hit in the 1 KiB corpus, a
  secret split across a chunk boundary, a bundle with two delegations and
  ten patterns, and an audit chain with fixed ids and timestamps. The report
  adds the stream's per-chunk median and its overhead over a single pass,
  the gateway overhead over the no-op control, and the memory size of the
  machine.
- `SigilGuard.Runtime.Gate.evaluate/3` takes `:decision_id`, a correlation id
  the host chooses. It reaches `audit_metadata`, the gate event and the
  opt-in attribute `sigilguard.decision.id`. The gate generates none.
- Telemetry carries more of what a decision already knows. The MCP request
  event has `deny_reason`, `manifest_digest`, `manifest_name`,
  `request_action_digest` and `quarantine_status`; the gate event has
  `sandbox_id` and `matched_rule_ids`; the audit event has `event_id`. The
  attribute mapper adds `sigilguard.deny_reason`, `sigilguard.manifest.name`,
  `sigilguard.quarantine.status` and `sigilguard.rules.matched`, and the
  opt-in `sigilguard.manifest.digest`, `sigilguard.policy.digest`,
  `sigilguard.request.action.digest`, `sigilguard.sandbox.id` and
  `sigilguard.audit.event_id`.
- A gateway denial for an attestation says which check failed
  (`attestation_error`, for example `expired_attestation` or
  `digest_mismatch`), and a denial for an expired manifest carries
  `expires_at`. Both were collapsed before.
- Add `SigilGuard.CapabilityManifest.drifted_fields/2`, which names the
  preimage fields in which an observed manifest differs from the pinned one.
- `SigilGuard.Confirmation` applies the metadata strip rule to the payload it
  digests, so a token attached to the request it confirms verifies in a
  direct `verify/5` call. Only the gateways stripped it before.
- `SigilGuard.ToolGateway.guard_result/3` resolves the pinned manifest for
  the tool the context names. The sandbox matrix then uses its declared
  classes for the result, the decision carries the manifest digest and name,
  and a result confirmation token may bind the manifest. A token issued
  without one still verifies (`manifest_binding: :when_claimed` in
  `SigilGuard.Confirmation.verify/5`). A result is never blocked for lacking
  a manifest.
- With an inbound attestation, `SigilGuard.ToolGateway.guard_request/3`
  requires the statement's actor to be the actor or identity of the host
  context, and denies `:invalid_attestation` otherwise.
- **Behaviour change.** The `action` subject of a `tool_request` or
  `tool_result` attestation built by `SigilGuard.ToolGateway` binds the
  request method and arguments. The gateway digests a wrapped payload, and the
  action preimage read only the tool name from it, so every call to one tool
  had the same action digest and a result's `request_action_digest` did not
  identify the call. Both sides of a gateway must run this version: an
  attestation signed before the upgrade fails verification after it.
- `SigilGuard.Attestation.from_decision/3` generates a 16-byte hex nonce
  unless `:nonce` is given (`nonce: false` omits it), writes timestamps with
  millisecond precision, copies the decision's matched rules and evidence
  references into the predicate, attests a confirmed release of a quarantined
  result as `released_sanitized`, and accepts a binary or list payload for
  statement types that need no map.
- `SigilGuard.Attestation.sign/3` and `SigilGuard.TrustProfile.validate/1`
  refuse a statement without an actor id, a verdict, or a lifetime that
  starts before it ends (`:invalid_payload`). `sign/3` gives a statement
  with `issued_at` and no `expires_at` the lifetime from `:ttl_ms`.
- `SigilGuard.Attestation.verify/3` accepts a verified
  `%SigilGuard.TrustBundle{}` as trust material. The signing keys are those of
  the bundle's delegate role named `"attestation"`, less revoked keys, under
  the role's threshold and expiry. A signature from a revoked key or from a
  key of another role returns the new error `:untrusted_issuer`. A bundle
  passed here used to resolve no key at all.
- `SigilGuard.Attestation.verify/3` honours `require_manifest: true`: the
  statement must carry a `manifest` subject equal to the supplied `:manifest`
  or `:manifest_digest`.
- **Behaviour change.** `SigilGuard.TrustBundle.verify/2`, and `load/2` with
  `cache: false`, refuse a bundle below the state already accepted in this
  boot: a sequence at or below the cached snapshot's, a sequence below the
  floor, a revoked signing key or a forked authority returns the error
  `SigilGuard.TrustBundle.Cache.put/1` would. Only a cached load checked this.
  `Cache.check/1` is the read-only form.
- A rotation document's `rollback_floor` is enforced. Within a chain each
  rotation's floor must exceed the one before it, and a bundle's `sequence`
  must not be below the floor of the last rotation in its chain. Both fail
  with `:sequence_below_floor`. The field was checked for format only.
- **Behaviour change.** `SigilGuard.Runtime.Gate` applies the `[contracts]`
  section of a boundary policy file passed as `:boundary_policy`. For the
  context sink it checks the content class and, on a text payload, re-scans
  the released text for secrets, digests PII hits and truncates to
  `max_size`. Transformed text is released as a `redact`; a disallowed class
  blocks. The section was parsed and ignored. `output_contracts: false`
  restores the old behaviour, and stream windows are exempt.
- Add `SigilGuard.Patterns.secret_category?/1`. A hit of category
  `credential` now counts as a secret for the kernel's external-sink rule.
- The decision that ends a `SigilGuard.Runtime.Stream` carries
  `stream_input_sha256`, `stream_emitted_sha256` and their byte counts in its
  audit metadata, and a halt the stream decides sets `deny_reason`
  (`:stream_holdback_overflow`, `:invalid_utf8`, `:incomplete_utf8`). The
  struct now holds two hash states, so two streams no longer compare equal.
- Advisory signals from `:hooks` and `:adaptive_detector` reach the decision
  `SigilGuard.Runtime.Gate` returns. Their indicators follow the quarantine
  indicators in `decision.indicators`, a risk they raise above the gate's own
  becomes `decision.risk_level` and goes back through the risk and trust
  ladder, and `audit_metadata` gains `advisory_indicator_count` and
  `adaptive_error`. The gate dropped all of these.
- A boundary policy `sensitivity:` rule matches through the gate: the host
  states `source_sensitivity` (`:public`, `:internal` or `:private`) in
  `context.metadata`.
- At a repo change `SigilGuard.Runtime.Gate` passes the repo policy facts to
  the policy kernel, so a decision lists the repo rules that produced it as
  `repo.<rule_id>` and its audit metadata carries `repo_policy_digest` and
  `repo_policy_default`.
- **Behaviour change.** The `[repo]` section of a boundary policy file passed
  as `:boundary_policy` is now evaluated at a repo change when no
  `:repo_policy` option is given. It was parsed and ignored.
- `SigilGuard.RepoPolicy.load/2` and `find_file/2` check `:candidates` and
  `:max_bytes` before reading the filesystem. A malformed `:max_bytes` on a
  directory without a policy file returned `:not_found`.
- Add `SigilGuard.Identity.spiffe_id?/1`, which checks the SPIFFE-ID syntax,
  and `SigilGuard.Identity.did_key_public_key/1`, which returns the Ed25519
  key an identifier of the `did:key` method embeds. Neither is applied by the
  library: actor and issuer strings stay opaque.
- `SigilGuard.Vault.InMemory` returns `{:error, :vault_unavailable}` from
  `encrypt/2`, `decrypt/1` and `delete/1` when its process is not running.
  `exists?/1` returns `false` and `list_entries/0` returns `[]`. The caller
  used to exit.
- `SigilGuard.Backend.impl/0` returns the native backend and raises
  `SigilGuard.ConfigError` when the removed `:backend` application key is set.
  It still read that key and dispatched `scan/2`, `redact/3`,
  `scan_and_redact/2` and `policy_verdict/3` to a configured module, which
  `SigilGuard.Config` and the migration guide treat as removed in 1.0.
- **Security.** In `SigilGuard.Runtime.Gate`, a repo policy `require_approval`
  verdict was checked before quarantine and scanner hits and returned first.
  A repo change that carried a detected secret or a high-severity injection
  indicator was blocked without a repo policy and became a confirm decision
  with `effect: :allow` once a rule asked for approval. The gate's own signals
  now combine by verdict strength, the reported risk is the highest any signal
  gives, and an approval that wins over a redaction keeps `effect: :redact`.
- `SigilGuard.ToolGateway.guard_result/3` drops a caller-supplied
  `:manifest_facts`, as `guard_request/3` does.
- `SigilGuard.ToolGateway.guarded_result/3` builds a redacted response from the
  original result, so an existing `resultType` such as `input_required`
  survives redaction. It was replaced by the default.
- A `tool_result` attestation built from a decision lists the built-in
  quarantine indicators that fired. `predicate.quarantine.indicator_ids` kept
  only string ids, and the built-in ids are atoms, so it was always empty.
- `SigilGuard.ToolGateway.guard_request/3` reads the sandbox id and isolation
  level from `Context.sandbox_id` and `Context.isolation_level`, the fields the
  context digest binds, and falls back to `context.metadata`. A context that
  set only the fields was denied `:sandbox_required`.
- The gateway passes a pinned manifest's digest and side effects to the gate,
  so the SP.04 sandbox matrix and `effect:` policy rules use the classes the
  manifest declares. Without a pinned manifest a tool is still class `execute`.
  `SigilGuard.Runtime.Gate.evaluate/3` accepts the same facts as
  `:manifest_facts`. An `effect:` rule compares classes: `delete` is `write`,
  `privileged` is `execute`, and an unknown side effect is `execute`.
- Quarantine indicators carry a `:category` (`:injection` or `:poisoning`, the
  set that supplied them). A boundary policy `indicator:` matcher compares that
  value, so it never matched an indicator the library produced: through
  `SigilGuard.Runtime.Gate`, `indicator:injection`, `indicator:poisoning` and
  `indicator:any` rules were dead and `indicator:none` always matched. They
  now behave as SP.04 describes.
- **Security.** The token-passthrough check (`:token_passthrough_denied`, an
  `:audience` that names `:self_resource`) ran only when a capability manifest
  resolved. `SigilGuard.ToolGateway.guard_request/3` now applies it to every
  request, with or without a manifest.
- **Security.** A tool whose manifest pins `ui.visibility: ["app"]` was
  reachable by any caller origin except `:model`: `:user`, `:tool`,
  `:resource`, `:repo`, `:registry` and an explicit `:unknown` skipped the
  visibility check. Every origin other than `:app` is now held to the tool's
  model visibility and gets `:app_visibility_denied` (SP.16).
- **Security.** `SigilGuard.RepoPolicy.evaluate/2` returned `:require_approval`
  for a change that touched an unmatched path under `default block` whenever
  another path matched a `require_approval` rule. The default now competes by
  rank for every unmatched path, so that change is `:block`, as SP.11 states.
  Decision reasons name the rule or the default that produced the verdict.
- **Security.** `SigilGuard.ToolGateway.guard_result/3` released a result
  unredacted after a confirmation token was accepted. A result that carried a
  detected secret from a caller below the required trust level got a confirm
  decision with `effect: :redact`; acceptance set the action to `:allow`, and
  `guarded_result/3` returned the original result. Acceptance now runs the
  decision's `effect`, as `SigilGuard.MCP.Gateway` already did and SP.07
  requires, so the released result is the sanitized one.
- Add `SigilGuard.EffectAuthority` and the `:effect_binding` option of
  `SigilGuard.ToolGateway.guard_request/3` for tool requests that change the
  physical world (SP.19). A request carries a closed binding record under
  `params._meta["dev.sigilguard/effect"]`; `admit/5` compares it with facts
  the host reads immediately before dispatch and refuses with a named reason.
  Effect envelopes bound a set of operations, targets and integer arguments.
  `classify_outcome/1` keeps a signed report apart from observed acceptance.
  The option defaults to `:off` and changes no existing decision, digest,
  telemetry metadata or wire shape. See `guides/physical-effects.md`.
- Add `SigilGuard.MCP.SecurityPayload.context/3`, the boundary context both
  gateways evaluate and digest.
- Encode JCS strings that need no escaping with a byte scan instead of a
  per-codepoint pass. Canonical bytes are unchanged.
- Build the gateway projection and context once per request or result, compute
  the gate's action digest once, and read the clock and application env in
  `SigilGuard.Attestation` only when the caller supplies no value.
- **Behaviour change.** `SigilGuard.Telemetry.otel_attributes/4` and
  `attach_otel_forwarder/3` no longer export the actor, identity, or
  confirmation actor in clear. `sigilguard.actor.hash`,
  `sigilguard.identity.hash`, and `sigilguard.confirmation.actor.hash` carried
  the raw value; SP.05 classifies them as hashed. Pass `field_hash_key:` to
  export `SigilGuard.Audit.hash_field/2` of the value. Without a usable key the
  attribute is `"redacted-v1"`. The attributes remain behind
  `include_high_cardinality: true`.
- `SigilGuard.Audit.classify/2` treats an actor as already hashed only when it
  is `fh1:` plus 64 lowercase hexadecimal characters. A value that merely
  starts with `fh1:` was stored unchanged and is now hashed.
- `mix sigil.docs_lint` reports a test module that a spec table cites and
  `test/` does not define.
- Answer malformed input without raising across the public entry points. A
  context that is not a map or keyword list, a foreign struct or an improper
  list in a request, result, boundary or payload, a non-map `metadata`, a
  non-integer `:max_skew_ms`, malformed `:indicator_sets`, a trust bundle
  document whose `roles` is not a map, a non-map envelope or key set in
  `SigilGuard.Audit.Witness.verify_threshold/3`, a repo-policy context or rule
  that is not a map or keyword list, invalid UTF-8 in a repo-policy agent,
  action or path, and non-keyword options to `SigilGuard.AgentTrust` each
  raised; they now return an error tuple or a blocked decision. `SigilGuard.Context.cast/1` is the total
  counterpart of `new/1`.
- Fix two gateway crashes. `ToolGateway.guard_request/3` and `guard_result/3`
  raised `FunctionClauseError` for a non-map request or result that reached a
  `confirm` verdict, and `response_for_decision/3` raised `ArgumentError` when
  a bundle-supplied indicator with a string id fired. Both now return a
  decision or a JSON-RPC error.
- Reject a SHA-256 digest followed by a newline. `Boundary.validate/1`, the
  `:request_action_digest`, `:manifest_digest`, `:output_schema_sha256` and
  `:card_digest` options, and release artifact digests accepted one.
- Fix a policy bypass in the runtime gate. A payload whose digest could not be
  computed (a `null` map value, an integer outside the JCS range, or invalid
  UTF-8) made the gate skip `BoundaryPolicy.evaluate/2`, so a policy-file rule
  that blocked the request did not apply. The kernel now always runs, and a
  Boundary it rejects blocks.
- Update Cowboy to 2.20.0, Cowlib to 2.21.0, Decimal to 3.2.0 and Req to
  0.7.5, and refresh pinned GitHub Actions.
- Update the optional live AI notebook's ReqLLM pin to 1.28.0.
- Remove the resolved Cowlib cookie/header advisory exceptions. Retain only
  CVE-2026-43966 for the test-only structured-header encoder, which is absent
  from the production archive.
- Update Cowboy to 2.21.0, Cowlib to 2.22.0, Plug to 1.20.4 and Telemetry to
  1.4.3. The update clears three new advisories on the test-only HTTP stack
  and resolves CVE-2026-43966, so the last advisory exception is removed.

## Unreleased Breaking Changes For 1.0.0

SigilGuard 1.0 is a deliberate breaking release. Apply
[`MIGRATING-1.0.md`](MIGRATING-1.0.md) before moving a 0.2.x consumer to the
1.0 line.

- Hardened trust-bundle authority transitions, concurrent rollback floors and
  cumulative revocations. Successors changing delegated authority require the
  new root quorum to countersign; revoked or expired card issuers fail closed.
- Fixed cold security modules, actor/tool policy facts, MCP object-key scanning,
  full replay retention, atomic rate quotas and bounded untrusted work/state.
- Rejected ambiguous null-valued application map fields while preserving v3
  signed bytes. See the [audit acceptance changes](MIGRATING-1.0.md#audit-hardening-of-v3-acceptance).
- Fixed overlapping redaction, unbounded streaming candidates, UTF-8 chunk
  boundaries and JCS float formatting. Added independent float vectors,
  measured scanner improvements and comparable performance regression gates.
- Updated development dependencies including Mint 1.10.0 security fixes and
  Muex 0.9.1. Mutation reports distinguish killed, compiler-invalid and proven
  equivalent mutations; broader bounded security campaigns retain strict scores.
- Added strict deployment guidance and a fresh unpacked-Hex consumer check.

- Removed `SigilGuard.Registry`, `SigilGuard.Registry.Bundle`, and
  `SigilGuard.Registry.Cache`; use
  [`SigilGuard.TrustBundle`](MIGRATING-1.0.md#registry-to-trust-bundles).
- Removed `SigilGuard.Envelope` and verdict-only `_sigil` metadata; use
  [`SigilGuard.Attestation`](MIGRATING-1.0.md#envelope-to-attestation) and
  [`_agent_trust`](MIGRATING-1.0.md#mcp-trust-metadata).
- Removed `SigilGuard.Profile`; use
  [`SigilGuard.TrustProfile`](MIGRATING-1.0.md#profile-to-trustprofile).
- Removed legacy config keys including `:backend`, `:protocol_profile`, and all
  `registry_*` keys; see
  [Configuration Keys](MIGRATING-1.0.md#configuration-keys).
- Renamed policy files from the old SIGIL family to the
  [SIGILGUARD policy filenames](MIGRATING-1.0.md#policy-filenames).
- Renamed confirmation metadata from `_sigil_confirmation` to
  [`_agent_confirmation`](MIGRATING-1.0.md#mcp-confirmation-metadata).
- Aligned the embedded gateway with MCP v2 (`2026-07-28`): structured action
  binding now covers nested keys and non-string values, modern successful
  responses carry `resultType`, and MRTR inputs/state remain bound across
  retries. See [MCP v2](MIGRATING-1.0.md#mcp-v2-2026-07-28).
- Moved gateway denial codes outside JSON-RPC's reserved server-error band to
  the application-defined
  [`-31990..-31984` range](MIGRATING-1.0.md#mcp-json-rpc-rejection-codes);
  the pre-release `-32050..-32056` draft allocation never ships.
- Upgraded capability manifests to
  `sigil_guard_capability_manifest/v2`, binding tool titles, icons, MCP Apps
  UI visibility, and validated `x-mcp-header` annotations.
- Added offline MCP Apps boundaries: same-server app/model visibility checks
  and `SigilGuard.MCP.AppResource` verification for pinned UI bytes, declared
  CSP domains, dedicated app domains, and browser permissions. Verification is
  strictly optioned and bounded to 1 MiB by default; rendering remains
  host-owned.
- Added `SigilGuard.Assessment.OSCAL.project/2`, a pure optional OSCAL
  Assessment Results v1.2.3 observation projection that binds a host-pinned
  canonical audit-export digest, rejects dangling fragment/query-only
  locators, and never infers findings or control satisfaction.
- Removed Finch from the runtime dependency set; HTTP anchor stores use the
  host-provided `SigilGuard.HTTPClient` behaviour.
- Runtime dependencies are intentionally limited to `:telemetry`,
  `:nimble_options`, and `:jason`; integrations, notebooks, and adaptive
  detector examples add no runtime dependency, and `mix deps.audit` is clean
  for the 1.0.0 release line. The test-only Bypass/Cowboy tree currently
  resolves Cowlib 2.19.0, for which Hex reports CVE-2026-43966 and
  CVE-2026-43969, plus CVE-2026-43971 published on 2026-08-18; Cowlib is absent
  from the production dependency tree, all three advisories are explicitly
  acknowledged in the Hex project configuration, affected encoders are not
  called by SigilGuard, and no patched Hex release is available as of
  2026-08-19. The canonical gate runs both `mix deps.audit` and
  `mix hex.audit`. Recheck the exceptions before 2026-09-19 and immediately
  before release, whichever comes first.
- Added a canonical full-history secret scan using a pinned,
  checksum-verified Gitleaks binary. Its ignore file contains only exact
  fingerprints for reviewed synthetic scanner fixtures.
- Malformed hook lists, adaptive-detector modules, and timeout options now fail
  closed at direct policy and runtime-gate entry points instead of allowing an
  invalid `receive ... after` timeout to raise.
- Repo and boundary-policy loaders now validate option containers, keys,
  candidate sets, legacy mappings, and byte limits before filesystem access;
  malformed inputs return `:invalid_options` instead of raising or weakening
  the configured size bound.
- Tagged publication now fails closed unless GitHub reports the exact release
  ref as protected; release documentation distinguishes the environment named
  in workflow YAML from the required owner-managed reviewer, deployment-tag,
  and environment-secret protections.
- Added an unoptimized, 100%-threshold mutation gate for the pure verdict
  ordering primitive; all 78 compilable mutants are killed.
- SPDX generation now binds the declared license from each matching locked Hex
  runtime artifact and fails on missing, malformed, or version-mismatched
  dependency metadata instead of emitting `NOASSERTION`.
- Boundary hook telemetry now covers successful and failed invocations with a
  native-time duration measurement and a normalized `hook_result`, matching the
  observability contract instead of reporting failures only.
- Reconciled the profile, gateway, and boundary specs to the final 1.0 event
  families and made boundary-policy decision telemetry use the shared policy
  shape with a system-time measurement.
- MCP gateway decision telemetry now fires after protocol/result enrichment on
  success and pre-gate denial paths; protocol revision and result type remain
  opt-in high-cardinality OpenTelemetry attributes.
- Revalidated reader-facing research and specification links, replacing moved
  SLSA, NIST, IETF, llm-guard, mcp-use, and historical crate references.
- Expanded `notebooks/` into an eleven-chapter, offline-validated Livebook
  tutorial track with conference/workshop run sheets, a deterministic AI-agent
  attack replay, and an optional ReqLLM proposal path using Livebook secrets;
  the canonical quality gate now executes every shipped Elixir cell offline.
- Changed selected trust-bundle error atoms and config boot errors; see
  [Error Changes](MIGRATING-1.0.md#error-changes).
- Version adoption is explicit: `~> 0.2` remains on the 0.2.x line and
  `~> 1.0` adopts the 1.0 release line; see
  [Version Pinning](MIGRATING-1.0.md#version-pinning).

<!-- changelog -->

## [v1.0.5](https://github.com/refpath/sigil_guard/compare/v1.0.4...v1.0.5) (2026-10-10)




### Bug Fixes:

* tooling: retain complete compiler diagnostics in mutation reports by futhr

* package: isolate archive checks from inherited Mix paths by futhr

* ci: clean downloaded scanner files after checks by futhr

* tooling: retry interrupted secret scanner downloads by futhr

## [v1.0.4](https://github.com/refpath/sigil_guard/compare/v1.0.3...v1.0.4) (2026-09-16)




### Bug Fixes:

* security: refresh Cowboy test stack by Tobias Bohwalli

## [v1.0.3](https://github.com/refpath/sigil_guard/compare/v1.0.2...v1.0.3) (2026-09-16)




### Bug Fixes:

* release: derive assertion from project version by Tobias Bohwalli

## [v1.0.2](https://github.com/refpath/sigil_guard/compare/v1.0.1...v1.0.2) (2026-09-16)




### Bug Fixes:

* json: validate every normalized object key by Tobias Bohwalli

* guides: preserve structured values and validate framework callbacks by Tobias Bohwalli

* stream: validate configuration before constructing sanitizers by Tobias Bohwalli

* vault: reject malformed encryption without losing entries by Tobias Bohwalli

* storage: bound trust reads and validate complete anchor writes by Tobias Bohwalli

* audit: bind proofs and statements to complete checkpoint state by Tobias Bohwalli

* attestation: enforce envelope construction limits by Tobias Bohwalli

* json: reject ambiguous evidence objects and canonical keys by Tobias Bohwalli

### Performance Improvements:

* audit: reuse indexed Merkle trees for batch inclusion proofs by Tobias Bohwalli

## [v1.0.1](https://github.com/refpath/sigil_guard/compare/v1.0.0...v1.0.1) (2026-09-07)




### Bug Fixes:

* package: validate a fresh unpacked Hex consumer by Tobias Bohwalli

* quarantine: bound diagnostics and decode rejected bundles once by Tobias Bohwalli

* scanner: merge overlapping redaction spans deterministically by Tobias Bohwalli

* runtime: resolve configured scanner patterns explicitly by Tobias Bohwalli

* stream: retain unbounded candidates and complete UTF-8 boundaries by Tobias Bohwalli

* gate: bind policy facts and scan structured MCP object keys by Tobias Bohwalli

* digest: reject ambiguous null-valued application fields by Tobias Bohwalli

* hooks: load configured security modules before checking callbacks by Tobias Bohwalli

* agent-card: enforce current issuer authority and revocations by Tobias Bohwalli

* trust-cache: preserve rollback and revocations under contention by Tobias Bohwalli

* trust: authenticate root and delegated authority transitions by Tobias Bohwalli

* policy: enforce atomic quotas and reclaim expired identities by Tobias Bohwalli

* replay: retain bounded claims for the full acceptance lifetime by Tobias Bohwalli

* jcs: correct integral floats and reject improper lists by Tobias Bohwalli

* security: bound untrusted input and signature verification work by Tobias Bohwalli

### Performance Improvements:

* scanner: reuse entropy and byte-frequency measurements by Tobias Bohwalli

## [1.0.0](https://github.com/refpath/sigil_guard/compare/v1.0.0...v1.0.0) (2026-08-24)




### Features:

* guidance: add terse prose skills by futhr

* guidance: align automatic repository skills by Tobias Bohwalli

* notebooks: add conference-ready tutorial track by Tobias Bohwalli

* assessment: add OSCAL evidence projection by Tobias Bohwalli

* mcp: support 2026-07-28 protocol by futhr

* release: gate releases on provenance by futhr

* sbom: verify SBOM digest by futhr

* audit: route anchor storage through HTTPClient by futhr

* audit: bind attestations to evidence by futhr

* audit: add query API by futhr

* audit: add decision CloudEvents projections by futhr

* telemetry: rename telemetry attributes by futhr

* audit: hash private fields by futhr

* audit: embed proofs in exports by futhr

* audit: add witness cosigning by futhr

* audit: build checkpoint state statements by futhr

* audit: add consistency proofs by futhr

* audit: add inclusion proofs by futhr

* scanner: split scanner patterns into bundles by futhr

* decision: separate verdicts from confirmation effects by futhr

* gate: evaluate boundary policy kernel by futhr

* boundary: scope sandbox matrix by futhr

* decision: add unified verdict typed fields by futhr

* identity: add static trust mapping by futhr

* scanner: add scanner match byte limits by futhr

* scanner: emit closed scanner categories by futhr

* boundary: wire repo hook and adaptive sources by futhr

* boundary: add hook and adaptive detector behaviours by futhr

* boundary: add sink aware output contracts by futhr

* repo-policy: add policy facts map by futhr

* boundary: add sandbox identity fields by futhr

* boundary: apply policy rules with precedence by futhr

* boundary: add policy loader legacy guard by futhr

* boundary: add policy file digest fixture by futhr

* boundary: add v3 policy file parser by futhr

* boundary: add unified verdict and policy kernel by futhr

* boundary: add lifecycle taxonomy and boundary input by futhr

* agent-trust: add AgentCard A2A surface by futhr

* gateway: enrich denial metadata by futhr

* gateway: renumber json-rpc errors by futhr

* attestation: strip legacy metadata by futhr

* gateway: issue confirmation tokens by futhr

* confirmation: issue v2 tokens by futhr

* gateway: sign tool attestations by futhr

* gateway: invalidate stale approvals by futhr

* gateway: verify listed manifests by futhr

* gateway: bind result decisions by futhr

* gateway: enforce request guard order by futhr

* gateway: require suspicious parameter confirmation by futhr

* manifest: add capability canonical form by futhr

* trust-bundle: retain revocation union by futhr

* trust-bundle: reject forked rotations by futhr

* trust-bundle: walk root rotations by futhr

* trust-bundle: bootstrap dev bundles by futhr

* trust-bundle: emit telemetry spans by futhr

* trust-bundle: load configured bundle on boot by futhr

* trust-bundle: load local sources by futhr

* trust-bundle: record quarantine failures by futhr

* trust-bundle: cache verified snapshots by futhr

* trust-bundle: verify signed bundles by futhr

* trust-bundle: validate document schema by futhr

* trust-bundle: add public api shell by futhr

* attestation: build statements from decisions by futhr

* attestation: add sign and verify by futhr

* attestation: add digest computation by futhr

* attestation: add metadata helpers by futhr

* attestation: add agent predicate extensions by futhr

* attestation: add trust profile registry by futhr

* attestation: add statement builder by futhr

* attestation: add dsse envelope by futhr

* canonical: add jcs encoder by futhr

* audit: expose signed anchor receipts by futhr

* audit: verify signed anchor receipts by futhr

* audit: require worm anchor receipts by futhr

* audit: add http anchor store by futhr

* audit: trace anchor store operations by futhr

* release: verify generated sbom artifacts by futhr

* audit: add append-only anchor store by futhr

* repo-policy: load repo policy files by futhr

* scanner: validate credential boundaries by futhr

* registry: enforce cache bundle freshness by futhr

* mcp: stream guarded result chunks by futhr

* mcp: release confirmed tool results by futhr

* mcp: compose signed confirmations by futhr

* mcp: accept confirmed tool requests by futhr

* confirmation: support single-use tokens by futhr

* audit: add portable checkpoint exports by futhr

* telemetry: trace signed mcp requests by futhr

* mcp: verify signed tool requests by futhr

* registry: enforce bundle freshness by futhr

* runtime: expand quarantine indicators by futhr

* scanner: harden generic secret validation by futhr

* mcp: return safe json-rpc guard responses by futhr

* audit: add external anchor records by futhr

* repo-policy: add deterministic agent governance by futhr

* audit: add signed checkpoint exports by futhr

* telemetry: add OTel attribute bridge by futhr

* scanner: add staged validation pipeline by futhr

* registry: verify bundle provenance by futhr

* runtime: add action-bound confirmation tokens by futhr

* mcp: add gateway and streaming guard by futhr

* runtime: add boundary-aware gate by futhr

* registry: normalize DID key resolution by futhr

* envelope: add protocol profiles and replay checks by futhr

### Bug Fixes:

* livebooks: use fetched dependencies for offline checks by futhr

* release: enforce protected provenance gates by Tobias Bohwalli

* runtime: fail closed and complete decision telemetry by Tobias Bohwalli

* harden release provenance and verification by Tobias Bohwalli

* release: address validation findings by Tobias Bohwalli

* validation: reject malformed keyword inputs by futhr

* core: fail closed on malformed options by futhr

* audit: harden anchor store boundaries by futhr

* policy: reject symlinked policy files by futhr

* deps: update vulnerable http stack by futhr

* schema: avoid opaque mapset injection from attributes by futhr

* quarantine: support elixir 1.18 compilation by futhr

* bench: avoid stream accumulation overhead by futhr

* patterns: support elixir 1.18 compilation by futhr

* bench: stabilize smoke comparison gate by futhr

* core: harden runtime verification paths by futhr

* attestation: enforce replay expiry semantics by futhr

* registry: require explicit compatibility endpoint by futhr

* audit: validate stored anchors before digest by futhr

* audit: reject invalid export packages by futhr

* audit: reject invalid canonical evidence by futhr

* registry: quarantine invalid bundle terms by futhr

* policy: fail closed on invalid rate options by futhr

* scanner: fail closed on invalid pipeline output by futhr

* scanner: normalize malformed pipeline options by futhr

* telemetry: propagate action digest errors by futhr

* runtime: keep stream holdback on invalid windows by futhr

* runtime: fail closed on invalid confirmation payloads by futhr

* audit: validate local anchor metadata by futhr

* sbom: reject incomplete runtime dependency graphs by futhr

* audit: validate http anchor metadata by futhr

* audit: normalize missing http client errors by futhr

* audit: restrict receipt fetch urls by futhr

* audit: reject conflicting receipt digests by futhr

* sbom: classify tuple dependency options by futhr

* sbom: bind verification to provenance by futhr

* audit: validate fetched anchor records by futhr

* policy: reject malformed risk options by futhr

* audit: reuse checkpoint verification digest by futhr

* signer: validate startup keys by futhr

* registry: validate request timeouts by futhr

* audit: validate http anchor timeouts by futhr

* sbom: validate document identity by futhr

* audit: validate export anchors by futhr

* vault: validate master keys by futhr

* confirmation: validate token options by futhr

* mcp: serialize malformed context errors by futhr

* runtime: normalize context boundaries by futhr

* audit: validate anchor provenance fields by futhr

* audit: validate local receipt uris by futhr

* sbom: verify dependency graph by futhr

* registry: reject malformed identity status by futhr

* audit: reject malformed checkpoints by futhr

* audit: reject remote file receipts by futhr

* audit: reject malformed fetched anchors by futhr

* audit: reject malformed store receipts by futhr

* audit: validate anchors before storage by futhr

* repo-policy: reject malformed matchers by futhr

* telemetry: expose runtime input errors by futhr

* registry: reject masked key material by futhr

* mcp: scan full request payloads by futhr

* runtime: reject malformed context fields by futhr

* patterns: reject malformed metadata by futhr

* audit: validate chain anchors by futhr

* crypto: reject malformed issuer keys by futhr

* runtime: preserve malformed repo context by futhr

* policy: reject malformed repo context by futhr

* audit: reject malformed remote receipts by futhr

* mcp: preserve malformed guard metadata by futhr

* registry: preserve malformed DID fields by futhr

* runtime: preserve malformed changed paths by futhr

* policy: preserve explicit invalid fields by futhr

* validate public key maps by futhr

* registry: harden bundle provenance by futhr

* audit: reject empty receipt signatures by futhr

* audit: reject empty checkpoint fields by futhr

* audit: reject ambiguous anchor receipts by futhr

* patterns: preserve explicit bundle fields by futhr

* preserve explicit string fields by futhr

* audit: harden local anchor lookup by futhr

* audit: enforce signed receipt fetches by futhr

* telemetry: preserve boolean attributes by futhr

* repo-policy: normalize policy edge cases by futhr

* registry: quarantine malformed signed bundles by futhr

* runtime: sanitize blocked decisions by futhr

* audit: reduce chain verification allocation by futhr

### Performance Improvements:

* gateway: avoid duplicate result gating by futhr

* scanner: reuse entropy byte frequencies by futhr

* bench: add reproducible baseline suite by futhr

* scanner: cache built-in patterns by futhr

* runtime: reuse gate scan results in streams by futhr

## [v0.2.0](https://github.com/refpath/sigil_guard/compare/v0.1.1...v0.2.0) (2026-06-10)




### Features:

* registry: retry failed bundle fetches before TTL expiry by futhr

### Bug Fixes:

* backend: reject invalid backend configuration with a clear error by futhr

* registry: reject non-object JSON responses by futhr

* envelope: make verify/2 total over adversarial input by futhr

* audit: enforce HMAC chain contiguity in verify_chain by futhr

* policy: own the default rate table and survive creation races by futhr

* use force-build for NIF compilation in CI by Tobias Bohwalli

## [v0.1.1](https://github.com/refpath/sigil_guard/compare/v0.1.0...v0.1.1) (2026-04-06)




### Bug Fixes:

* add NIF version features and musl/LTO config for precompiled builds by Tobias Bohwalli

## [v0.1.0](https://github.com/refpath/sigil_guard/compare/v0.1.0...v0.1.0) (2026-04-03)




### Features:

* add missing protocol types from sigil-protocol crate by Tobias Bohwalli

* Rust NIF backend via Rustler by Tobias Bohwalli

* SIGIL protocol core library by Tobias Bohwalli

### Bug Fixes:

* remove HTML div wrapper for hex.pm rendering by Tobias Bohwalli

* resolve doc coverage failures in CI by Tobias Bohwalli

* track benchmark output for ExDoc generation by Tobias Bohwalli
