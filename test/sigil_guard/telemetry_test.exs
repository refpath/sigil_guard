defmodule SigilGuard.TelemetryTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Audit.Anchor.Store
  alias SigilGuard.Audit.Anchor.Store.LocalFile
  alias SigilGuard.AuditProofFixture
  alias SigilGuard.Telemetry

  @expected_events [
    [:sigil_guard, :scan, :start],
    [:sigil_guard, :scan, :stop],
    [:sigil_guard, :scan, :exception],
    [:sigil_guard, :policy, :decision],
    [:sigil_guard, :boundary, :hook],
    [:sigil_guard, :boundary, :adaptive],
    [:sigil_guard, :runtime, :gate],
    [:sigil_guard, :mcp, :request],
    [:sigil_guard, :audit, :logged],
    [:sigil_guard, :audit, :anchor_store, :put, :start],
    [:sigil_guard, :audit, :anchor_store, :put, :stop],
    [:sigil_guard, :audit, :anchor_store, :put, :exception],
    [:sigil_guard, :audit, :anchor_store, :fetch, :start],
    [:sigil_guard, :audit, :anchor_store, :fetch, :stop],
    [:sigil_guard, :audit, :anchor_store, :fetch, :exception],
    [:sigil_guard, :audit, :anchor_store, :verify, :start],
    [:sigil_guard, :audit, :anchor_store, :verify, :stop],
    [:sigil_guard, :audit, :anchor_store, :verify, :exception],
    [:sigil_guard, :trust_bundle, :load, :start],
    [:sigil_guard, :trust_bundle, :load, :stop],
    [:sigil_guard, :trust_bundle, :load, :exception],
    [:sigil_guard, :trust_bundle, :verify, :start],
    [:sigil_guard, :trust_bundle, :verify, :stop],
    [:sigil_guard, :trust_bundle, :verify, :exception],
    [:sigil_guard, :trust_bundle, :quarantine],
    [:sigil_guard, :agent_trust, :card_verify, :start],
    [:sigil_guard, :agent_trust, :card_verify, :stop],
    [:sigil_guard, :agent_trust, :card_verify, :exception],
    [:sigil_guard, :agent_trust, :attest, :start],
    [:sigil_guard, :agent_trust, :attest, :stop],
    [:sigil_guard, :agent_trust, :attest, :exception],
    [:sigil_guard, :agent_trust, :verify, :start],
    [:sigil_guard, :agent_trust, :verify, :stop],
    [:sigil_guard, :agent_trust, :verify, :exception],
    [:sigil_guard, :agent_trust, :quarantine]
  ]

  describe "events/0" do
    test "lists known SigilGuard telemetry events" do
      assert Telemetry.events() == @expected_events
    end
  end

  describe "otel_attributes/4" do
    test "maps runtime security metadata to the sigilguard.* namespace" do
      attributes =
        Telemetry.otel_attributes(
          [:sigil_guard, :runtime, :gate],
          %{system_time: 123},
          %{
            phase: :tool_request,
            actor: "did:sigil:agent",
            identity: "did:sigil:agent",
            origin: :model,
            sink: :external,
            tool: "send_webhook",
            trust_zone: :semi_trusted,
            trust_level: :high,
            risk_level: :high,
            verdict: :blocked,
            action: :block,
            action_digest: "digest123",
            action_digest_error: :invalid_payload,
            hit_count: 1,
            indicator_ids: [:ignore_instructions],
            envelope_status: :invalid,
            envelope_reason: :invalid_signature,
            confirmation_status: :invalid,
            confirmation_reason: :digest_mismatch,
            confirmation_actor: "did:sigil:agent",
            confirmation_nonce_hash: "nonce-hash",
            release_status: :confirmed_sanitized,
            runtime_input_error: :invalid_action,
            scanner_error: :scanner_failed,
            content_hash: "abc123"
          },
          include_high_cardinality: true
        )

      assert attributes == %{
               "sigilguard.event" => "sigil_guard.runtime.gate",
               "sigilguard.component" => "runtime",
               "sigilguard.operation" => "gate",
               "sigilguard.measurement.system_time" => 123,
               "sigilguard.phase" => "tool_request",
               "sigilguard.actor.hash" => "redacted-v1",
               "sigilguard.identity.hash" => "redacted-v1",
               "sigilguard.origin" => "model",
               "sigilguard.sink" => "external",
               "sigilguard.tool.name" => "send_webhook",
               "sigilguard.trust_zone" => "semi_trusted",
               "sigilguard.trust_level" => "high",
               "sigilguard.risk_level" => "high",
               "sigilguard.verdict" => "blocked",
               "sigilguard.action" => "block",
               "sigilguard.action.digest" => "digest123",
               "sigilguard.action.digest_error" => "invalid_payload",
               "sigilguard.hit_count" => 1,
               "sigilguard.indicator_ids" => ["ignore_instructions"],
               "sigilguard.confirmation.status" => "invalid",
               "sigilguard.confirmation.reason" => "digest_mismatch",
               "sigilguard.confirmation.actor.hash" => "redacted-v1",
               "sigilguard.confirmation.nonce_hash" => "nonce-hash",
               "sigilguard.release.status" => "confirmed_sanitized",
               "sigilguard.runtime_input_error" => "invalid_action",
               "sigilguard.scanner.error" => "scanner_failed",
               "sigilguard.payload.digest" => "abc123"
             }
    end

    test "drops high-cardinality attributes unless opted in" do
      metadata = %{
        verdict: :blocked,
        actor: "did:sigil:agent",
        identity: "did:sigil:agent",
        action_digest: "digest123",
        content_hash: "abc123",
        confirmation_actor: "did:sigil:agent",
        resource_uri: "file://x",
        protocol_version: "2026-07-28",
        mcp_result_type: "input_required",
        hit_count: 3
      }

      bounded = Telemetry.otel_attributes([:sigil_guard, :runtime, :gate], %{}, metadata)

      assert bounded["sigilguard.verdict"] == "blocked"
      assert bounded["sigilguard.hit_count"] == 3

      for key <- ~w(sigilguard.actor.hash sigilguard.identity.hash sigilguard.action.digest
                    sigilguard.payload.digest sigilguard.confirmation.actor.hash
                    sigilguard.resource.uri sigilguard.mcp.protocol_version
                    sigilguard.mcp.result_type) do
        refute Map.has_key?(bounded, key)
      end

      opted_in =
        Telemetry.otel_attributes([:sigil_guard, :runtime, :gate], %{}, metadata,
          include_high_cardinality: true
        )

      assert opted_in["sigilguard.actor.hash"] == "redacted-v1"
      assert opted_in["sigilguard.payload.digest"] == "abc123"
      assert opted_in["sigilguard.resource.uri"] == "file://x"
      assert opted_in["sigilguard.mcp.protocol_version"] == "2026-07-28"
      assert opted_in["sigilguard.mcp.result_type"] == "input_required"
    end
  end

  describe "decision correlation and denial facts" do
    alias SigilGuard.Runtime.Gate
    alias SigilGuard.ToolGateway

    defp capture(event, fun) do
      ref = :telemetry_test.attach_event_handlers(self(), [event])

      try do
        result = fun.()
        assert_receive {^event, ^ref, _, metadata}
        {result, metadata}
      after
        :telemetry.detach(ref)
      end
    end

    test "a host correlation id reaches the decision, the event and the attribute" do
      context = [phase: :tool_request, sink: :tool, sandbox_id: "sandbox-7", trust_level: :high]

      {decision, metadata} =
        capture([:sigil_guard, :runtime, :gate], fn ->
          Gate.evaluate("clean", context, decision_id: "req-7f3a")
        end)

      assert decision.audit_metadata.decision_id == "req-7f3a"
      assert metadata.decision_id == "req-7f3a"
      assert metadata.sandbox_id == "sandbox-7"

      event = [:sigil_guard, :runtime, :gate]
      low = Telemetry.otel_attributes(event, %{}, metadata)
      high = Telemetry.otel_attributes(event, %{}, metadata, include_high_cardinality: true)

      refute Map.has_key?(low, "sigilguard.decision.id")
      refute Map.has_key?(low, "sigilguard.sandbox.id")
      assert high["sigilguard.decision.id"] == "req-7f3a"
      assert high["sigilguard.sandbox.id"] == "sandbox-7"
    end

    test "the gate mints no id and ignores one it cannot carry" do
      for opts <- [
            [],
            [decision_id: ""],
            [decision_id: 7],
            [decision_id: String.duplicate("a", 129)],
            [decision_id: <<0, 1>>]
          ] do
        decision = Gate.evaluate("clean", [trust_level: :high], opts)

        refute Map.has_key?(decision.audit_metadata, :decision_id)
      end
    end

    test "the rules behind a decision are a bounded attribute" do
      {:ok, policy} =
        SigilGuard.BoundaryPolicy.File.parse("version 3\n[rules]\nblock sink:external\n")

      context = [phase: :outbound_model, sink: :external, trust_level: :high]

      {decision, metadata} =
        capture([:sigil_guard, :runtime, :gate], fn ->
          Gate.evaluate("clean", context, boundary_policy: policy)
        end)

      assert decision.audit_metadata.matched_rule_ids == ["line_3"]

      assert Telemetry.otel_attributes([:sigil_guard, :runtime, :gate], %{}, metadata)[
               "sigilguard.rules.matched"
             ] == ["line_3"]

      refute Map.has_key?(
               Gate.evaluate("clean", [trust_level: :high], []).audit_metadata,
               :matched_rule_ids
             )
    end

    test "a gateway denial names its reason and manifest on the MCP event" do
      manifest = SigilGuard.FixturePath.read_unexpiring_manifest!()

      request = %{
        "jsonrpc" => "2.0",
        "id" => 1,
        "method" => "tools/call",
        "params" => %{"name" => manifest["name"], "arguments" => %{}}
      }

      event = [:sigil_guard, :mcp, :request]

      {denied, denied_metadata} =
        capture(event, fn ->
          ToolGateway.guard_request(request, [trust_level: :high],
            manifests: %{manifest["name"] => manifest}
          )
        end)

      assert denied.audit_metadata.deny_reason == :sandbox_required

      assert Telemetry.otel_attributes(event, %{}, denied_metadata)["sigilguard.deny_reason"] ==
               "sandbox_required"

      context = [trust_level: :high, sandbox_id: "s", isolation_level: :vm]

      {allowed, metadata} =
        capture(event, fn ->
          ToolGateway.guard_request(request, context, manifests: %{manifest["name"] => manifest})
        end)

      low = Telemetry.otel_attributes(event, %{}, metadata)
      high = Telemetry.otel_attributes(event, %{}, metadata, include_high_cardinality: true)

      assert low["sigilguard.manifest.name"] == manifest["name"]
      refute Map.has_key?(low, "sigilguard.manifest.digest")
      assert high["sigilguard.manifest.digest"] == allowed.audit_metadata.manifest_digest
      refute Map.has_key?(low, "sigilguard.deny_reason")
    end

    test "the event of an accepted confirmation states no denial" do
      manifest =
        SigilGuard.FixturePath.read_unexpiring_manifest!()
        |> put_in(["input_schema", "required"], ["apiKey", "content", "path"])
        |> Map.put("suspicious_params", ["apiKey"])

      request = %{
        "jsonrpc" => "2.0",
        "id" => 1,
        "method" => "tools/call",
        "params" => %{
          "name" => manifest["name"],
          "arguments" => %{"path" => "a", "content" => "b"}
        }
      }

      context = [
        trust_level: :high,
        actor: "did:web:approver",
        sandbox_id: "s",
        isolation_level: :vm
      ]

      key = :crypto.hash(:sha256, "telemetry confirmation key")
      opts = [manifests: %{manifest["name"] => manifest}, confirmation_key: key]
      event = [:sigil_guard, :mcp, :request]

      {pending, pending_metadata} =
        capture(event, fn -> ToolGateway.guard_request(request, context, opts) end)

      assert {:confirm, _} = pending.verdict
      assert pending_metadata.deny_reason == :suspicious_required_param

      {:ok, capability} = SigilGuard.CapabilityManifest.new(manifest)

      {:ok, token} =
        ToolGateway.issue_confirmation(request, context, pending, key, manifest: capability)

      {accepted, metadata} =
        capture(event, fn ->
          ToolGateway.guard_request(request, context, [{:confirmation_token, token} | opts])
        end)

      assert accepted.verdict == :allowed
      assert metadata.verdict == :allowed
      refute Map.has_key?(metadata, :deny_reason)

      refute Map.has_key?(
               Telemetry.otel_attributes(event, %{}, metadata),
               "sigilguard.deny_reason"
             )
    end

    test "the policy digest, the request back-reference and the quarantine status are attributes" do
      event = [:sigil_guard, :mcp, :request]
      digest = String.duplicate("a", 64)

      {_, metadata} =
        capture(event, fn ->
          ToolGateway.guard_result(
            %{
              "jsonrpc" => "2.0",
              "id" => 1,
              "result" => %{"content" => [%{"type" => "text", "text" => "done"}]}
            },
            [phase: :tool_result, trust_level: :high],
            request_action_digest: digest
          )
        end)

      assert metadata.request_action_digest == digest
      assert metadata.quarantine_status == :safe

      low = Telemetry.otel_attributes(event, %{}, metadata)
      high = Telemetry.otel_attributes(event, %{}, metadata, include_high_cardinality: true)

      assert low["sigilguard.quarantine.status"] == "safe"
      refute Map.has_key?(low, "sigilguard.request.action.digest")
      assert high["sigilguard.request.action.digest"] == digest

      with_policy = %{repo_policy_digest: digest, verdict: :allowed}

      refute Map.has_key?(
               Telemetry.otel_attributes(event, %{}, with_policy),
               "sigilguard.policy.digest"
             )

      assert Telemetry.otel_attributes(event, %{}, with_policy, include_high_cardinality: true)[
               "sigilguard.policy.digest"
             ] == digest
    end

    test "a refusal of malformed input carries the host correlation id" do
      {decision, metadata} =
        capture([:sigil_guard, :runtime, :gate], fn ->
          Gate.evaluate("text", [phase: :not_a_phase, sandbox_id: "sandbox-3"],
            decision_id: "req-9"
          )
        end)

      assert decision.verdict == :blocked
      assert decision.audit_metadata.runtime_input_error == :invalid_phase
      assert decision.audit_metadata.decision_id == "req-9"
      assert metadata.decision_id == "req-9"

      for unusable <- ["two words", "line\nbreak", <<0xC3, 0xA9>>] do
        refute Map.has_key?(
                 Gate.evaluate("text", [], decision_id: unusable).audit_metadata,
                 :decision_id
               )
      end

      refute Map.has_key?(Gate.evaluate("text", [], :not_options).audit_metadata, :decision_id)
    end

    test "an audit log event carries the event id as an opt-in attribute" do
      event = [:sigil_guard, :audit, :logged]

      {signed, metadata} =
        capture(event, fn ->
          "runtime.gate"
          |> SigilGuard.Audit.new_event("did:web:agent", "cell.move", "allow")
          |> SigilGuard.Audit.sign_event(:crypto.hash(:sha256, "telemetry chain key"))
        end)

      assert metadata.event_id == signed.id

      refute Map.has_key?(
               Telemetry.otel_attributes(event, %{}, metadata),
               "sigilguard.audit.event_id"
             )

      assert Telemetry.otel_attributes(event, %{}, metadata, include_high_cardinality: true)[
               "sigilguard.audit.event_id"
             ] == signed.id
    end
  end

  describe "otel_attributes/4 hashed class" do
    @field_hash_key :crypto.hash(:sha256, "telemetry field hash test key")
    @hashed_attributes ~w(sigilguard.actor.hash sigilguard.identity.hash
                          sigilguard.confirmation.actor.hash)

    defp identities(opts) do
      metadata = %{
        actor: "did:web:alice",
        identity: "spiffe://example.test/agent/planner",
        confirmation_actor: "did:web:approver",
        verdict: :allowed
      }

      Telemetry.otel_attributes(
        [:sigil_guard, :runtime, :gate],
        %{},
        metadata,
        [{:include_high_cardinality, true} | opts]
      )
    end

    test "no identity value leaves in clear, with or without a key" do
      for opts <- [
            [],
            [field_hash_key: @field_hash_key],
            [field_hash_key: ""],
            [field_hash_key: 5]
          ] do
        exported = Enum.join(Map.values(identities(opts)), "\n")

        refute exported =~ "alice"
        refute exported =~ "planner"
        refute exported =~ "approver"
      end
    end

    test "without a usable key every hashed attribute is the redaction placeholder" do
      for opts <- [[], [field_hash_key: nil], [field_hash_key: ""], [field_hash_key: 5]] do
        attributes = identities(opts)

        assert Enum.map(@hashed_attributes, &attributes[&1]) == List.duplicate("redacted-v1", 3)
      end
    end

    test "with a key the attribute is the value the audit chain stores" do
      attributes = identities(field_hash_key: @field_hash_key)

      event =
        SigilGuard.Audit.classify(
          SigilGuard.Audit.new_event("runtime.gate", "did:web:alice", "cell.move", "allow"),
          field_hash_key: @field_hash_key
        )

      assert attributes["sigilguard.actor.hash"] == event.actor
      assert attributes["sigilguard.actor.hash"] =~ ~r/\Afh1:[0-9a-f]{64}\z/

      assert attributes["sigilguard.identity.hash"] ==
               SigilGuard.Audit.hash_field("spiffe://example.test/agent/planner", @field_hash_key)

      assert attributes["sigilguard.confirmation.actor.hash"] ==
               SigilGuard.Audit.hash_field("did:web:approver", @field_hash_key)

      refute attributes["sigilguard.actor.hash"] ==
               identities(field_hash_key: "another key")["sigilguard.actor.hash"]
    end

    test "an already hashed value is unchanged and a look-alike is not trusted" do
      hashed = SigilGuard.Audit.hash_field("did:web:alice", @field_hash_key)
      event = [:sigil_guard, :runtime, :gate]
      opts = [include_high_cardinality: true]

      attributes = fn actor -> Telemetry.otel_attributes(event, %{}, %{actor: actor}, opts) end

      assert attributes.(hashed)["sigilguard.actor.hash"] == hashed
      assert attributes.("redacted-v1")["sigilguard.actor.hash"] == "redacted-v1"

      for forged <- ["fh1:alice@example.test", "fh1:" <> String.duplicate("A", 64), "fh1:"] do
        assert attributes.(forged)["sigilguard.actor.hash"] == "redacted-v1"
      end

      assert attributes.(:alice)["sigilguard.actor.hash"] == "redacted-v1"
      refute Map.has_key?(attributes.(nil), "sigilguard.actor.hash")
    end

    test "the forwarder applies the same rule" do
      parent = self()
      handler_id = "sigil-otel-hash-test-#{System.unique_integer()}"
      event = [:sigil_guard, :policy, :decision]

      assert :ok =
               Telemetry.attach_otel_forwarder(
                 handler_id,
                 fn _, _, _, attributes -> send(parent, {:attributes, attributes}) end,
                 events: [event],
                 include_high_cardinality: true,
                 field_hash_key: @field_hash_key
               )

      on_exit(fn -> Telemetry.detach(handler_id) end)

      Telemetry.emit(event, %{}, %{actor: "did:web:alice", action: "cell.move"})

      assert_receive {:attributes, attributes}

      assert attributes["sigilguard.actor.hash"] ==
               SigilGuard.Audit.hash_field("did:web:alice", @field_hash_key)
    end

    test "maps url to url.full and exports no registry attribute" do
      attributes =
        Telemetry.otel_attributes(
          [:sigil_guard, :registry, :fetch, :stop],
          %{duration: 10},
          %{
            url: "https://registry.example.test/patterns/bundle",
            endpoint: "patterns/bundle",
            count: 5,
            source: "remote"
          }
        )

      assert attributes["url.full"] == "https://registry.example.test/patterns/bundle"
      assert attributes["sigilguard.measurement.duration"] == 10
      refute Enum.any?(Map.keys(attributes), &String.contains?(&1, "registry"))
      refute Enum.member?(Map.values(attributes), "patterns/bundle")
    end

    test "maps audit anchor-store metadata without raw paths" do
      attributes =
        Telemetry.otel_attributes(
          [:sigil_guard, :audit, :anchor_store, :put, :stop],
          %{duration: 10},
          %{
            anchor_store: "SigilGuard.Audit.Anchor.Store.LocalFile",
            anchor_digest: "abc123",
            anchor_storage: "local_file",
            anchor_uri_scheme: "file",
            outcome: :ok,
            error_reason: nil,
            uri: "file:///private/path/anchors.jsonl"
          },
          include_high_cardinality: true
        )

      assert attributes["sigilguard.event"] == "sigil_guard.audit.anchor_store.put.stop"
      assert attributes["sigilguard.component"] == "audit"
      assert attributes["sigilguard.operation"] == "anchor_store.put.stop"

      assert attributes["sigilguard.audit.anchor.store"] ==
               "SigilGuard.Audit.Anchor.Store.LocalFile"

      assert attributes["sigilguard.audit.anchor.digest"] == "abc123"
      assert attributes["sigilguard.audit.anchor.storage"] == "local_file"
      assert attributes["sigilguard.audit.anchor.uri_scheme"] == "file"
      assert attributes["sigilguard.outcome"] == "ok"
      refute Map.has_key?(attributes, "uri")
      refute Map.has_key?(attributes, "url.full")
    end

    test "drops nil, unknown, and unsupported attribute values" do
      attributes =
        Telemetry.otel_attributes(
          [:third_party, :event],
          %{duration: nil, unsupported: %{nested: true}},
          %{
            unknown: "ignored",
            phase: nil,
            indicator_ids: [:ignore_instructions, "direct", 42, true, %{nested: true}],
            repo_policy_rules: [%{not: "exportable"}]
          }
        )

      assert attributes["sigilguard.event"] == "third_party.event"
      assert attributes["sigilguard.component"] == "unknown"
      assert attributes["sigilguard.operation"] == "unknown"

      assert attributes["sigilguard.indicator_ids"] == [
               "ignore_instructions",
               "direct",
               42,
               true
             ]

      refute Map.has_key?(attributes, "unknown")
      refute Map.has_key?(attributes, "sigilguard.measurement.duration")
      refute Map.has_key?(attributes, "sigilguard.measurement.unsupported")
      refute Map.has_key?(attributes, "sigilguard.phase")
      refute Map.has_key?(attributes, "sigilguard.repo_policy.rules")
    end
  end

  describe "attach_otel_forwarder/3" do
    test "forwards event, metadata, and OTel-style attributes" do
      parent = self()
      handler_id = "sigil-otel-test-#{System.unique_integer()}"

      assert :ok =
               Telemetry.attach_otel_forwarder(
                 handler_id,
                 fn event, measurements, metadata, attributes ->
                   send(parent, {event, measurements, metadata, attributes})
                 end,
                 events: [[:sigil_guard, :policy, :decision]]
               )

      on_exit(fn -> Telemetry.detach(handler_id) end)

      Telemetry.emit(
        [:sigil_guard, :policy, :decision],
        %{system_time: 123},
        %{action: "delete_database", risk_level: :high, trust_level: :low}
      )

      assert_receive {[:sigil_guard, :policy, :decision], %{system_time: 123}, metadata,
                      attributes}

      assert metadata.action == "delete_database"
      assert attributes["sigilguard.action"] == "delete_database"
      assert attributes["sigilguard.risk_level"] == "high"
    end

    test "rejects duplicate handler IDs and reports missing detach targets" do
      handler_id = "sigil-otel-duplicate-test-#{System.unique_integer()}"

      assert :ok =
               Telemetry.attach_otel_forwarder(handler_id, fn _, _, _, _ -> :ok end,
                 events: [[:sigil_guard, :policy, :decision]]
               )

      on_exit(fn -> Telemetry.detach(handler_id) end)

      assert {:error, :already_exists} =
               Telemetry.attach_otel_forwarder(handler_id, fn _, _, _, _ -> :ok end,
                 events: [[:sigil_guard, :policy, :decision]]
               )

      assert {:error, :not_found} =
               Telemetry.detach("sigil-otel-missing-test-#{System.unique_integer()}")
    end
  end

  describe "scan telemetry" do
    test "includes scanner pipeline metadata" do
      ref = :telemetry_test.attach_event_handlers(self(), [[:sigil_guard, :scan, :stop]])
      on_exit(fn -> :telemetry.detach(ref) end)

      SigilGuard.scan("safe text")

      assert_receive {[:sigil_guard, :scan, :stop], ^ref, %{duration: _}, metadata}
      assert metadata.pipeline == :staged
      assert metadata.scanner_validate
      assert metadata.patterns_checked > 0
      assert metadata.hit_count == 0
    end
  end

  describe "anchor store telemetry" do
    test "emits audit-safe stop metadata for local anchor storage" do
      ref =
        :telemetry_test.attach_event_handlers(self(), [
          [:sigil_guard, :audit, :anchor_store, :put, :stop],
          [:sigil_guard, :audit, :anchor_store, :fetch, :stop],
          [:sigil_guard, :audit, :anchor_store, :verify, :stop]
        ])

      on_exit(fn -> :telemetry.detach(ref) end)

      {checkpoint, anchor} = anchor_fixture()
      path = tmp_path()

      assert {:ok, receipt} = Store.put(LocalFile, anchor, path: path)
      assert {:ok, ^anchor} = Store.fetch(LocalFile, receipt)
      assert {:ok, verified} = Store.verify(LocalFile, receipt, checkpoint)

      assert verified.digest == receipt["anchor_digest"]

      assert_receive {[:sigil_guard, :audit, :anchor_store, :put, :stop], ^ref, %{duration: _},
                      put_metadata}

      assert_receive {[:sigil_guard, :audit, :anchor_store, :fetch, :stop], ^ref, %{duration: _},
                      fetch_metadata}

      assert_receive {[:sigil_guard, :audit, :anchor_store, :verify, :stop], ^ref, %{duration: _},
                      verify_metadata}

      for metadata <- [put_metadata, fetch_metadata, verify_metadata] do
        assert metadata.anchor_store == "SigilGuard.Audit.Anchor.Store.LocalFile"
        assert metadata.anchor_digest == receipt["anchor_digest"]
        assert metadata.anchor_uri_scheme == "file"
        assert metadata.outcome == :ok
        refute Map.has_key?(metadata, :uri)
        refute Map.has_key?(metadata, :path)
        refute Map.has_key?(metadata, :record)
      end

      assert put_metadata.anchor_storage == "local_file"
    end

    test "emits error metadata for invalid stores" do
      ref =
        :telemetry_test.attach_event_handlers(self(), [
          [:sigil_guard, :audit, :anchor_store, :put, :stop]
        ])

      on_exit(fn -> :telemetry.detach(ref) end)

      assert {:error, :invalid_store} =
               Store.put(String, %{"kind" => "sigil_guard.audit.anchor"})

      assert_receive {[:sigil_guard, :audit, :anchor_store, :put, :stop], ^ref, %{duration: _},
                      metadata}

      assert metadata.anchor_store == "String"
      assert metadata.outcome == :error
      assert metadata.error_reason == :invalid_store

      {_, anchor} = anchor_fixture()

      assert {:error, :worm_required} =
               Store.put(LocalFile, anchor, path: tmp_path(), require_worm: true)

      assert_receive {[:sigil_guard, :audit, :anchor_store, :put, :stop], ^ref, %{duration: _},
                      worm_metadata}

      assert worm_metadata.anchor_store == "SigilGuard.Audit.Anchor.Store.LocalFile"
      assert worm_metadata.outcome == :error
      assert worm_metadata.error_reason == :worm_required
    end
  end

  defp anchor_fixture,
    do: AuditProofFixture.anchor_fixture(storage: :local_file, uri: "file://anchors.jsonl")

  defp tmp_path do
    root =
      System.tmp_dir!()
      |> Path.join("sigil_guard_anchor_telemetry_tests")
      |> Path.join("#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf(root) end)

    Path.join(root, "anchors.jsonl")
  end
end
