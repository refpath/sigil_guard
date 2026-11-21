defmodule SigilGuard.ToolGatewayEffectTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Attestation
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.CapabilityManifest
  alias SigilGuard.Confirmation
  alias SigilGuard.EffectAuthority
  alias SigilGuard.EffectAuthorityFixture, as: Fixture
  alias SigilGuard.MCP.Gateway
  alias SigilGuard.MCP.SecurityPayload
  alias SigilGuard.ReplayStore
  alias SigilGuard.Telemetry
  alias SigilGuard.TestSigner
  alias SigilGuard.ToolGateway

  @effect_keys [:effect_binding, :effect_binding_digest, :effect_operation_key]
  @digest_keys [:action_digest, :payload_digest, :context_digest]

  setup do
    ReplayStore.clear()
    on_exit(&ReplayStore.clear/0)
    :ok
  end

  describe "effect_binding: :off" do
    test "is the default and changes nothing" do
      opts = Keyword.delete(Fixture.gateway_opts(), :effect_binding)

      default = ToolGateway.guard_request(Fixture.request(), Fixture.context(), opts)

      explicit =
        ToolGateway.guard_request(
          Fixture.request(),
          Fixture.context(),
          Keyword.put(opts, :effect_binding, :off)
        )

      assert default == explicit
      assert {:confirm, _} = default.verdict
      assert Map.take(default.audit_metadata, @effect_keys) == %{}
      refute Map.has_key?(default.audit_metadata, :payload_digest)
    end

    test "does not require a record or refuse consume_confirmation: false" do
      decision =
        ToolGateway.guard_request(
          Fixture.drop_record(Fixture.request()),
          Fixture.context(),
          Fixture.gateway_opts(effect_binding: :off, consume_confirmation: false)
        )

      assert {:confirm, _} = decision.verdict
    end

    test "leaves guard_result/3 untouched" do
      result = %{"result" => %{"content" => [%{"type" => "text", "text" => "moved"}]}}
      context = Keyword.put(Fixture.context(), :tool, "cell.move")

      assert ToolGateway.guard_result(result, context, effect_binding: :required) ==
               ToolGateway.guard_result(result, context, [])
    end
  end

  describe "the option value" do
    test "any value other than :off and :required blocks" do
      for value <- [:on, true, "required", nil, 1] do
        decision = guard(Fixture.request(), effect_binding: value)

        assert decision.verdict == :blocked
        assert decision.audit_metadata.deny_reason == :invalid_effect_binding
        assert Map.take(decision.audit_metadata, @effect_keys) == %{}
      end
    end

    test "is checked before the manifest" do
      request = put_in(Fixture.request(), ["params", "name"], "cell.weld")

      assert guard(request, effect_binding: :on).audit_metadata.deny_reason ==
               :invalid_effect_binding

      assert guard(request).audit_metadata.deny_reason == :unknown_manifest
    end
  end

  describe "effect_binding: :required" do
    test "a valid record passes to the gate and the decision records the digests" do
      decision = guard(Fixture.request())
      {:ok, binding_digest} = EffectAuthority.binding_digest(Fixture.record())
      {:ok, operation_key} = EffectAuthority.operation_key(Fixture.record())

      assert {:confirm, _} = decision.verdict
      assert decision.audit_metadata.effect_binding == :valid
      assert decision.audit_metadata.effect_binding_digest == binding_digest
      assert decision.audit_metadata.effect_operation_key == operation_key

      for key <- @digest_keys do
        assert decision.audit_metadata[key] =~ ~r/\A[0-9a-f]{64}\z/
      end
    end

    test "the recorded digests are the ones a confirmation token binds" do
      decision = guard(Fixture.request())

      {:ok, token} = issue_token(decision)

      {:ok, claims} =
        Confirmation.verify(
          token,
          SecurityPayload.for_gate(Fixture.request(), :request),
          gateway_context(),
          Fixture.confirmation_key(),
          now: Fixture.now(),
          manifest: decision.audit_metadata.manifest_digest,
          consume: false
        )

      for key <- @digest_keys do
        assert claims[Atom.to_string(key)] == decision.audit_metadata[key]
      end
    end

    test "a missing record blocks and still records the digests" do
      {response, decision} = guarded(Fixture.drop_record(Fixture.request()))

      assert decision.audit_metadata.deny_reason == :effect_binding_required
      assert decision.audit_metadata.effect_binding == :absent
      refute Map.has_key?(decision.audit_metadata, :effect_binding_digest)
      assert Enum.all?(@digest_keys, &is_binary(decision.audit_metadata[&1]))
      assert response["error"]["code"] == -31_990
      assert response["error"]["data"]["status"] == "blocked"
    end

    test "a malformed record blocks" do
      malformed = [
        Map.put(Fixture.record(), "extra", "x"),
        Map.delete(Fixture.record(), "not_after"),
        "not a record"
      ]

      for record <- malformed do
        {response, decision} = guarded(Fixture.put_record(Fixture.request(), record))

        assert decision.audit_metadata.deny_reason == :invalid_effect_binding
        assert decision.audit_metadata.effect_binding == :invalid
        assert response["error"]["code"] == -31_990
      end
    end

    test "consume_confirmation: false blocks before the record is read" do
      for value <- [false, nil] do
        {response, decision} =
          guarded(Fixture.drop_record(Fixture.request()), consume_confirmation: value)

        assert decision.audit_metadata.deny_reason == :effect_replay_protection_required
        assert response["error"]["code"] == -31_990
      end
    end

    test "a request that cannot be digested blocks and records no digest" do
      request = put_in(Fixture.request(), ["params", "arguments", "speed_mm_s"], nil)
      {response, decision} = guarded(request)

      assert decision.audit_metadata.deny_reason == :invalid_payload
      assert Map.take(decision.audit_metadata, @digest_keys) == %{}
      assert decision.audit_metadata.effect_binding == :valid
      assert response["error"]["code"] == -31_990

      assert guard(Fixture.drop_record(request)).audit_metadata.deny_reason == :invalid_payload
    end

    test "existing denials keep their precedence over the record check" do
      unknown_tool =
        put_in(Fixture.drop_record(Fixture.request()), ["params", "name"], "cell.weld")

      unsandboxed = Keyword.delete(Fixture.context(), :metadata)

      assert guard(unknown_tool).audit_metadata.deny_reason == :unknown_manifest

      assert ToolGateway.guard_request(
               Fixture.drop_record(Fixture.request()),
               unsandboxed,
               Fixture.gateway_opts()
             ).audit_metadata.deny_reason == :sandbox_required
    end

    test "a refusal carries no record or argument value" do
      {response, decision} =
        guarded(Fixture.put_record(Fixture.request(), Map.put(Fixture.record(), "extra", "x")))

      rendered = inspect({response, decision.audit_metadata, decision.reason}, limit: :infinity)

      for value <- ["urn:example:cell-a:arm-1", "op-0001", "cal-r3", "example-bundle"] do
        refute rendered =~ value
      end
    end

    test "a decision allowed without confirmation records the action digest" do
      {:ok, policy} =
        PolicyFile.parse(
          "version 3\n[rules]\ndefault block\nallow tool:cell.move actor:#{Fixture.actor()}\n"
        )

      decision = guard(Fixture.request(), boundary_policy: policy)

      assert decision.verdict == :allowed
      assert decision.action == :allow
      assert Enum.all?(@digest_keys, &is_binary(decision.audit_metadata[&1]))
      refute Map.has_key?(decision.audit_metadata, :effect_authority_expires_at)
    end

    test "an allowed decision records when the accepted token expires" do
      pending = guard(Fixture.request())
      {:ok, token} = issue_token(pending, ttl_ms: 60_000)
      allowed = guard(Attestation.attach_confirmation(Fixture.request(), token))

      assert allowed.verdict == :allowed
      assert allowed.audit_metadata.confirmation_expires_at == "2026-11-19T12:02:00.000Z"
      assert allowed.audit_metadata.effect_authority_expires_at == "2026-11-19T12:02:00.000Z"
      refute Map.has_key?(pending.audit_metadata, :effect_authority_expires_at)
    end

    test "the recorded expiry drops sub-millisecond digits" do
      pending = guard(Fixture.request())

      {:ok, token} =
        ToolGateway.issue_confirmation(
          Fixture.request(),
          Fixture.context(),
          pending,
          Fixture.confirmation_key(),
          now: ~U[2026-11-19 12:01:00.000999Z],
          manifest: pending.audit_metadata.manifest_digest
        )

      allowed = guard(Attestation.attach_confirmation(Fixture.request(), token))

      assert allowed.audit_metadata.confirmation_expires_at == "2026-11-19T12:06:00.000999Z"
      assert allowed.audit_metadata.effect_authority_expires_at == "2026-11-19T12:06:00.000Z"
    end

    test "an accepted token allows the request once" do
      pending = guard(Fixture.request())
      {:ok, token} = issue_token(pending)
      confirmed = Attestation.attach_confirmation(Fixture.request(), token)

      allowed = guard(confirmed)
      replayed = guard(confirmed)

      assert allowed.verdict == :allowed
      assert allowed.action == :allow

      assert Map.take(allowed.audit_metadata, @digest_keys) ==
               Map.take(pending.audit_metadata, @digest_keys)

      assert replayed.verdict == :blocked
      assert replayed.audit_metadata.confirmation_reason == :replay_detected
    end

    test "the MCP gateway facade passes the option through" do
      decision =
        Gateway.guard_confirmed_request(
          Fixture.drop_record(Fixture.request()),
          Fixture.context(),
          Fixture.gateway_opts()
        )

      assert decision.audit_metadata.deny_reason == :effect_binding_required
    end

    test "ToolGateway.Base does not read the option" do
      decision =
        ToolGateway.Base.guard_request(
          Fixture.drop_record(Fixture.request()),
          Fixture.context(),
          effect_binding: :required
        )

      refute decision.audit_metadata[:deny_reason] == :effect_binding_required
      assert Map.take(decision.audit_metadata, @effect_keys) == %{}
    end
  end

  describe "inbound attestation with effect_binding: :required" do
    setup do
      {:ok, capability} = CapabilityManifest.new(Fixture.manifests()["cell.move"])
      pending = guard(Fixture.request())

      {:ok, envelope} =
        ToolGateway.attest_request(pending, gateway_context(),
          payload: Fixture.request(),
          signer: TestSigner,
          keyid: "trusted",
          now: Fixture.now(),
          nonce: "effect-attestation-nonce",
          manifest: capability
        )

      opts = [attestation: :required, trust_material: %{"trusted" => TestSigner.public_key()}]

      %{attested: Map.put(Fixture.request(), "_agent_trust", envelope), opts: opts}
    end

    test "the nonce is consumed once, on the pass that allows execution", context do
      %{attested: attested, opts: opts} = context

      first = guard(attested, opts)
      again = guard(attested, opts)

      assert {:confirm, _} = first.verdict
      assert {:confirm, _} = again.verdict

      {:ok, token} = issue_token(first)
      allowed = guard(Attestation.attach_confirmation(attested, token), opts)

      assert allowed.verdict == :allowed

      {:ok, second_token} = issue_token(first)

      {response, refused} = guarded(Attestation.attach_confirmation(attested, second_token), opts)

      assert refused.audit_metadata.deny_reason == :invalid_attestation
      assert refused.audit_metadata.attestation_error == :replay_detected
      assert response["error"]["code"] == -31_985
      assert response["error"]["data"]["attestation_error"] == "replay_detected"
    end

    test "with :off the nonce is never consumed", %{attested: attested, opts: opts} do
      opts = Keyword.put(opts, :effect_binding, :off)
      first = guard(attested, opts)

      for _ <- 1..2 do
        {:ok, token} = issue_token(first)
        allowed = guard(Attestation.attach_confirmation(attested, token), opts)

        assert allowed.verdict == :allowed
        refute Map.has_key?(allowed.audit_metadata, :effect_authority_expires_at)
      end
    end

    test "the recorded expiry is the earlier of the token and the attestation", %{opts: opts} do
      {:ok, capability} = CapabilityManifest.new(Fixture.manifests()["cell.move"])
      pending = guard(Fixture.request())

      {:ok, envelope} =
        ToolGateway.attest_request(pending, gateway_context(),
          payload: Fixture.request(),
          signer: TestSigner,
          keyid: "trusted",
          now: Fixture.now(),
          ttl_ms: 30_000,
          nonce: "short-attestation-nonce",
          manifest: capability
        )

      attested = Map.put(Fixture.request(), "_agent_trust", envelope)

      for {token_ttl_ms, expected} <- [
            {300_000, "2026-11-19T12:01:30.000Z"},
            {10_000, "2026-11-19T12:01:10.000Z"}
          ] do
        ReplayStore.clear()
        {:ok, token} = issue_token(guard(attested, opts), ttl_ms: token_ttl_ms)
        allowed = guard(Attestation.attach_confirmation(attested, token), opts)

        assert allowed.verdict == :allowed
        assert allowed.audit_metadata.effect_authority_expires_at == expected
      end
    end

    test "a missing required envelope blocks before the record is read", %{opts: opts} do
      decision = guard(Fixture.drop_record(Fixture.request()), opts)

      assert decision.audit_metadata.deny_reason == :invalid_attestation
    end
  end

  describe "telemetry" do
    setup do
      ref = :telemetry_test.attach_event_handlers(self(), [[:sigil_guard, :mcp, :request]])
      on_exit(fn -> :telemetry.detach(ref) end)
      %{telemetry: ref}
    end

    test "the effect keys appear only with :required", %{telemetry: ref} do
      guard(Fixture.request(), effect_binding: :off)
      assert_receive {_, ^ref, _, off}
      assert Map.take(off, @effect_keys) == %{}

      decision = guard(Fixture.request())
      assert_receive {event, ^ref, measurements, required}

      assert Map.take(required, @effect_keys) ==
               Map.take(decision.audit_metadata, @effect_keys)

      refute Map.has_key?(required, :payload_digest)

      low = Telemetry.otel_attributes(event, measurements, required)

      high =
        Telemetry.otel_attributes(event, measurements, required, include_high_cardinality: true)

      assert low["sigilguard.effect.binding"] == "valid"
      refute Map.has_key?(low, "sigilguard.effect.binding_digest")
      refute Map.has_key?(low, "sigilguard.effect.operation_key")

      assert high["sigilguard.effect.binding_digest"] ==
               decision.audit_metadata.effect_binding_digest

      assert high["sigilguard.effect.operation_key"] ==
               decision.audit_metadata.effect_operation_key
    end
  end

  defp gateway_context,
    do: SecurityPayload.context(Fixture.request(), :request, Fixture.context())

  defp guard(request, overrides \\ []) do
    ToolGateway.guard_request(request, Fixture.context(), Fixture.gateway_opts(overrides))
  end

  defp guarded(request, overrides \\ []) do
    assert {:error, response, decision} =
             ToolGateway.guarded_request(
               request,
               Fixture.context(),
               Fixture.gateway_opts(overrides)
             )

    {response, decision}
  end

  defp issue_token(decision, opts \\ []) do
    ToolGateway.issue_confirmation(
      Fixture.request(),
      Fixture.context(),
      decision,
      Fixture.confirmation_key(),
      Keyword.merge([now: Fixture.now(), manifest: decision.audit_metadata.manifest_digest], opts)
    )
  end
end
