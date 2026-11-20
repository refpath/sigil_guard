defmodule SigilGuard.Conformance.UntrustedInputTest do
  @moduledoc """
  No public entry point that accepts caller or peer data may raise on it.

  Each property feeds arbitrary terms and single-point mutations of a valid
  fixture, and asserts the documented result shape. The properties sample the
  input space; a pass is not a proof that no raising input exists.
  """

  use ExUnit.Case, async: false

  use ExUnitProperties

  alias SigilGuard.AgentCard
  alias SigilGuard.Attestation
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Audit.Export
  alias SigilGuard.Audit.Proof
  alias SigilGuard.Boundary
  alias SigilGuard.BoundaryPolicy
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.CapabilityManifest
  alias SigilGuard.Confirmation
  alias SigilGuard.Decision
  alias SigilGuard.EffectAuthorityFixture, as: Fixture
  alias SigilGuard.FixturePath
  alias SigilGuard.MCP.SecurityPayload
  alias SigilGuard.Quarantine
  alias SigilGuard.ReplayStore
  alias SigilGuard.Runtime.Gate
  alias SigilGuard.TestMutation, as: Mutation
  alias SigilGuard.ToolGateway
  alias SigilGuard.TrustBundle

  @digest String.duplicate("a", 64)
  @bundle_now ~U[2026-07-03 12:00:00.000Z]
  @result %{
    "jsonrpc" => "2.0",
    "id" => 1,
    "result" => %{"content" => [%{"type" => "text", "text" => "moved"}]}
  }
  @option_keys [
    :manifests,
    :boundary_policy,
    :confirmation_token,
    :confirmation_key,
    :attestation,
    :trust_material,
    :now,
    :effect_binding,
    :require_manifest,
    :resource,
    :audience,
    :server,
    :protocol_version,
    :consume_confirmation,
    :confirmation,
    :hooks,
    :on_sensitive,
    :max_input_bytes,
    :risk_level,
    :trust_bundle,
    :indicator_sets,
    :patterns,
    :request_action_digest,
    :adaptive_detector,
    :hook_timeout_ms,
    :max_skew_ms
  ]

  setup do
    ReplayStore.clear()
    on_exit(&ReplayStore.clear/0)
    :ok
  end

  describe "tool gateway" do
    property "a mutated or arbitrary request gets a decision and a JSON-RPC answer" do
      check all(request <- one_of([Mutation.mutant(Fixture.request()), Mutation.term()])) do
        assert %Decision{} =
                 ToolGateway.guard_request(request, Fixture.context(), Fixture.gateway_opts())

        assert answer?(ToolGateway.guarded_request(request, [], []))
      end
    end

    property "a mutated or arbitrary result gets a decision and a JSON-RPC answer" do
      check all(result <- one_of([Mutation.mutant(@result), Mutation.term()])) do
        assert %Decision{} = ToolGateway.guard_result(result, Fixture.context(), [])
        assert answer?(ToolGateway.guarded_result(result, [], []))
      end
    end

    property "a mutated context or option value is answered, not raised" do
      check all(
              context <- one_of([Mutation.mutant(Map.new(Fixture.context())), Mutation.term()]),
              key <- member_of(@option_keys),
              value <- Mutation.term(),
              max_runs: 300
            ) do
        opts = Keyword.put(Fixture.gateway_opts(), key, value)

        assert %Decision{} = ToolGateway.guard_request(Fixture.request(), context, opts)
        assert %Decision{} = ToolGateway.guard_result(@result, context, opts)
      end
    end

    property "a decision with mutated audit metadata still renders a response" do
      pending =
        ToolGateway.guard_request(Fixture.request(), Fixture.context(), Fixture.gateway_opts())

      check all(metadata <- Mutation.mutant(pending.audit_metadata)) do
        if is_map(metadata) and not is_struct(metadata) do
          decision = %{pending | audit_metadata: metadata}

          assert %{"jsonrpc" => "2.0"} = ToolGateway.response_for_decision(decision, 1, [])
        end
      end
    end

    property "stream chunks of any bytes never raise" do
      check all(chunks <- list_of(binary(max_length: 80), max_length: 6)) do
        stream =
          Enum.reduce(chunks, ToolGateway.stream_result(Fixture.context(), []), fn chunk,
                                                                                   stream ->
            {stream, result} = ToolGateway.guarded_result_chunk(stream, chunk, [])
            assert elem(result, 0) in [:ok, :error]
            stream
          end)

        assert {_, result} = ToolGateway.finish_guarded_result_stream(stream, [])
        assert elem(result, 0) in [:ok, :error]
      end
    end
  end

  describe "manifests" do
    setup do
      manifest = FixturePath.read_unexpiring_manifest!()

      entry = %{
        "name" => manifest["name"],
        "description" => manifest["description"],
        "inputSchema" => manifest["input_schema"],
        "annotations" => manifest["annotations"]
      }

      %{manifest: manifest, entry: entry}
    end

    property "a mutated manifest is accepted or refused with a reason", %{manifest: manifest} do
      check all(mutated <- Mutation.mutant(manifest), max_runs: 300) do
        assert tagged?(CapabilityManifest.new(mutated))

        assert CapabilityManifest.verify(manifest, mutated) == :ok or
                 match?({:error, _}, CapabilityManifest.verify(manifest, mutated))

        assert %Decision{} =
                 ToolGateway.guard_request(%{"params" => %{"name" => manifest["name"]}}, [],
                   manifests: %{manifest["name"] => mutated}
                 )
      end
    end

    property "a mutated tools/list entry is verified or refused", context do
      opts = [manifests: %{context.manifest["name"] => context.manifest}, server: "repo-mcp"]

      check all(entry <- one_of([Mutation.mutant(context.entry), Mutation.term()])) do
        assert tagged?(ToolGateway.verify_manifest(entry, opts))
        assert tagged?(ToolGateway.verify_list_changed([entry], opts))
      end
    end
  end

  describe "signed material" do
    property "a mutated attestation envelope verifies or is refused" do
      envelope = FixturePath.read_json!("agent_trust/tool_request/envelope.json")
      trust = %{"unknown" => :binary.copy(<<1>>, 32)}

      check all(
              mutated <- one_of([Mutation.mutant(envelope), Mutation.term()]),
              max_runs: 300
            ) do
        assert tagged?(Attestation.verify(mutated, trust, now: Fixture.now()))
        assert tagged?(Attestation.verify(envelope, mutated, now: Fixture.now()))
        assert tagged?(Envelope.decode(mutated))
        assert tagged?(Envelope.verify(mutated, trust))

        assert Attestation.fetch(mutated) == :error or
                 match?({:ok, _}, Attestation.fetch(mutated))
      end
    end

    property "a mutated trust bundle envelope or document verifies or is refused" do
      envelope = FixturePath.read_json!("trust_bundle/minimal/envelope.json")
      {:ok, bytes} = Base.url_decode64(envelope["payload"], padding: false)
      document = Jason.decode!(bytes)

      check all(
              mutated <- one_of([Mutation.mutant(envelope), Mutation.term()]),
              changed <- Mutation.mutant(document),
              max_runs: 300
            ) do
        assert tagged?(TrustBundle.verify(mutated, now: @bundle_now))
        assert tagged?(TrustBundle.verify(with_document(envelope, changed), now: @bundle_now))
      end
    end

    property "a mutated agent card or card envelope verifies or is refused" do
      envelope = FixturePath.read_json!("agent_cards/research_peer.envelope.json")
      card = FixturePath.read_json!("agent_cards/research_peer.card.json")

      check all(
              mutated <- one_of([Mutation.mutant(envelope), Mutation.term()]),
              changed <- Mutation.mutant(card)
            ) do
        assert tagged?(AgentCard.verify(mutated, %{}, now: Fixture.now()))
        assert tagged?(AgentCard.new(changed))
        assert tagged?(AgentCard.digest(changed))
      end
    end

    property "any string or forged claim set is a refused confirmation token" do
      payload = %{"tool" => "cell.move"}
      context = [phase: :tool_request, origin: :model, sink: :tool]

      check all(
              token <- one_of([binary(max_length: 120), Mutation.term()]),
              claims <-
                map_of(member_of(~w(v typ alg actor nonce expires_at decision)), Mutation.term(),
                  max_length: 4
                )
            ) do
        assert {:error, _} =
                 Confirmation.verify(token, payload, context, Fixture.confirmation_key())

        assert {:error, _} =
                 Confirmation.verify(
                   forged_token(claims),
                   payload,
                   context,
                   Fixture.confirmation_key(),
                   consume: false
                 )
      end
    end
  end

  describe "policy and digests" do
    property "the policy kernel decides on any boundary and the parser on any text" do
      {:ok, policy} = PolicyFile.parse(FixturePath.read!("boundary_policy/canonical.policy"))
      text = FixturePath.read!("boundary_policy/canonical.policy")

      boundary = %{
        phase: :tool_request,
        source: :model,
        sink: :tool,
        trust_level: :high,
        action_digest: @digest,
        payload_digest: @digest,
        context_digest: @digest
      }

      check all(
              mutated <- one_of([Mutation.mutant(boundary), Mutation.term()]),
              cut <- integer(0..byte_size(text)),
              junk <- binary(max_length: 24),
              max_runs: 300
            ) do
        assert %Decision{} = BoundaryPolicy.evaluate(mutated, policy: policy)
        assert %Decision{} = BoundaryPolicy.evaluate(boundary, policy: mutated)

        assert Boundary.validate(mutated) == :ok or
                 match?({:error, _}, Boundary.validate(mutated))

        spliced =
          binary_part(text, 0, cut) <> junk <> binary_part(text, cut, byte_size(text) - cut)

        assert tagged?(PolicyFile.parse(spliced))
        assert tagged?(PolicyFile.parse(mutated))
      end
    end

    property "the gate decides on any payload and context" do
      check all(
              payload <- Mutation.term(),
              context <- one_of([Mutation.mutant(Map.new(Fixture.context())), Mutation.term()])
            ) do
        assert %Decision{} = Gate.evaluate(payload, context, [])
      end
    end

    property "digest, projection, and scanning functions return a tagged result" do
      check all(term <- Mutation.term(), max_runs: 300) do
        assert tagged?(Digest.payload_digest(term))
        assert tagged?(Digest.context_digest(:tool_request, term))
        assert tagged?(Digest.action_digest(:tool_request, term, term, []))
        assert tagged?(Digest.digests(:tool_result, term, term, request_action_digest: @digest))
        assert tagged?(Confirmation.fetch_action_digest(term, term))
        assert tagged?(JCS.encode(term))
        assert is_map(SecurityPayload.request(term))
        assert %{binding: %{}} = SecurityPayload.for_gate(term, :result)
        assert %SigilGuard.Context{} = SecurityPayload.context(term, :request, term)
        assert %{verdict: _} = Quarantine.inspect(term, term, [])
        assert %{verdict: _} = Quarantine.inspect("text", term, [])
      end
    end
  end

  describe "audit evidence" do
    property "a mutated checkpoint, export, or proof verifies or is refused" do
      checkpoint = FixturePath.read_json!("audit_proofs/checkpoint_5.json")
      export = FixturePath.read_json!("audit_proofs/export.json")
      inclusion = FixturePath.read_json!("audit_proofs/inclusion_5.json")
      consistency = FixturePath.read_json!("audit_proofs/consistency_3_5.json")

      check all(
              mutated_checkpoint <- one_of([Mutation.mutant(checkpoint), Mutation.term()]),
              mutated_export <- Mutation.mutant(export),
              mutated_inclusion <- Mutation.mutant(inclusion),
              mutated_consistency <- Mutation.mutant(consistency)
            ) do
        assert outcome?(Checkpoint.verify(mutated_checkpoint, [], []))
        assert outcome?(Export.verify(mutated_export, [], []))
        assert outcome?(Proof.verify_inclusion(mutated_inclusion, "aa", @digest))
        assert outcome?(Proof.verify_consistency(mutated_consistency, @digest, @digest))
      end
    end
  end

  describe "inputs that used to raise" do
    @improper [1 | 2]

    test "a struct or an improper list as a request or result" do
      for input <- [~U[2026-11-19 12:01:00.000Z], %{"params" => @improper}, @improper] do
        assert answer?(ToolGateway.guarded_request(input, [], []))
        assert answer?(ToolGateway.guarded_result(input, [], []))
        assert %{text: text} = SecurityPayload.for_gate(input, :request)
        assert is_binary(text)
      end
    end

    test "scanner text skips keys that are neither strings nor atoms" do
      binding = %{1 => "one", {1, 2} => "tuple", "key" => ["value" | "tail"], atom: "a"}

      assert SecurityPayload.scan_text(binding) =~ "tuple"
      assert SecurityPayload.scan_text(binding) =~ "tail"
      assert SecurityPayload.scan_text(%{"b" => "2", "a" => "1"}) == "a\n1\nb\n2"
    end

    test "an option of the wrong type blocks instead of raising" do
      manifest = FixturePath.read_unexpiring_manifest!()
      request = %{"params" => %{"name" => manifest["name"], "arguments" => %{}}}
      context = [trust_level: :high, metadata: %{sandbox_id: "s", isolation_level: "container"}]

      guard =
        &ToolGateway.guard_request(request, context, [
          {:manifests, %{manifest["name"] => manifest}} | &1
        ])

      assert guard.(max_skew_ms: 3.0).audit_metadata.deny_reason == :invalid_manifest
      assert guard.(max_skew_ms: -1).audit_metadata.deny_reason == :invalid_manifest
      assert guard.(audience: @improper).audit_metadata.deny_reason == :audience_mismatch
      assert guard.(audience: "repo-mcp").verdict == :allowed
    end

    test "context metadata that is not a plain map names no sandbox" do
      manifest = FixturePath.read_unexpiring_manifest!()
      request = %{"params" => %{"name" => manifest["name"], "arguments" => %{}}}

      for metadata <- [[sandbox_id: "s"], "metadata", 5, ~U[2026-11-19 12:01:00.000Z]] do
        decision =
          ToolGateway.guard_request(request, [trust_level: :high, metadata: metadata],
            manifests: %{manifest["name"] => manifest}
          )

        assert decision.audit_metadata.deny_reason == :sandbox_required
      end
    end

    test "malformed indicator sets fail closed as a scanner failure" do
      for sets <- [%{injection: 5}, %{injection: [5]}, %{injection: [%{}]}] do
        decision =
          Gate.evaluate("build completed", [phase: :tool_result, sink: :model],
            indicator_sets: sets
          )

        assert decision.action == :block
        assert decision.audit_metadata.scanner_error == :scanner_failed
      end
    end

    test "a foreign struct is not a context or a boundary" do
      datetime = ~U[2026-11-19 12:01:00.000Z]

      assert SigilGuard.Context.cast(datetime) == {:error, :invalid_context}
      assert SigilGuard.Context.overrides(datetime) == %{}
      assert %Decision{action: :block} = Gate.evaluate("text", datetime, [])
      assert %Decision{action: :block} = BoundaryPolicy.evaluate(datetime, [])
      assert %Decision{action: :block} = BoundaryPolicy.evaluate(%{1 => 2}, [])
    end

    test "an improper list is not a JSON array" do
      assert_raise ArgumentError, fn -> SigilGuard.Canonical.LegacyJSON.encode(@improper) end

      assert Confirmation.fetch_action_digest(%{"a" => @improper}, []) ==
               {:error, :invalid_payload}

      assert Digest.payload_digest(@improper) == {:error, :invalid_payload}
      assert Attestation.strip_metadata(@improper) == @improper
    end

    test "a bundle document whose roles are not a map is refused" do
      envelope = FixturePath.read_json!("trust_bundle/minimal/envelope.json")
      {:ok, bytes} = Base.url_decode64(envelope["payload"], padding: false)
      document = Jason.decode!(bytes)

      for roles <- [0, "roles", [], %{"root" => 0}] do
        mutated = with_document(envelope, Map.put(document, "roles", roles))

        assert {:error, _} = TrustBundle.verify(mutated, now: @bundle_now)
      end
    end
  end

  defp answer?({:ok, %Decision{}}), do: true
  defp answer?({:ok, %{}, %Decision{}}), do: true
  defp answer?({:error, %{"error" => %{"code" => code}}, %Decision{}}), do: is_integer(code)
  defp answer?(_), do: false

  defp tagged?({:ok, _}), do: true
  defp tagged?({:error, _}), do: true
  defp tagged?(_), do: false

  defp outcome?(result), do: result in [:ok, true, false] or tagged?(result)

  defp with_document(envelope, document) do
    case JCS.encode(document) do
      {:ok, bytes} -> Map.put(envelope, "payload", Base.url_encode64(bytes, padding: false))
      {:error, _} -> envelope
    end
  end

  defp forged_token(claims) do
    base = %{
      "v" => 2,
      "typ" => "sigil_guard.confirmation.v2",
      "alg" => "HS256",
      "decision" => "confirm",
      "actor" => "agent-1",
      "action" => "confirm",
      "action_digest" => @digest,
      "payload_digest" => @digest,
      "context_digest" => @digest,
      "issued_at" => "2026-11-19T12:00:00.000Z",
      "expires_at" => "2026-11-19T12:05:00.000Z",
      "nonce" => String.duplicate("a", 32)
    }

    body =
      try do
        IO.iodata_to_binary(SigilGuard.Canonical.LegacyJSON.encode(Map.merge(base, claims)))
      rescue
        _ in [ArgumentError, Jason.EncodeError, Protocol.UndefinedError] -> "{}"
      end

    mac = :crypto.mac(:hmac, :sha256, Fixture.confirmation_key(), body)

    Base.url_encode64(body, padding: false) <> "." <> Base.url_encode64(mac, padding: false)
  end
end
