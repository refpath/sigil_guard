defmodule SigilGuard.AttestationFromDecisionTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Attestation
  alias SigilGuard.Context
  alias SigilGuard.Decision
  alias SigilGuard.TrustProfile

  @now ~U[2026-07-03 12:00:00.000Z]
  @payload %{"method" => "tools/call", "params" => %{"name" => "repo_file_write"}}
  @context %Context{
    phase: :tool_request,
    actor: "spiffe://agents/requester",
    identity: "fallback-identity",
    trust_level: :medium,
    origin: :user,
    sink: :tool,
    tool: "repo_file_write"
  }

  describe "from_decision/3" do
    test "builds a profile-valid statement from a tool-request decision" do
      assert {:ok, statement} =
               Attestation.from_decision(decision(), @context,
                 payload: @payload,
                 now: @now,
                 ttl_ms: 60_000,
                 nonce: "nonce-1"
               )

      assert TrustProfile.validate(statement) == {:ok, statement}
      assert statement["predicateType"] == "https://sigilguard.dev/attestation/tool_request/v1"
      assert get_in(statement, ["predicate", "actor", "id"]) == @context.actor
      assert get_in(statement, ["predicate", "actor", "trust_level"]) == "medium"
      assert get_in(statement, ["predicate", "verdict"]) == "allow"
      assert get_in(statement, ["predicate", "issued_at"]) == DateTime.to_iso8601(@now)
      assert get_in(statement, ["predicate", "expires_at"]) == "2026-07-03T12:01:00.000Z"
      assert get_in(statement, ["predicate", "nonce"]) == "nonce-1"
      assert subject_names(statement) == ["action", "payload", "context"]
    end

    test "adds tool request resource mirrors from map contexts and string scopes" do
      context = %{
        phase: :tool_request,
        actor: "spiffe://agents/requester",
        trust_level: :medium,
        origin: :model,
        sink: :tool,
        tool: "repo_file_write",
        mcp_server: "repo-mcp",
        resource_uri: "mcp://repo-mcp"
      }

      assert {:ok, statement} =
               Attestation.from_decision(
                 decision(verdict: {:confirm, "review"}, action: :confirm),
                 context,
                 payload: @payload,
                 statement_type: "tool_request",
                 now: @now,
                 manifest_digest: String.duplicate("d", 64),
                 audience: "repo-mcp",
                 scopes: "repo:write"
               )

      predicate = statement["predicate"]
      assert predicate["verdict"] == "confirm"

      assert predicate["tool"] == %{
               "name" => "repo_file_write",
               "mcp_server" => "repo-mcp",
               "manifest_digest" => String.duplicate("d", 64)
             }

      assert predicate["resource"] == %{
               "uri" => "mcp://repo-mcp",
               "audience" => "repo-mcp",
               "scope" => "repo:write"
             }
    end

    test "adds released sanitized result status from explicit result opts" do
      context = %{
        phase: :tool_result,
        actor: "spiffe://agents/requester",
        trust_level: :medium,
        origin: :tool,
        sink: :model,
        tool: "repo_file_write"
      }

      assert {:ok, statement} =
               Attestation.from_decision(decision(action: :redact, phase: :tool_result), context,
                 payload: @payload,
                 now: @now,
                 request_action_digest: String.duplicate("a", 64),
                 quarantine_status: :released_sanitized,
                 indicator_ids: ["z", 123, nil, %{}, "a", :ignore_instructions, "a"],
                 scanner_hit_count: 2
               )

      assert statement["predicate"]["quarantine"] == %{
               "status" => "released_sanitized",
               "indicator_ids" => ["a", "ignore_instructions", "z"]
             }

      assert statement["predicate"]["scanner"] == %{"hit_count" => 2, "redacted" => true}
    end

    test "builds result predicates from decision fallback metadata" do
      context = [
        phase: :tool_result,
        actor: "spiffe://agents/requester",
        trust_level: :medium,
        origin: :tool,
        sink: :model,
        tool: "repo_file_write"
      ]

      decision =
        decision(action: :allow, phase: :tool_result)
        |> Map.put(:hits, [%{name: "secret"}])
        |> Map.put(:indicators, [%{"id" => "detected-indicator"}])

      assert {:ok, statement} =
               Attestation.from_decision(decision, context,
                 payload: @payload,
                 now: @now,
                 request_action_digest: String.duplicate("b", 64),
                 output_schema_sha256: nil
               )

      predicate = statement["predicate"]
      refute Map.has_key?(predicate, "output_schema_sha256")

      assert predicate["quarantine"] == %{
               "status" => "none",
               "indicator_ids" => ["detected-indicator"]
             }

      assert predicate["scanner"] == %{"hit_count" => 1, "redacted" => false}
    end

    test "omits empty tool request mirrors" do
      context = %{@context | tool: nil, mcp_server: nil, resource_uri: nil}

      assert {:ok, statement} =
               Attestation.from_decision(decision(), context,
                 payload: @payload,
                 now: @now,
                 scopes: []
               )

      predicate = statement["predicate"]
      refute Map.has_key?(predicate, "tool")
      assert predicate["resource"] == %{"audience" => "internal"}
    end

    test "explicit statement type wins over phase-derived type" do
      payload = %{"repository" => "repo", "operation" => "write", "paths" => ["b.ex", "a.ex"]}

      assert {:ok, statement} =
               Attestation.from_decision(decision(), @context,
                 payload: payload,
                 statement_type: :repo_change,
                 now: @now
               )

      assert statement["predicateType"] == "https://sigilguard.dev/attestation/repo_change/v1"
      assert get_in(statement, ["predicate", "statement_type"]) == "repo_change"
    end

    test "falls back from context actor to identity" do
      context = %{@context | actor: nil, identity: "spiffe://agents/fallback"}

      assert {:ok, statement} =
               Attestation.from_decision(decision(), context, payload: @payload, now: @now)

      assert get_in(statement, ["predicate", "actor", "id"]) == "spiffe://agents/fallback"
    end

    test "a release statement comes only from an explicit statement_type" do
      payload = %{
        "package" => "sigil_guard",
        "version" => "1.0.0",
        "artifacts" => [
          %{"name" => "sigil_guard-1.0.0.tar", "sha256" => String.duplicate("a", 64)}
        ]
      }

      assert {:ok, implicit} =
               Attestation.from_decision(decision(), @context, payload: payload, now: @now)

      assert implicit["predicateType"] == "https://sigilguard.dev/attestation/tool_request/v1"

      assert {:ok, statement} =
               Attestation.from_decision(decision(), @context,
                 payload: payload,
                 statement_type: "release",
                 now: @now
               )

      assert statement["predicateType"] == "https://sigilguard.dev/attestation/release/v1"
    end

    test "supports agent request extension fields" do
      payload = %{"peer_agent" => "spiffe://agents/responder", "capability" => "summarize"}
      context = %{@context | phase: :tool_request, trust_level: :low}
      decision = decision(action: :quarantine)

      assert {:ok, statement} =
               Attestation.from_decision(decision, context,
                 payload: payload,
                 statement_type: :agent_request,
                 now: @now,
                 peer_trust: :low
               )

      predicate = statement["predicate"]
      assert predicate["statement_type"] == "agent_request"
      assert predicate["verdict"] == "quarantine"
      assert predicate["peer_agent"] == %{"id" => "spiffe://agents/responder"}
      assert predicate["peer_trust"] == "low"
      assert predicate["capability"] == "summarize"
    end

    test "supports agent response extension fields" do
      payload = %{
        "peer_agent" => "spiffe://agents/responder",
        "capability" => "summarize",
        "status" => "error"
      }

      assert {:ok, statement} =
               Attestation.from_decision(decision(action: :quarantine), @context,
                 payload: payload,
                 statement_type: :agent_response,
                 now: @now,
                 request_action_digest: String.duplicate("a", 64),
                 peer_trust: :medium
               )

      predicate = statement["predicate"]
      assert predicate["statement_type"] == "agent_response"
      assert predicate["status"] == "error"
      assert predicate["request_action_digest"] == String.duplicate("a", 64)
      assert predicate["quarantined"] == true
    end

    test "maps blocked and confirmation decisions into predicate verdicts" do
      for {decision, verdict} <- [
            {decision(verdict: :blocked, action: :block), "block"},
            {decision(verdict: {:confirm, "token"}, action: :confirm), "confirm"}
          ] do
        assert {:ok, statement} =
                 Attestation.from_decision(decision, @context,
                   payload: @payload,
                   now: @now
                 )

        assert get_in(statement, ["predicate", "verdict"]) == verdict
      end
    end

    test "rejects malformed inputs" do
      assert Attestation.from_decision(%{}, @context, payload: @payload, now: @now) ==
               {:error, :invalid_payload}

      assert Attestation.from_decision(decision(), @context, :bad_opts) ==
               {:error, :invalid_payload}

      assert Attestation.from_decision(decision(), @context, now: @now) ==
               {:error, :invalid_payload}

      assert Attestation.from_decision(decision(), @context, payload: "bad", now: @now) ==
               {:error, :invalid_payload}

      assert Attestation.from_decision(decision(), %{@context | actor: nil, identity: nil},
               payload: @payload,
               now: @now
             ) == {:error, :invalid_payload}

      assert Attestation.from_decision(decision(), %{@context | phase: :release},
               payload: @payload,
               now: @now
             ) == {:error, :invalid_phase}

      assert Attestation.from_decision(decision(), "bad", payload: @payload, now: @now) ==
               {:error, :invalid_context}

      assert Attestation.from_decision(decision(), @context,
               payload: @payload,
               statement_type: :unknown,
               now: @now
             ) == {:error, :unknown_statement_type}

      assert Attestation.from_decision(decision(), @context,
               payload: @payload,
               statement_type: 42,
               now: @now
             ) == {:error, :unknown_statement_type}

      assert Attestation.from_decision(decision(), @context,
               payload: @payload,
               now: "bad-now"
             ) == {:error, :invalid_payload}

      assert Attestation.from_decision(decision(), @context,
               payload: @payload,
               now: @now,
               ttl_ms: 0
             ) ==
               {:error, :invalid_payload}

      result_context = %{@context | phase: :tool_result, origin: :tool, sink: :model}

      assert Attestation.from_decision(decision(phase: :tool_result), result_context,
               payload: @payload,
               now: @now,
               request_action_digest: "bad"
             ) == {:error, :invalid_payload}

      assert Attestation.from_decision(decision(phase: :tool_result), result_context,
               payload: @payload,
               now: @now,
               request_action_digest: String.duplicate("c", 64),
               output_schema_sha256: :bad
             ) == {:error, :invalid_payload}

      assert Attestation.from_decision(decision(phase: :tool_result), result_context,
               payload: @payload,
               now: @now,
               request_action_digest: String.duplicate("c", 64),
               redacted: :bad
             ) == {:error, :invalid_payload}
    end
  end

  describe "from_decision/3 statement content" do
    defp build(decision, extra \\ []) do
      Attestation.from_decision(
        decision,
        @context,
        Keyword.merge([payload: @payload, now: @now], extra)
      )
    end

    test "generates a nonce unless the caller supplies one or opts out" do
      assert {:ok, first} = build(decision())
      assert {:ok, second} = build(decision())

      assert get_in(first, ["predicate", "nonce"]) =~ ~r/\A[0-9a-f]{32}\z/
      refute get_in(first, ["predicate", "nonce"]) == get_in(second, ["predicate", "nonce"])

      assert {:ok, explicit} = build(decision(), nonce: "nonce-1")
      assert get_in(explicit, ["predicate", "nonce"]) == "nonce-1"

      for off <- [false, nil] do
        assert {:ok, without} = build(decision(), nonce: off)
        refute Map.has_key?(without["predicate"], "nonce")
      end
    end

    test "a statement with the generated nonce can be replay-consumed once" do
      defmodule NonceSigner do
        @behaviour SigilGuard.Signer
        @seed :crypto.hash(:sha256, "from-decision-nonce-signer")

        @impl SigilGuard.Signer
        def sign(message) do
          {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
          :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
        end

        @impl SigilGuard.Signer
        def public_key do
          {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
          public_key
        end
      end

      assert {:ok, statement} = build(decision())
      assert {:ok, envelope} = Attestation.sign(statement, NonceSigner, keyid: "nonce")
      trust = %{"nonce" => NonceSigner.public_key()}
      opts = [now: @now, consume: true]

      assert {:ok, _} = Attestation.verify(envelope, trust, opts)
      assert Attestation.verify(envelope, trust, opts) == {:error, :replay_detected}
    end

    test "timestamps have millisecond precision whatever the clock gives" do
      assert {:ok, precise} =
               build(decision(), now: ~U[2026-07-03 12:00:00.123456Z], ttl_ms: 1_500)

      assert get_in(precise, ["predicate", "issued_at"]) == "2026-07-03T12:00:00.123Z"
      assert get_in(precise, ["predicate", "expires_at"]) == "2026-07-03T12:00:01.623Z"

      assert {:ok, default_clock} =
               Attestation.from_decision(decision(), @context, payload: @payload)

      for field <- ~w(issued_at expires_at) do
        assert get_in(default_clock, ["predicate", field]) =~ ~r/T\d\d:\d\d:\d\d\.\d{3}Z\z/
      end
    end

    test "matched rules and evidence references follow the decision" do
      rules = [
        %{rule_id: "boundary.secret.external_sink", explanation: "secret headed out"},
        %{rule_id: "line_3", explanation: nil}
      ]

      evidence = [%{"kind" => "checkpoint", "ref" => String.duplicate("a", 64)}]

      assert {:ok, statement} = build(decision(matched_rules: rules, evidence_refs: evidence))

      assert statement["predicate"]["matched_rules"] == [
               %{"id" => "boundary.secret.external_sink", "explanation" => "secret headed out"},
               %{"id" => "line_3", "explanation" => ""}
             ]

      assert statement["predicate"]["evidence"] == evidence
      assert TrustProfile.validate(statement) == {:ok, statement}

      assert {:ok, plain} = build(decision())
      refute Map.has_key?(plain["predicate"], "matched_rules")
      refute Map.has_key?(plain["predicate"], "evidence")
    end

    test "an :evidence option overrides the decision's evidence_refs" do
      evidence = [%{"kind" => "checkpoint", "ref" => String.duplicate("a", 64)}]
      other = [%{"kind" => "export", "ref" => String.duplicate("b", 64)}]

      assert {:ok, overridden} =
               build(decision(evidence_refs: evidence), evidence: other)

      assert overridden["predicate"]["evidence"] == other
    end

    test "a statement is equal to its decoded canonical bytes" do
      contexts = [
        @context,
        %{@context | intended_audience: :external, resource_uri: "mcp://repo", mcp_server: "repo"}
      ]

      for context <- contexts,
          opts <- [[], [audience: "spiffe://agents/reviewer", scopes: ["b", "a"]]] do
        {:ok, statement} =
          Attestation.from_decision(
            decision(matched_rules: [%{rule_id: "line_3", explanation: nil}]),
            context,
            Keyword.merge([payload: @payload, now: @now], opts)
          )

        {:ok, bytes} = SigilGuard.Canonical.JCS.encode(statement)

        assert SigilGuard.Canonical.JSON.decode(bytes) == {:ok, statement}
      end

      {:ok, statement} =
        Attestation.from_decision(decision(), @context, payload: @payload, now: @now)

      assert statement["predicate"]["resource"]["audience"] == "internal"
    end

    test "the boundary mirror states the fields the context digest binds" do
      assert {:ok, plain} = build(decision())

      assert plain["predicate"]["boundary"] == %{
               "phase" => "tool_request",
               "origin" => "user",
               "sink" => "tool",
               "trust_zone" => "semi_trusted",
               "intended_audience" => "internal"
             }

      sandboxed = %{
        @context
        | source: "session-7f3acb12",
          sandbox_id: "sbx-9c2e4d10",
          isolation_level: :container,
          trust_zone: :untrusted
      }

      attest = fn context ->
        {:ok, statement} =
          Attestation.from_decision(decision(), context, payload: @payload, now: @now)

        statement
      end

      statement = attest.(sandboxed)
      boundary = statement["predicate"]["boundary"]

      assert Map.take(boundary, ~w(source sandbox_id isolation_level trust_zone)) == %{
               "source" => "session-7f3acb12",
               "sandbox_id" => "sbx-9c2e4d10",
               "isolation_level" => "container",
               "trust_zone" => "untrusted"
             }

      # Every mirrored value is the one in the context digest preimage, and
      # the identity fields of that preimage stay out of the mirror.
      {:ok, preimage} = Attestation.Digest.context_preimage(:tool_request, sandboxed)
      {:ok, normalized} = Attestation.Digest.normalize(preimage)

      assert Map.take(normalized, Map.keys(boundary)) == boundary
      refute Map.has_key?(boundary, "actor")
      refute Map.has_key?(boundary, "tool")

      # A change to a mirrored field changes the context subject too.
      moved = attest.(%{sandboxed | trust_zone: :semi_trusted})

      assert moved["predicate"]["boundary"]["trust_zone"] == "semi_trusted"
      refute context_digest(moved) == context_digest(statement)
    end

    test "a decision's evidence references pass the same check as the option" do
      for refs <- [["event-1"], [%{"kind" => "audit", "ref" => "x"}], [%{"kind" => "export"}]] do
        assert build(decision(evidence_refs: refs)) == {:error, :invalid_evidence}
        assert build(decision(), evidence: refs) == {:error, :invalid_evidence}
      end

      # A valid option is what gets signed, so a malformed field behind it
      # does not refuse the statement.
      valid = [%{"kind" => "anchor", "ref" => String.duplicate("c", 64)}]

      assert {:ok, statement} = build(decision(evidence_refs: ["event-1"]), evidence: valid)
      assert statement["predicate"]["evidence"] == valid
    end

    test "timestamps have three fractional digits whatever the clock precision" do
      for now <- [
            ~U[2026-07-02 12:00:00Z],
            ~U[2026-07-02 12:00:00.1Z],
            ~U[2026-07-02 12:00:00.123456Z]
          ] do
        assert {:ok, statement} = build(decision(), now: now)

        for field <- ["issued_at", "expires_at"] do
          assert statement["predicate"][field] =~ ~r/\A2026-07-02T12:0[05]:00\.\d{3}Z\z/, field
        end
      end

      assert {:ok, coarse} = build(decision(), now: ~U[2026-07-02 12:00:00Z])
      assert coarse["predicate"]["issued_at"] == "2026-07-02T12:00:00.000Z"

      assert {:ok, fine} = build(decision(), now: ~U[2026-07-02 12:00:00.123999Z])
      assert fine["predicate"]["issued_at"] == "2026-07-02T12:00:00.123Z"
    end

    test "a confirmed release of a quarantined result attests released_sanitized" do
      context = %{@context | phase: :tool_result, origin: :tool, sink: :model}
      digest = String.duplicate("a", 64)

      attest = fn metadata ->
        {:ok, statement} =
          Attestation.from_decision(
            decision(action: :redact, phase: :tool_result, audit_metadata: metadata),
            context,
            payload: @payload,
            now: @now,
            request_action_digest: digest
          )

        get_in(statement, ["predicate", "quarantine", "status"])
      end

      assert attest.(%{quarantine_status: :quarantined}) == "quarantined"

      assert attest.(%{quarantine_status: :quarantined, release_status: :confirmed_sanitized}) ==
               "released_sanitized"

      assert attest.(%{}) == "none"
    end

    test "a text or list payload is accepted where the statement type needs no map" do
      egress = %{@context | phase: :outbound_model, origin: :model, sink: :user}
      decision = decision(phase: :outbound_model)

      for payload <- ["model output text", ["part one", "part two"]] do
        assert {:ok, statement} =
                 Attestation.from_decision(decision, egress, payload: payload, now: @now)

        assert statement["predicate"]["statement_type"] == "model_egress"
      end

      # A tool request is defined over the request map.
      assert build(decision(), payload: "tools/call") == {:error, :invalid_payload}
      assert build(decision(), payload: 42) == {:error, :invalid_payload}
    end
  end

  defp decision(overrides \\ []) do
    attrs =
      Keyword.merge(
        [
          verdict: :allowed,
          action: :allow,
          phase: :tool_request,
          risk_level: :low,
          trust_level: :medium
        ],
        overrides
      )

    struct!(Decision, attrs)
  end

  defp context_digest(statement) do
    Enum.find_value(statement["subject"], fn entry ->
      entry["name"] == "context" && entry["digest"]["sha256"]
    end)
  end

  defp subject_names(statement) do
    Enum.map(statement["subject"], & &1["name"])
  end
end
