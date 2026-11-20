defmodule SigilGuard.AgentTrustCasesTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.AgentCard
  alias SigilGuard.AgentTrust
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Decision
  alias SigilGuard.ReplayStore

  @now ~U[2026-07-15 12:00:00.000Z]
  @peer_id "spiffe://prod.example.org/agents/reviewer"

  setup do
    ReplayStore.clear()
    on_exit(&ReplayStore.clear/0)
    :ok
  end

  defmodule Issuer do
    @behaviour SigilGuard.Signer
    @seed :binary.copy(<<0x21>>, 32)
    @impl SigilGuard.Signer
    def sign(m), do: :crypto.sign(:eddsa, :none, m, [priv(), :ed25519])
    @impl SigilGuard.Signer
    def public_key, do: elem(:crypto.generate_key(:eddsa, :ed25519, @seed), 0)
    defp priv, do: elem(:crypto.generate_key(:eddsa, :ed25519, @seed), 1)
  end

  defmodule Agent do
    @behaviour SigilGuard.Signer
    @seed :binary.copy(<<0x41>>, 32)
    @impl SigilGuard.Signer
    def sign(m), do: :crypto.sign(:eddsa, :none, m, [priv(), :ed25519])
    @impl SigilGuard.Signer
    def public_key, do: elem(:crypto.generate_key(:eddsa, :ed25519, @seed), 0)
    defp priv, do: elem(:crypto.generate_key(:eddsa, :ed25519, @seed), 1)
  end

  describe "verify_agent_response binds the capability, the context and the payload" do
    test "a response that names the card but carries no manifest subject fails :manifest_digest_mismatch" do
      {:ok, digest} = AgentCard.digest(card())
      rad = request_action_digest(request_payload())
      payload = %{"peer_agent" => @peer_id, "capability" => "summarize", "status" => "ok"}

      build = fn extra ->
        {:ok, statement} =
          SigilGuard.Attestation.from_decision(
            %{decision() | phase: :tool_result},
            response_context(),
            [
              statement_type: :agent_response,
              payload: payload,
              request_action_digest: rad,
              peer_trust: :medium,
              card_digest: digest,
              now: @now
            ] ++ extra
          )

        {:ok, envelope} = SigilGuard.Attestation.sign(statement, Agent)
        {statement, envelope}
      end

      {statement, envelope} = build.([])

      assert statement["predicate"]["peer_agent"]["card_digest"] == digest
      assert Enum.map(statement["subject"], & &1["name"]) == ["action", "payload", "context"]

      assert verify_response(envelope, rad, payload: payload) ==
               {:error, :manifest_digest_mismatch}

      {_, bound} = build.(manifest_digest: digest)
      assert {:ok, _} = verify_response(bound, rad, payload: payload)
    end
  end

  defp verify_response(envelope, rad, opts) do
    AgentTrust.verify_agent_response(
      envelope,
      issuer_material(),
      Keyword.merge([peer_card: card_envelope(), request_action_digest: rad, now: @now], opts)
    )
  end

  defp issuer_material, do: %{Envelope.keyid(Issuer.public_key()) => Issuer.public_key()}

  defp card(overrides \\ %{}) do
    agent_pub = Agent.public_key()

    Map.merge(
      %{
        "kind" => "sigil_guard_agent_card",
        "schema_version" => "1",
        "agent_id" => @peer_id,
        "name" => "reviewer",
        "version" => "2.1.0",
        "provider" => "spiffe://prod.example.org/operators/team",
        "endpoints" => ["https://agents.example.org/reviewer/a2a"],
        "capabilities" => [%{"name" => "summarize"}],
        "protocols" => ["a2a/1.0"],
        "public_keys" => [
          %{
            "algorithm" => "ed25519",
            "keyid" => Envelope.keyid(agent_pub),
            "public_key" => Base.url_encode64(agent_pub, padding: false)
          }
        ],
        "trust_zone" => "semi_trusted",
        "issued_at" => "2026-07-02T12:00:00.000Z",
        "expires_at" => "2026-08-01T12:00:00.000Z"
      },
      overrides
    )
  end

  defp card_envelope(overrides \\ %{}) do
    {:ok, envelope} = AgentCard.sign(card(overrides), Issuer)
    envelope
  end

  defp decision do
    %Decision{
      verdict: :allowed,
      action: :allow,
      phase: :tool_request,
      risk_level: :low,
      trust_level: :medium
    }
  end

  defp request_context do
    %{
      actor: "spiffe://prod.example.org/agents/release-bot",
      identity: "spiffe://prod.example.org/agents/release-bot",
      phase: :tool_request,
      origin: :model,
      sink: :external,
      trust_level: :medium,
      trust_zone: :semi_trusted
    }
  end

  defp response_context,
    do: Map.merge(request_context(), %{phase: :tool_result, origin: :external, sink: :model})

  defp request_payload(overrides \\ %{}) do
    Map.merge(
      %{"peer_agent" => @peer_id, "capability" => "summarize", "arguments" => %{"topic" => "x"}},
      overrides
    )
  end

  defp request_action_digest(payload) do
    {:ok, digest} = Digest.action_digest(:agent_request, payload, %{})
    digest
  end
end
