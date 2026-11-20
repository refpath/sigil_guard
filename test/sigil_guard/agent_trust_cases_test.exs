defmodule SigilGuard.AgentTrustCasesTest do
  @moduledoc false

  # Verification writes nonces to the runtime's shared replay table.
  use ExUnit.Case, async: false

  import SigilGuard.AgentTrustFixture

  alias SigilGuard.AgentCard
  alias SigilGuard.AgentTrust
  alias SigilGuard.AgentTrustFixture
  alias SigilGuard.AgentTrustFixture.Agent
  alias SigilGuard.ReplayStore

  @now ~U[2026-07-15 12:00:00.000Z]
  @peer_id AgentTrustFixture.peer_id()

  setup do
    ReplayStore.clear()
    on_exit(&ReplayStore.clear/0)
    :ok
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
end
