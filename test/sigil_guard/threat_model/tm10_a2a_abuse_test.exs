defmodule SigilGuard.ThreatModel.TM10A2AAbuseTest do
  @moduledoc false

  use ExUnit.Case, async: false

  import SigilGuard.AgentTrustFixture

  alias __MODULE__.Impostor
  alias SigilGuard.AgentCard
  alias SigilGuard.AgentTrust
  alias SigilGuard.AgentTrustFixture
  alias SigilGuard.AgentTrustFixture.Agent
  alias SigilGuard.AgentTrustFixture.Issuer
  alias SigilGuard.AgentTrustFixture.Local
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.ReplayStore
  alias SigilGuard.TrustBundle

  @now ~U[2026-07-15 12:00:00.000Z]
  @peer_id AgentTrustFixture.peer_id()

  setup do
    ReplayStore.clear()
    on_exit(&ReplayStore.clear/0)
    :ok
  end

  describe "agent cards are verified against the bundle's issuers (row 12, mitigates)" do
    test "a card signed by a bundle-declared issuer verifies (no false positive)" do
      assert {:ok, card} = AgentCard.verify(card_envelope(), issuer_material(), now: @now)
      assert card["agent_id"] == @peer_id
    end

    test "a card from an unrecognized issuer is rejected (impersonation)" do
      {:ok, forged} = AgentCard.sign(card(), Impostor)

      assert AgentCard.verify(forged, issuer_material(), now: @now) ==
               {:error, :unknown_key_id}
    end

    test "a signer present in the bundle but lacking the agent_card role is untrusted" do
      assert AgentCard.verify(card_envelope(), bundle_without_issuer_role(), now: @now) ==
               {:error, :untrusted_issuer}
    end
  end

  describe "expired or tampered cards are rejected (row 12, expiration and tamper)" do
    test "a card past its expiry is rejected" do
      assert AgentCard.verify(card_envelope(), issuer_material(),
               now: ~U[2026-09-01 12:00:00.000Z]
             ) == {:error, :card_expired}
    end

    test "a card whose payload is swapped under a valid signature fails signature verification" do
      tampered =
        Map.put(card_envelope(), "payload", card_envelope(%{"version" => "9.9.9"})["payload"])

      assert AgentCard.verify(tampered, issuer_material(), now: @now) ==
               {:error, :invalid_signature}
    end
  end

  describe "unknown or rogue agents are quarantined at the boundary (row 20, detects-at-boundary)" do
    test "a request from a peer with no verified card attests a quarantine verdict" do
      opts = [signer: Local, decision: decision(), now: @now, nonce: "unk"]

      assert {:ok, envelope} =
               AgentTrust.attest_agent_request(request_payload(), request_context(), opts)

      predicate = predicate(envelope, Local.public_key())

      assert predicate["verdict"] == "quarantine"
      assert predicate["peer_trust"] == "low"
      refute Map.has_key?(predicate, "manifest")

      assert Enum.any?(predicate["matched_rules"], &(&1["id"] == "agent.unknown_peer.quarantine"))
    end

    test "require_peer_card denies an unknown agent at the boundary" do
      opts = [signer: Local, decision: decision(), require_peer_card: true, now: @now]

      assert AgentTrust.attest_agent_request(request_payload(), request_context(), opts) ==
               {:error, :unknown_agent}
    end
  end

  describe "delegation chains enforce depth and reject tampering (row 13, mitigates)" do
    test "a chain within the depth limit is accepted; beyond it is rejected" do
      assert {:ok, _} = attest_with_chain(chain(8), nonce: "d8")
      assert attest_with_chain(chain(9), nonce: "d9") == {:error, :delegation_too_deep}
    end

    test "a reordered delegation chain fails against its signed mirror (tamper)" do
      hops = [
        %{"actor" => "spiffe://prod.example.org/agents/hop-1", "evidence" => "e1"},
        %{"actor" => "spiffe://prod.example.org/agents/hop-2"}
      ]

      payload = request_payload(%{"delegation_chain" => hops})

      {:ok, envelope} =
        AgentTrust.attest_agent_request(payload, request_context(), chain_opts("chain"))

      predicate = predicate(envelope, Local.public_key())
      reordered = update_in(payload["delegation_chain"], &Enum.reverse/1)

      assert AgentTrust.verify_delegation_chain(reordered, predicate) ==
               {:error, :delegation_chain_tampered}
    end
  end

  describe "a replayed agent response is rejected (replay); malformed input fails closed" do
    test "a single-use agent response nonce cannot be replayed" do
      {envelope, payload, rad} = signed_response()

      verify = fn ->
        AgentTrust.verify_agent_response(envelope, issuer_material(),
          peer_card: card_envelope(),
          request_action_digest: rad,
          payload: payload,
          now: @now,
          replay: true
        )
      end

      assert {:ok, _} = verify.()
      assert verify.() == {:error, :replay_detected}
    end

    test "a non-envelope card verification fails closed" do
      assert AgentCard.verify("not-an-envelope", issuer_material(), now: @now) ==
               {:error, :invalid_envelope}
    end
  end

  # An issuer whose key is not among the trust bundle's declared card issuers.
  defmodule Impostor do
    use SigilGuard.TestSigner, seed: :binary.copy(<<0x99>>, 32)
  end

  # A bundle that knows the issuer's key but does not grant it the agent_card role.
  defp bundle_without_issuer_role do
    issuer_pub = Issuer.public_key()

    %TrustBundle{
      document: %{
        "keys" => %{
          Envelope.keyid(issuer_pub) => %{
            "alg" => "ed25519",
            "public_key" => Base.url_encode64(issuer_pub, padding: false)
          }
        },
        "roles" => %{
          "delegates" => [
            %{"name" => "agent_card", "keyids" => ["sha256:" <> String.duplicate("0", 64)]}
          ]
        }
      }
    }
  end

  defp chain(n), do: for(i <- 1..n, do: %{"actor" => "spiffe://prod.example.org/agents/hop-#{i}"})

  defp chain_opts(nonce) do
    [
      signer: Local,
      decision: decision(),
      peer_card: card_envelope(),
      trust_material: issuer_material(),
      now: @now,
      nonce: nonce,
      resolve: fn _ -> :medium end
    ]
  end

  defp attest_with_chain(hops, opts) do
    AgentTrust.attest_agent_request(
      request_payload(%{"delegation_chain" => hops}),
      request_context(),
      Keyword.merge(chain_opts("chain"), opts)
    )
  end

  defp signed_response do
    rad = request_action_digest(request_payload())
    payload = %{"peer_agent" => @peer_id, "capability" => "summarize", "status" => "ok"}

    opts = [
      signer: Agent,
      decision: %{decision() | phase: :tool_result},
      peer_card: card_envelope(),
      trust_material: issuer_material(),
      request_action_digest: rad,
      now: @now,
      nonce: "resp",
      resolve: fn _ -> :medium end
    ]

    {:ok, envelope} = AgentTrust.attest_agent_response(payload, response_context(), opts)
    {envelope, payload, rad}
  end
end
