defmodule SigilGuard.AgentCardIssuerCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.AgentCard
  alias SigilGuard.AgentCardFixtureGenerator
  alias SigilGuard.AgentCardFixtureGenerator.IssuerSigner
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.TrustBundle

  @now ~U[2026-07-15 12:00:00.000Z]

  defp issuer_public_key, do: AgentCardFixtureGenerator.issuer_public_key()
  defp issuer_keyid, do: Envelope.keyid(issuer_public_key())
  defp issuer_material, do: %{issuer_keyid() => issuer_public_key()}

  defp valid_card do
    agent_pub = AgentCardFixtureGenerator.agent_public_key()

    %{
      "kind" => "sigil_guard_agent_card",
      "schema_version" => "1",
      "agent_id" => "spiffe://prod.example.org/agents/research-peer",
      "name" => "research-peer",
      "version" => "2.1.0",
      "provider" => "spiffe://prod.example.org/operators/platform-team",
      "endpoints" => ["https://agents.example.org/research-peer/a2a"],
      "capabilities" => [
        %{"description" => "Summarize a document set", "name" => "summarize"},
        %{"description" => "Web research with citations", "name" => "web_research"}
      ],
      "protocols" => ["a2a/1.0"],
      "public_keys" => [
        %{
          "algorithm" => "ed25519",
          "keyid" => Envelope.keyid(agent_pub),
          "public_key" => Base.url_encode64(agent_pub, padding: false)
        }
      ],
      "scopes" => ["research:read"],
      "trust_zone" => "semi_trusted",
      "issued_at" => "2026-07-02T12:00:00.000Z",
      "expires_at" => "2026-08-01T12:00:00.000Z"
    }
  end

  defp bundle_with_role(role_keyids, keys: keys) do
    document = %{
      "keys" =>
        Map.new(keys, fn {keyid, public_key} ->
          {keyid,
           %{"alg" => "ed25519", "public_key" => Base.url_encode64(public_key, padding: false)}}
        end),
      "roles" => %{"delegates" => [%{"name" => "agent_card", "keyids" => role_keyids}]}
    }

    %TrustBundle{document: document}
  end

  test "an expiry that is not a string fails closed on the role, the bundle and the root" do
    {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)
    base = bundle_with_role([issuer_keyid()], keys: issuer_material())
    assert {:ok, _} = AgentCard.verify(envelope, base, now: @now)

    role = fn expiry ->
      put_in(base.document["roles"]["delegates"], [
        %{"name" => "agent_card", "keyids" => [issuer_keyid()], "expires_at" => expiry}
      ])
    end

    for bundle <- [
          role.(1_790_000_000),
          role.(nil),
          put_in(base.document["expires_at"], 1_790_000_000),
          put_in(base.document["roles"]["root"], %{"expires_at" => ["2027"]})
        ] do
      assert AgentCard.verify(envelope, bundle, now: @now) == {:error, :untrusted_issuer}
    end
  end

  test "a role threshold that is not a positive integer authorizes nothing" do
    {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)
    base = bundle_with_role([issuer_keyid()], keys: issuer_material())

    for threshold <- [0, -1, "1", nil, 1.0] do
      bundle =
        put_in(base.document["roles"]["delegates"], [
          %{"name" => "agent_card", "keyids" => [issuer_keyid()], "threshold" => threshold}
        ])

      assert AgentCard.verify(envelope, bundle, now: @now) == {:error, :untrusted_issuer}
    end
  end

  test "a malformed envelope is refused against a trust bundle without raising" do
    {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)
    bundle = bundle_with_role([issuer_keyid()], keys: issuer_material())

    for malformed <- [
          "envelope",
          [envelope],
          Map.put(envelope, "signatures", "sig"),
          Map.delete(envelope, "signatures"),
          Map.put(envelope, "signatures", ["sig"]),
          Map.update!(envelope, "signatures", &["sig" | &1])
        ] do
      assert AgentCard.verify(malformed, bundle, now: @now) == {:error, :invalid_envelope}
    end
  end
end
