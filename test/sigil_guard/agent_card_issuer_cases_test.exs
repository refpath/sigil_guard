defmodule SigilGuard.AgentCardIssuerCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  import SigilGuard.AgentCardFixtureGenerator,
    only: [bundle_with_role: 2, issuer_keyid: 0, issuer_material: 0]

  alias SigilGuard.AgentCard
  alias SigilGuard.AgentCardFixtureGenerator
  alias SigilGuard.AgentCardFixtureGenerator.IssuerSigner

  @now ~U[2026-07-15 12:00:00.000Z]

  test "an expiry that is not a string fails closed on the role, the bundle and the root" do
    {:ok, envelope} = AgentCard.sign(AgentCardFixtureGenerator.card(), IssuerSigner)
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
    {:ok, envelope} = AgentCard.sign(AgentCardFixtureGenerator.card(), IssuerSigner)
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
    {:ok, envelope} = AgentCard.sign(AgentCardFixtureGenerator.card(), IssuerSigner)
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
