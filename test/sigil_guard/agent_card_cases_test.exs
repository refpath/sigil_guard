defmodule SigilGuard.AgentCardCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.AgentCard
  alias SigilGuard.AgentCardFixtureGenerator
  alias SigilGuard.Attestation.Envelope

  describe "new/1" do
    test "a timestamp of the right shape that names no instant is refused" do
      assert {:ok, _} = AgentCard.new(valid_card())

      for {field, value} <- [
            {"issued_at", "2026-13-01T12:00:00.000Z"},
            {"issued_at", "2026-02-30T12:00:00.000Z"},
            {"expires_at", "2026-08-01T25:00:00.000Z"},
            {"expires_at", "2026-08-32T12:00:00.000Z"}
          ] do
        card = Map.put(valid_card(), field, value)

        assert AgentCard.new(card) == {:error, :invalid_agent_card}
        assert AgentCard.digest(card) == {:error, :invalid_agent_card}
      end
    end

    test "an endpoint that is the empty string is refused" do
      assert AgentCard.new(Map.put(valid_card(), "endpoints", [""])) ==
               {:error, :invalid_agent_card}

      assert {:ok, _} = AgentCard.new(Map.put(valid_card(), "endpoints", []))
    end
  end

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
end
