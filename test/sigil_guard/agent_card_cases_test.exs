defmodule SigilGuard.AgentCardCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.AgentCard
  alias SigilGuard.AgentCardFixtureGenerator

  describe "new/1" do
    test "a timestamp of the right shape that names no instant is refused" do
      assert {:ok, _} = AgentCard.new(AgentCardFixtureGenerator.card())

      for {field, value} <- [
            {"issued_at", "2026-13-01T12:00:00.000Z"},
            {"issued_at", "2026-02-30T12:00:00.000Z"},
            {"expires_at", "2026-08-01T25:00:00.000Z"},
            {"expires_at", "2026-08-32T12:00:00.000Z"}
          ] do
        card = Map.put(AgentCardFixtureGenerator.card(), field, value)

        assert AgentCard.new(card) == {:error, :invalid_agent_card}
        assert AgentCard.digest(card) == {:error, :invalid_agent_card}
      end
    end

    test "an endpoint that is the empty string is refused" do
      assert AgentCard.new(Map.put(AgentCardFixtureGenerator.card(), "endpoints", [""])) ==
               {:error, :invalid_agent_card}

      assert {:ok, _} = AgentCard.new(Map.put(AgentCardFixtureGenerator.card(), "endpoints", []))
    end
  end
end
