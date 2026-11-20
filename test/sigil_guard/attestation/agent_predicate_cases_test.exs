defmodule SigilGuard.Attestation.AgentPredicateCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Attestation.AgentPredicate
  alias SigilGuard.Attestation.Digest

  @card_digest String.duplicate("c", 64)
  @request_action_digest String.duplicate("a", 64)

  describe "validate/2" do
    test "a predicate without a card digest validates only with a block or quarantine verdict" do
      unknown = %{
        "peer_agent" => %{"id" => "spiffe://agents/responder"},
        "peer_trust" => "low",
        "capability" => "summarize"
      }

      assert AgentPredicate.validate(:agent_request, unknown) == {:error, :invalid_payload}

      assert AgentPredicate.validate(:agent_request, Map.put(unknown, :verdict, "quarantine")) ==
               :ok

      assert AgentPredicate.validate(:agent_request, Map.put(unknown, :verdict, :block)) == :ok

      assert AgentPredicate.validate(:agent_request, Map.put(unknown, :verdict, "allow")) ==
               {:error, :invalid_payload}
    end

    test "a response predicate without a request action digest is refused" do
      response = %{
        "peer_agent" => %{"id" => "spiffe://agents/responder", "card_digest" => @card_digest},
        "peer_trust" => "medium",
        "capability" => "summarize",
        "status" => "ok",
        "quarantined" => false
      }

      assert AgentPredicate.validate(:agent_response, response) == {:error, :invalid_payload}

      assert AgentPredicate.validate(
               :agent_response,
               Map.put(response, "request_action_digest", @request_action_digest)
             ) == :ok
    end
  end

  describe "build_response/2" do
    test "needs a status in the payload and a quarantined flag in the options" do
      opts = [
        peer_trust: :low,
        card_digest: @card_digest,
        request_action_digest: @request_action_digest,
        quarantined: false
      ]

      assert AgentPredicate.build_response(response_payload(), opts) ==
               {:ok,
                %{
                  "capability" => "summarize",
                  "status" => "ok",
                  "quarantined" => false,
                  "peer_trust" => "low",
                  "request_action_digest" => @request_action_digest,
                  "peer_agent" => %{
                    "id" => "spiffe://agents/responder",
                    "card_digest" => @card_digest
                  }
                }}

      assert AgentPredicate.build_response(Map.delete(response_payload(), "status"), opts) ==
               {:error, :invalid_payload}

      assert AgentPredicate.build_response(Map.put(response_payload(), "status", 200), opts) ==
               {:error, :invalid_payload}

      without_flag = Keyword.delete(opts, :quarantined)

      assert AgentPredicate.build_response(response_payload(), without_flag) ==
               {:error, :invalid_payload}

      assert AgentPredicate.build_response(
               response_payload(),
               Keyword.put(opts, :request_action_digest, nil)
             ) == {:error, :invalid_payload}

      assert AgentPredicate.build_response(
               response_payload(),
               Keyword.put(opts, :card_digest, 123)
             ) ==
               {:error, :invalid_payload}

      # Without options there is no peer trust, digest or flag to write.
      assert AgentPredicate.build_response(response_payload()) == {:error, :invalid_payload}
    end
  end

  describe "build_request/2" do
    test "without options a request predicate has no peer trust and is refused" do
      payload = Map.delete(request_payload(), "delegation_chain")

      assert AgentPredicate.build_request(payload) == {:error, :invalid_payload}

      assert AgentPredicate.build_request(payload, peer_trust: :low, verdict: :block) ==
               {:ok,
                %{
                  "capability" => "summarize",
                  "peer_agent" => %{"id" => "spiffe://agents/responder"},
                  "peer_trust" => "low"
                }}
    end
  end

  describe "action_digest/3" do
    test "arguments with no JSON form, or an integer above 2^53 - 1, are refused" do
      payload = Map.delete(request_payload(), "delegation_chain")

      for arguments <- [{1, 2}, self(), <<255>>, %{1 => 2}, [1 | 2]] do
        assert AgentPredicate.action_digest(
                 :agent_request,
                 Map.put(payload, "arguments", arguments),
                 []
               ) == {:error, :invalid_payload}
      end

      assert AgentPredicate.action_digest(
               :agent_request,
               Map.put(payload, "arguments", %{"n" => 9_007_199_254_740_992}),
               []
             ) == {:error, :unsupported_number_range}
    end

    test "a request needs no options and a response needs the request digest" do
      payload = Map.delete(request_payload(), "delegation_chain")

      assert {:ok, digest} = AgentPredicate.action_digest(:agent_request, payload)
      assert Digest.action_digest(:agent_request, payload, %{}) == {:ok, digest}

      assert {:ok, %{"statement_type" => "agent_request"}} =
               AgentPredicate.action_preimage(:agent_request, payload)

      assert AgentPredicate.action_digest(:agent_response, response_payload()) ==
               {:error, :invalid_payload}

      assert AgentPredicate.action_preimage(:agent_response, response_payload()) ==
               {:error, :invalid_payload}

      assert AgentPredicate.action_digest(:agent_response, response_payload(),
               request_action_digest: 5
             ) == {:error, :invalid_payload}
    end
  end

  describe "delegation_chain_digest/1" do
    test "a hop with a key that is not a name, or an actor that is not UTF-8, is refused" do
      assert AgentPredicate.delegation_chain_digest(%{
               "delegation_chain" => [%{"actor" => "spiffe://agents/router", 1 => "extra"}]
             }) == {:error, :invalid_payload}

      assert AgentPredicate.delegation_chain_digest(%{
               "delegation_chain" => [%{"actor" => <<255>>}]
             }) == {:error, :invalid_payload}

      assert AgentPredicate.delegation_chain_digest(%{
               "delegation_chain" => [
                 %{"actor" => "spiffe://agents/router", "evidence" => <<255>>}
               ]
             }) == {:error, :invalid_payload}
    end
  end

  defp request_payload do
    %{
      "peer_agent" => "spiffe://agents/responder",
      "capability" => "summarize",
      "arguments" => %{"topic" => "build"},
      "delegation_chain" => [
        %{"actor" => "spiffe://agents/router", "evidence" => "audit:1"},
        %{"actor" => "spiffe://agents/planner"}
      ]
    }
  end

  defp response_payload do
    %{"peer_agent" => "spiffe://agents/responder", "capability" => "summarize", "status" => "ok"}
  end
end
