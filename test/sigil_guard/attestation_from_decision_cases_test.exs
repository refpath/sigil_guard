defmodule SigilGuard.AttestationFromDecisionCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Attestation
  alias SigilGuard.Context
  alias SigilGuard.Decision

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
    test "an integer outside the JCS range in the arguments is refused" do
      arguments = fn amount ->
        put_in(@payload, ["params", "arguments"], %{"amount" => amount})
      end

      assert {:ok, _} =
               Attestation.from_decision(decision(), @context,
                 payload: arguments.(9_007_199_254_740_991),
                 now: @now
               )

      assert Attestation.from_decision(decision(), @context,
               payload: arguments.(9_007_199_254_740_992),
               now: @now
             ) == {:error, :invalid_payload}
    end

    test "a statement type given as an unknown string is refused" do
      assert Attestation.from_decision(decision(), @context,
               payload: @payload,
               statement_type: "tool_bogus",
               now: @now
             ) == {:error, :unknown_statement_type}
    end

    test "a decision whose verdict is outside the vocabulary is attested as block" do
      for verdict <- [nil, :allow, {:confirm}, "allowed"] do
        assert {:ok, statement} =
                 Attestation.from_decision(decision(verdict: verdict), @context,
                   payload: @payload,
                   now: @now
                 )

        assert get_in(statement, ["predicate", "verdict"]) == "block"
      end
    end

    test "a result decision whose indicators are not a list attests no indicator ids" do
      result_context = %{@context | phase: :tool_result, origin: :tool, sink: :model}

      assert {:ok, statement} =
               Attestation.from_decision(
                 decision(phase: :tool_result, indicators: nil),
                 result_context,
                 payload: @payload,
                 now: @now,
                 request_action_digest: String.duplicate("c", 64)
               )

      assert statement["predicate"]["quarantine"] == %{"status" => "none", "indicator_ids" => []}
    end

    test "from_decision/2 has no payload to attest" do
      assert Attestation.from_decision(decision(), @context) == {:error, :invalid_payload}
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
end
