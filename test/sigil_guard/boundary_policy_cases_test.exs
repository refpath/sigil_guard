defmodule SigilGuard.BoundaryPolicyCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.BoundaryPolicy
  alias SigilGuard.BoundaryPolicy.Contract
  alias SigilGuard.BoundaryPolicy.File, as: PolicyFile

  @digest String.duplicate("a", 64)

  defp boundary(extra \\ %{}) do
    Map.merge(
      %{
        phase: :tool_request,
        source: :model,
        origin: :model,
        sink: :tool,
        action_digest: @digest,
        payload_digest: @digest,
        context_digest: @digest,
        trust_level: :high,
        sandbox: %{"isolation_level" => :vm}
      },
      extra
    )
  end

  defp rule_ids(decision), do: Enum.map(decision.matched_rules, & &1.rule_id)

  test "the advisory risk is the higher of the hook's and the detector's" do
    for {hook, detector} <- [
          {SigilGuard.CaseFixtures.HookMedium, SigilGuard.CaseFixtures.DetectorHigh},
          {SigilGuard.CaseFixtures.HookHigh, SigilGuard.CaseFixtures.DetectorLow}
        ] do
      decision =
        BoundaryPolicy.evaluate(boundary(), hooks: [hook], adaptive_detector: detector, text: "x")

      assert decision.action == :allow
      assert decision.risk_level == :high
      assert decision.audit_metadata.advisory_risk_level == :high
    end
  end

  test "malformed repo facts still contribute their verdict under a generic rule id" do
    blocked =
      BoundaryPolicy.evaluate(boundary(),
        repo_facts: %{verdict: :block, matched_rules: :not_a_list}
      )

    assert blocked.action == :block

    assert blocked.matched_rules == [
             %{rule_id: "repo.default", explanation: "repo policy verdict"}
           ]

    confirm =
      BoundaryPolicy.evaluate(boundary(),
        repo_facts: %{
          verdict: :require_approval,
          matched_rules: [%{explanation: "no id"}, "junk"]
        }
      )

    assert confirm.action == :confirm
    assert rule_ids(confirm) == ["repo.rule", "repo.rule"]
  end

  test "a sandbox that states no isolation level is the absent column of the matrix" do
    for sandbox <- [%{"sandbox_id" => "s-1"}, %{"sandbox_id" => "s-1", "isolation_level" => nil}] do
      decision = BoundaryPolicy.evaluate(boundary(%{sandbox: sandbox}))

      assert decision.action == :quarantine
      assert rule_ids(decision) == ["sandbox.matrix.execute.absent"]
    end
  end

  test "a pinned tool that declares no side-effect list is class execute" do
    container = %{"isolation_level" => :container}
    pinned = %{"name" => "repo_file_read", "manifest_digest" => @digest}

    for tool <- [pinned, Map.put(pinned, "side_effects", "read")] do
      decision = BoundaryPolicy.evaluate(boundary(%{tool: tool, sandbox: container}))

      assert decision.action == :confirm
      assert rule_ids(decision) == ["sandbox.matrix.execute.container"]
    end

    read =
      BoundaryPolicy.evaluate(
        boundary(%{tool: Map.put(pinned, "side_effects", ["read"]), sandbox: container})
      )

    assert read.action == :allow
  end

  test "a tool matcher, the wildcard included, does not match a tool without a name" do
    {:ok, policy} = PolicyFile.parse("version 3\n\n[rules]\ndefault allow\nblock tool:*\n")
    tool = %{"manifest_digest" => @digest, "side_effects" => ["read"]}

    unnamed = BoundaryPolicy.evaluate(boundary(%{tool: tool}), policy: policy)
    assert unnamed.action == :allow
    assert rule_ids(unnamed) == ["policy.default"]

    named = BoundaryPolicy.evaluate(boundary(%{tool: Map.put(tool, "name", "t")}), policy: policy)
    assert named.action == :block
    assert rule_ids(named) == ["line_5"]
  end

  test "truncate/2 returns the bare marker when max_size leaves no room for content" do
    content = "abcdefghijklmnopqrstuvwxyz"

    assert Contract.truncate(content, 12) == "a[TRUNCATED]"
    assert Contract.truncate(content, 11) == "[TRUNCATED]"
    # Below the marker size the result exceeds max_size. The parser refuses such a contract.
    assert Contract.truncate(content, 5) == "[TRUNCATED]"

    assert Contract.parse(["contract sink:external max_size:5"]) ==
             {:error, :invalid_output_contract}
  end

  test "an improper hooks list is malformed options, not a raise" do
    refute SigilGuard.BoundaryPolicy.valid_extension_options?(hooks: [Foo | Bar])

    decision = SigilGuard.Runtime.Gate.evaluate("x", [phase: :tool_result], hooks: [Foo | Bar])
    assert decision.verdict == :blocked
  end
end
