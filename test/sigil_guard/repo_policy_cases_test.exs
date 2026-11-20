defmodule SigilGuard.RepoPolicyCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.RepoPolicy

  test "a pattern without a globstar does not match a path below it" do
    {:ok, policy} =
      RepoPolicy.parse("""
      default block
      allow agent:* lib/*
      allow agent:* README.md
      allow agent:* **/notes.md
      """)

    evaluate =
      &RepoPolicy.evaluate(policy, agent: "did:web:codex", action: "modify", changed_paths: [&1])

    assert evaluate.("lib/app.ex").verdict == :allow

    for path <- ["lib/deep/app.ex", "README.md/evil", "docs/notes.md/evil"] do
      decision = evaluate.(path)

      assert decision.verdict == :block
      assert decision.unmatched_paths == [path]
    end
  end

  test "decision aliases normalize to the three repo verdicts" do
    for {given, expected} <- [
          {:blocked, :block},
          {"allowed", :allow},
          {"blocked", :block},
          {"BLOCKED", :block},
          {"require-approval", :require_approval},
          {"confirm", :require_approval}
        ] do
      assert {:ok, policy} =
               RepoPolicy.compile(%{
                 default: given,
                 rules: [%{decision: given, paths: ["docs/**"]}]
               })

      assert policy.default == expected
      assert hd(policy.rules).decision == expected
    end

    assert {:ok, parsed} = RepoPolicy.parse("default blocked\nconfirm agent:* docs/**\n")
    assert {parsed.default, hd(parsed.rules).decision} == {:block, :require_approval}
    assert RepoPolicy.compile(%{default: "deny"}) == {:error, :invalid_decision}
  end

  test "a hand-built policy struct with malformed rules does not compile" do
    assert RepoPolicy.compile(%RepoPolicy{rules: :not_a_list}) == {:error, :invalid_rules}

    assert RepoPolicy.compile(%RepoPolicy{rules: [%{decision: :allow}]}) ==
             {:error, :invalid_rule}

    assert RepoPolicy.compile(%RepoPolicy{rules: ["allow docs/**"]}) == {:error, :invalid_rule}

    assert RepoPolicy.compile(%RepoPolicy{
             rules: [%{decision: :allow, agents: ["*"], actions: ["*"], paths: "docs/**"}]
           }) ==
             {:error, :missing_paths}
  end

  test "a rule message that is not text is dropped and the decision reason explains the rule" do
    {:ok, policy} =
      RepoPolicy.compile(%{
        rules: [%{id: "r1", decision: :require_approval, paths: ["lib/**"], message: 42}]
      })

    assert hd(policy.rules).message == nil

    decision =
      RepoPolicy.evaluate(policy, agent: "a", action: "modify", changed_paths: ["lib/a.ex"])

    assert RepoPolicy.policy_facts(policy, decision).matched_rules == [
             %{rule_id: "r1", explanation: "Repo policy requires approval by r1"}
           ]
  end

  test "a rule pattern with backslashes is checked after its separators are normalized" do
    compile = fn path ->
      SigilGuard.RepoPolicy.compile(%{
        version: 1,
        default: :block,
        rules: [%{id: "r", decision: :allow, paths: [path]}]
      })
    end

    assert compile.("..\\secrets") == {:error, {:path_traversal_pattern, 0}}
    assert compile.("docs\\..\\..\\etc") == {:error, {:path_traversal_pattern, 0}}
    assert compile.("C:\\repo") == {:error, {:absolute_path_pattern, 0}}
    assert {:ok, policy} = compile.("src\\lib\\")
    assert hd(policy.rules).paths == ["src/lib/**"]
  end
end
