defmodule SigilGuard.Runtime.GateCasesTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.BoundaryPolicy
  alias SigilGuard.RepoPolicy
  alias SigilGuard.Runtime.Gate

  @digest String.duplicate("a", 64)

  test "a kernel quarantine outranks the gate's allow and is a blocked quarantine decision" do
    {:ok, policy} =
      BoundaryPolicy.File.parse("""
      version 3

      [rules]
      default allow
      quarantine origin:tool sink:model zone:untrusted
      """)

    context = [
      phase: :tool_result,
      origin: :tool,
      sink: :model,
      tool: "fetch_url",
      actor: "agent:1",
      trust_level: :high,
      trust_zone: :untrusted
    ]

    by_rule = Gate.evaluate("clean tool output", context, boundary_policy: policy)

    assert by_rule.verdict == :blocked
    assert by_rule.action == :quarantine
    assert Enum.map(by_rule.matched_rules, & &1.rule_id) == ["line_5"]

    by_matrix =
      Gate.evaluate(
        %{"tool" => "repo_file_write", "content" => "hello"},
        [
          phase: :tool_request,
          origin: :model,
          sink: :tool,
          tool: "repo_file_write",
          trust_level: :high,
          isolation_level: :none,
          sandbox_id: "s1"
        ],
        manifest_facts: %{manifest_digest: @digest, side_effects: ["write"]}
      )

    assert by_matrix.verdict == :blocked
    assert by_matrix.action == :quarantine
    assert Enum.map(by_matrix.matched_rules, & &1.rule_id) == ["sandbox.matrix.write.none"]
  end

  test "an advisory risk raise does not reopen a policy block" do
    context = [
      phase: :tool_request,
      origin: :model,
      sink: :tool,
      trust_level: :low,
      action: "read_file"
    ]

    # Low risk needs high trust here; medium risk needs medium, one level above the caller.
    thresholds = %{low: :high}

    assert {:confirm, _} =
             SigilGuard.Policy.evaluate("read_file", :low,
               risk_level: :medium,
               trust_thresholds: thresholds
             )

    blocked = Gate.evaluate("hello", context, trust_thresholds: thresholds)
    assert {blocked.verdict, blocked.risk_level} == {:blocked, :low}

    raised =
      Gate.evaluate("hello", context,
        trust_thresholds: thresholds,
        hooks: [SigilGuard.CaseFixtures.HookMedium]
      )

    assert raised.risk_level == :medium
    assert raised.verdict == :blocked
    assert raised.action == :block
  end

  test "an output contract that truncates a redacted crossing keeps it a redact" do
    {:ok, policy} =
      BoundaryPolicy.File.parse("""
      version 3

      [rules]
      default allow

      [contracts]
      contract sink:external max_size:64 no_raw_credentials:true classes:text credential_transform:mask
      """)

    text = "key AKIAIOSFODNN7EXAMPLE " <> String.duplicate("diagnostic ", 12)

    decision =
      Gate.evaluate(
        text,
        [
          phase: :outbound_model,
          origin: :model,
          sink: :external,
          trust_level: :high,
          action: "send_report"
        ],
        boundary_policy: policy,
        on_sensitive: :redact
      )

    assert {decision.verdict, decision.action, decision.effect} == {:allowed, :redact, :redact}
    assert decision.audit_metadata.output_contract_transforms == [:truncate]
    assert byte_size(decision.sanitized_text) == 64
    assert String.ends_with?(decision.sanitized_text, "[TRUNCATED]")
    refute decision.sanitized_text =~ "AKIAIOSFODNN7EXAMPLE"
  end

  test "a risk mapping for another action leaves this action's classification alone" do
    context = [
      phase: :tool_request,
      origin: :model,
      sink: :tool,
      trust_level: :high,
      action: "read_file"
    ]

    other = Gate.evaluate("hello", context, risk_mappings: %{"delete_database" => :high})
    assert {other.verdict, other.risk_level} == {:allowed, :low}

    invalid = Gate.evaluate("hello", context, risk_mappings: %{"read_file" => :critical})
    assert invalid.verdict == :blocked
  end

  test "the repo policy action falls back to the context tool, then to the gate action" do
    {:ok, by_tool} =
      RepoPolicy.parse("default block\nallow agent:* action:repo_file_write docs/**\n")

    context = [phase: :repo_change, sink: :repo, identity: "did:web:codex", trust_level: :high]
    payload = %{"changed_paths" => ["docs/a.md"]}

    allowed =
      Gate.evaluate(payload, Keyword.put(context, :tool, "repo_file_write"), repo_policy: by_tool)

    assert allowed.verdict == :allowed
    assert allowed.audit_metadata.repo_policy_rules == ["line_2"]

    assert Gate.evaluate(payload, Keyword.put(context, :tool, "shell_exec"), repo_policy: by_tool).verdict ==
             :blocked

    # A text payload names no action: the gate's own default action is used.
    {:ok, by_default} =
      RepoPolicy.parse("default block\nallow agent:* action:tool_call docs/**\n")

    text_context = Keyword.put(context, :metadata, %{changed_paths: ["docs/a.md"]})

    assert Gate.evaluate("docs change summary", text_context, repo_policy: by_default).verdict ==
             :allowed

    assert Gate.evaluate("docs change summary", text_context, repo_policy: by_tool).verdict ==
             :blocked
  end

  test "a hand-built repo policy struct that does not compile blocks the repo change" do
    context = [
      phase: :repo_change,
      sink: :repo,
      identity: "did:web:codex",
      trust_level: :high,
      action: "modify"
    ]

    for {policy, reason} <- [
          {%RepoPolicy{rules: :not_a_list}, ":invalid_rules"},
          {%RepoPolicy{rules: [%{decision: :allow}]}, ":invalid_rule"},
          {%RepoPolicy{
             rules: [%{decision: :allow, agents: ["*"], actions: ["*"], paths: "docs/**"}]
           }, ":missing_paths"}
        ] do
      decision = Gate.evaluate(%{"changed_paths" => ["docs/a.md"]}, context, repo_policy: policy)

      assert decision.verdict == :blocked
      assert decision.audit_metadata.repo_policy_error == reason
    end
  end
end
