defmodule SigilGuard.ContextCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Config
  alias SigilGuard.Context
  alias SigilGuard.Runtime.Gate

  test "action_name/2 reads only the payload when the context is not a struct" do
    assert Context.action_name(:not_a_context, %{"tool" => "read_file"}) == "read_file"
    assert Context.action_name(nil, "text") == "tool_call"
    # A map or keyword context is not normalized here: its action is not used.
    assert Context.action_name(%{action: "send_email"}, %{}) == "tool_call"
    assert Context.action_name([action: "send_email"], %{"name" => "x"}) == "x"
  end

  test "the three network postures validate and reach the gate" do
    for posture <- [:none, :outbound, :bidirectional, "outbound"] do
      assert Context.validate(network_posture: posture) == :ok
    end

    context = [
      phase: :tool_request,
      origin: :model,
      sink: :tool,
      trust_level: :high,
      action: "read_file"
    ]

    assert Gate.evaluate("hello", Keyword.put(context, :network_posture, "outbound")).verdict ==
             :allowed

    refused = Gate.evaluate("hello", Keyword.put(context, :network_posture, "airgap"))
    assert refused.verdict == :blocked
    assert refused.audit_metadata.runtime_input_error == :invalid_network_posture
  end

  test "binary and priv trust bundle sources are accepted in their exact shape only" do
    for source <- [{:binary, "{}"}, {:priv, :sigil_guard, "trust/bundle.json"}] do
      assert Keyword.fetch!(Config.validate!(trust_bundle: source), :trust_bundle) == source
    end

    for source <- [
          {:binary, 123},
          {:priv, "sigil_guard", "p"},
          {:priv, :sigil_guard, 1},
          {:priv, :sigil_guard}
        ] do
      assert_raise SigilGuard.ConfigError, fn -> Config.validate!(trust_bundle: source) end
    end
  end

  test "redact/2 uses each hit's replacement hint" do
    {:hit, hits} = SigilGuard.scan("key=AKIAIOSFODNN7EXAMPLE")

    assert SigilGuard.redact("key=AKIAIOSFODNN7EXAMPLE", hits) == "key=[AWS_KEY]"
  end

  test "validate/1 refuses a list that is not a keyword list instead of raising" do
    assert SigilGuard.Context.validate([1, 2]) == {:error, :invalid_context}
    assert SigilGuard.Context.validate(phase: :tool_result) == :ok
  end

  test "a sandbox whose string key is nil is read as no isolation, as the boundary check reads it" do
    boundary = %{
      phase: :tool_request,
      source: :model,
      origin: :model,
      sink: :tool,
      trust_level: :high,
      actor: %{id: "agent-1"},
      sandbox: %{"isolation_level" => nil, isolation_level: :bogus},
      action_digest: String.duplicate("a", 64),
      payload_digest: String.duplicate("b", 64),
      context_digest: String.duplicate("c", 64)
    }

    decision = SigilGuard.BoundaryPolicy.evaluate(boundary)
    assert "sandbox.matrix.execute.absent" in Enum.map(decision.matched_rules, & &1.rule_id)
  end

  test "an event's traceparent is written only from well-formed W3C ids" do
    event = SigilGuard.Audit.new_event("tool_call", "agent-1", "read_file", "allowed")
    trace = String.duplicate("a", 32)
    span = String.duplicate("b", 16)

    with_ids = fn trace_id, span_id ->
      %{event | metadata: %{"trace_id" => trace_id, "span_id" => span_id}}
      |> SigilGuard.Audit.CloudEvents.project()
      |> Map.get("traceparent")
    end

    assert with_ids.(trace, span) == "00-#{trace}-#{span}-01"

    for {trace_id, span_id} <- [
          {"short", span},
          {trace, "short"},
          {String.duplicate("A", 32), span},
          {String.duplicate("0", 32), span},
          {trace, String.duplicate("0", 16)},
          {trace <> "\r\n", span}
        ] do
      assert with_ids.(trace_id, span_id) == nil
    end
  end
end
