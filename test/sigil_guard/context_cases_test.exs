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
end
