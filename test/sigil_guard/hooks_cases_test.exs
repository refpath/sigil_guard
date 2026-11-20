defmodule SigilGuard.HooksCasesTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.AdaptiveDetector
  alias SigilGuard.Boundary
  alias SigilGuard.BoundaryPolicy
  alias SigilGuard.Hooks

  @digest String.duplicate("a", 64)
  @fields %{
    phase: :tool_request,
    source: :model,
    origin: :model,
    sink: :tool,
    action_digest: @digest,
    payload_digest: @digest,
    context_digest: @digest,
    trust_level: :high,
    sandbox: %{"isolation_level" => :vm}
  }
  @empty %{contributions: [], risk_level: nil, indicators: []}

  test "a notification callback that returns :ok continues, and another return is invalid" do
    ref = :telemetry_test.attach_event_handlers(self(), [[:sigil_guard, :boundary, :hook]])
    boundary = Boundary.new(%{@fields | phase: :session_start})

    for {hook, result} <- [
          {SigilGuard.CaseFixtures.NotifyOkHook, :continue},
          {SigilGuard.CaseFixtures.BadIndicatorsHook, :invalid_hook_result}
        ] do
      assert Hooks.dispatch(boundary, hooks: [hook]) == @empty
      module = inspect(hook)

      assert_receive {[:sigil_guard, :boundary, :hook], ^ref, _,
                      %{module: ^module, hook_result: ^result}}
    end
  end

  test "a signal whose indicators are not a list fails closed on a blockable phase" do
    decision =
      BoundaryPolicy.evaluate(@fields, hooks: [SigilGuard.CaseFixtures.BadIndicatorsHook])

    assert decision.action == :block

    assert decision.matched_rules == [
             %{
               rule_id: "hook.SigilGuard.CaseFixtures.BadIndicatorsHook.tool_request",
               explanation: "invalid_hook_result"
             }
           ]

    notify = Boundary.new(%{@fields | phase: :session_start})
    assert Hooks.dispatch(notify, hooks: [SigilGuard.CaseFixtures.BadIndicatorsHook]) == @empty
  end

  test "a hook whose process is killed fails closed to :hook_crash" do
    decision = BoundaryPolicy.evaluate(@fields, hooks: [SigilGuard.CaseFixtures.SelfKillHook])

    assert decision.action == :block

    assert decision.matched_rules == [
             %{
               rule_id: "hook.SigilGuard.CaseFixtures.SelfKillHook.tool_request",
               explanation: "hook_crash"
             }
           ]
  end

  test "a detector that is killed, throws or exits degrades to no indicators" do
    boundary = Boundary.new(@fields)

    for detector <- [
          SigilGuard.CaseFixtures.SelfKillDetector,
          SigilGuard.CaseFixtures.ThrowDetector,
          SigilGuard.CaseFixtures.ExitDetector
        ] do
      assert AdaptiveDetector.run(boundary, adaptive_detector: detector, text: "x") ==
               %{indicators: [], risk_level: nil, error: :adaptive_error}

      decision = BoundaryPolicy.evaluate(@fields, adaptive_detector: detector, text: "x")
      assert decision.action == :allow
      assert decision.audit_metadata.adaptive_error == :adaptive_error
    end
  end
end
