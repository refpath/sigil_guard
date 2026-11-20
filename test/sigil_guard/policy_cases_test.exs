defmodule SigilGuard.PolicyCasesTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Policy

  test "malformed risk mappings, thresholds and trust levels block" do
    assert Policy.evaluate("read_file", :high, risk_mappings: :bad) == :blocked

    assert SigilGuard.policy_verdict("read_file", :high, risk_mappings: [{"read_file", :low}]) ==
             :blocked

    assert Policy.evaluate("read_file", :high, trust_thresholds: :bad) == :blocked
    assert Policy.evaluate("read_file", :high, trust_thresholds: [low: :low]) == :blocked
    assert Policy.evaluate("read_file", :root) == :blocked
    assert Policy.evaluate("read_file", "high") == :blocked
  end

  test "an action that is not a string is high risk" do
    assert Policy.classify_risk(:delete_everything) == :high
    assert Policy.classify_risk(nil) == :high
    assert Policy.evaluate(42, :low) == :blocked
    assert {:confirm, _} = Policy.evaluate(nil, :medium)
  end

  test "a full rate store refuses a new identity and keeps serving known ones" do
    table = :sigil_guard_rate_capacity_case
    opts = [rate_store: table, max_requests: 2, window_ms: 600_000]

    for index <- 1..100_000, do: :ok = Policy.rate_check("id-#{index}", opts)

    assert Policy.rate_check("id-100001", opts) == {:error, :rate_limited}
    # The refused claim released its reservation: the next one is refused for
    # capacity again, and an identity already in the store is still counted.
    assert Policy.rate_check("id-100002", opts) == {:error, :rate_limited}
    assert Policy.rate_check("id-1", opts) == :ok
    assert Policy.rate_check("id-1", opts) == {:error, :rate_limited}
  end
end
