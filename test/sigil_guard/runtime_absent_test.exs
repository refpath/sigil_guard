defmodule SigilGuard.RuntimeAbsentTest do
  @moduledoc """
  Stateful calls in a VM where no `SigilGuard.Runtime` is running.

  The replay, rate and bundle tables belong to the runtime. A call that
  created a missing table would own it, and the table would vanish with that
  process: three short-lived processes could then verify one confirmation
  token. These tests run in a peer VM, because this suite's own VM always has
  the runtime.
  """

  use ExUnit.Case, async: true

  @tables [
    :sigil_guard_rates,
    :sigil_guard_replay,
    :sigil_guard_trust_bundle,
    :sigil_guard_trust_bundle_quarantine
  ]

  # The peer is linked to the test process and stops with it.
  setup do
    paths = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])
    {:ok, peer, _} = :peer.start_link(%{connection: :standard_io, args: paths})

    %{peer: peer}
  end

  defp tables(peer),
    do: for(table <- @tables, :peer.call(peer, :ets, :whereis, [table]) != :undefined, do: table)

  test "a nonce cannot be recorded, and nothing creates the replay table", %{peer: peer} do
    for _ <- 1..3 do
      assert :peer.call(peer, SigilGuard.ReplayStore, :check_and_put, ["actor", "nonce", 60_000]) ==
               {:error, :replay_store_unavailable}
    end

    assert :peer.call(peer, SigilGuard.ReplayStore, :clear, []) == :ok
    assert tables(peer) == []
  end

  test "the default rate limiter refuses, and a caller's own table still works", %{peer: peer} do
    assert :peer.call(peer, SigilGuard.Policy, :rate_check, ["actor", []]) ==
             {:error, :rate_limited}

    assert tables(peer) == []

    assert :peer.call(peer, SigilGuard.Policy, :rate_check, ["actor", [rate_store: :host_rates]]) ==
             :ok
  end

  test "the bundle cache reads as empty and refuses a write", %{peer: peer} do
    assert :peer.call(peer, SigilGuard.TrustBundle.Cache, :get, ["bundle"]) == :error
    assert :peer.call(peer, SigilGuard.TrustBundle.Cache, :floor, ["bundle"]) == 0
    assert :peer.call(peer, SigilGuard.TrustBundle.Cache, :clear, []) == :ok

    bundle = %SigilGuard.TrustBundle{bundle_id: "bundle", sequence: 1, root_version: 1}

    assert :peer.call(peer, SigilGuard.TrustBundle.Cache, :check, [bundle]) == :ok

    assert :peer.call(peer, SigilGuard.TrustBundle.Cache, :put, [bundle]) ==
             {:error, :cache_unavailable}

    assert tables(peer) == []
  end

  test "a quarantine record is returned and not kept", %{peer: peer} do
    record =
      :peer.call(peer, SigilGuard.TrustBundle.Quarantine, :record, [:invalid_signature, %{}])

    assert record.reason == :invalid_signature
    assert :peer.call(peer, SigilGuard.TrustBundle.Quarantine, :list, []) == []
    assert :peer.call(peer, SigilGuard.TrustBundle.Quarantine, :clear, []) == :ok
    assert tables(peer) == []
  end

  test "a confirmation token is refused instead of verifying without replay state", %{peer: peer} do
    key = :crypto.hash(:sha256, "runtime-absent-key")
    context = [phase: :tool_result, sink: :model, trust_level: :low]
    now = ~U[2026-06-30 12:00:00.000Z]
    decision = SigilGuard.Runtime.Gate.evaluate("result text", context, risk_level: :medium)

    {:ok, token} = SigilGuard.Confirmation.issue("result text", context, decision, key, now: now)

    verify = fn opts ->
      :peer.call(peer, SigilGuard.Confirmation, :verify, [
        token,
        "result text",
        context,
        key,
        [{:now, now} | opts]
      ])
    end

    assert verify.([]) == {:error, :replay_store_unavailable}
    assert verify.([]) == {:error, :replay_store_unavailable}

    # Stateless verification needs no table.
    assert {:ok, _} = verify.(consume: false)
  end

  test "the runtime owns all four tables once it starts", %{peer: peer} do
    {:ok, _} = :peer.call(peer, Application, :ensure_all_started, [:sigil_guard])

    assert Enum.sort(tables(peer)) == Enum.sort(@tables)

    assert :peer.call(peer, SigilGuard.ReplayStore, :check_and_put, ["actor", "nonce", 60_000]) ==
             :ok

    assert :peer.call(peer, SigilGuard.ReplayStore, :check_and_put, ["actor", "nonce", 60_000]) ==
             {:error, :replay_detected}
  end
end
