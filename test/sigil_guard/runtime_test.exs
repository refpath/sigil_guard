defmodule SigilGuard.RuntimeTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias SigilGuard.Runtime

  @tables [
    :sigil_guard_rates,
    :sigil_guard_replay,
    :sigil_guard_trust_bundle,
    :sigil_guard_trust_bundle_quarantine
  ]

  test "the Hex application automatically starts the singleton security runtime" do
    assert Application.spec(:sigil_guard, :mod) == {SigilGuard.Application, []}
    assert Process.whereis(Runtime)
  end

  test "runtime owns the ETS tables and validated configuration" do
    runtime = Process.whereis(Runtime)

    assert Keyword.fetch!(Runtime.configuration(runtime), :trust_bundle) == :none
    assert Keyword.fetch!(Runtime.configuration(runtime), :runtime)

    for table <- @tables do
      assert :ets.info(table, :owner) == runtime
    end
  end

  test "runtime configuration resolves explicit built-in scanner options" do
    assert {:ok, []} = Runtime.scanner_options()
  end

  test "an explicitly configured runtime hands out the values its consumers do not read" do
    alias SigilGuard.Attestation
    alias SigilGuard.Identity.Static

    previous = Runtime.configuration()

    config =
      SigilGuard.Config.validate!(
        trust_mappings: [{"user:*", :high}],
        attestation_ttl_ms: 10_000,
        max_skew_ms: 5_000,
        replay_ttl_ms: 20_000
      )

    :sys.replace_state(Runtime, fn _ -> config end)
    on_exit(fn -> :sys.replace_state(Runtime, fn _ -> previous end) end)

    assert Runtime.attestation_options() == [
             ttl_ms: 10_000,
             max_skew_ms: 5_000,
             replay_ttl_ms: 20_000
           ]

    assert Runtime.trust_mappings() == [{"user:*", :high}]

    # The application environment holds none of this, so the plain calls
    # answer from their defaults.
    assert Static.trust_level("user:alice") == :low
    assert Static.trust_level("user:alice", Runtime.trust_mappings()) == :high

    now = ~U[2026-07-03 12:00:00.000Z]

    decision = %SigilGuard.Decision{
      verdict: :allowed,
      action: :allow,
      phase: :tool_request,
      risk_level: :low,
      trust_level: :low
    }

    context = [phase: :tool_request, actor: "user:alice", tool: "read_file"]
    payload = %{"method" => "tools/call", "params" => %{"name" => "read_file"}}
    opts = Runtime.attestation_options()

    {:ok, statement} =
      Attestation.from_decision(decision, context, [{:payload, payload}, {:now, now} | opts])

    assert statement["predicate"]["expires_at"] == "2026-07-03T12:00:10.000Z"

    {:ok, envelope} = Attestation.sign(statement, SigilGuard.TestSigner, keyid: "runtime")
    trust = %{"runtime" => SigilGuard.TestSigner.public_key()}
    late = DateTime.add(now, 20, :second)

    # Six seconds past expiry: inside the default 60 s skew, outside the
    # configured 5 s.
    assert {:ok, _} = Attestation.verify(envelope, trust, now: DateTime.add(now, 16, :second))

    assert Attestation.verify(envelope, trust, [{:now, DateTime.add(now, 16, :second)} | opts]) ==
             {:error, :expired_attestation}

    assert Attestation.verify(envelope, trust, [{:now, late} | opts]) ==
             {:error, :expired_attestation}
  end

  test "bundle pattern selection resolves explicitly and rejects an expired source" do
    alias SigilGuard.TrustBundle
    now = DateTime.utc_now(:millisecond)

    {:ok, bundle} =
      TrustBundle.dev_bundle(
        now: now,
        seed: :binary.copy(<<71>>, 32),
        patterns: [
          %{"name" => "custom", "set" => "secret", "regex" => "SPECIAL", "severity" => "high"}
        ]
      )

    previous = Runtime.configuration()

    config =
      SigilGuard.Config.validate!(
        scanner_patterns: :bundle,
        trust_bundle: {:map, bundle.envelope}
      )

    :sys.replace_state(Runtime, fn _ -> config end)
    on_exit(fn -> :sys.replace_state(Runtime, fn _ -> previous end) end)
    assert {:ok, opts} = Runtime.scanner_options(Runtime, now: now)
    assert {:hit, [%{name: "custom"}]} = SigilGuard.Scanner.scan("SPECIAL", opts)

    assert {:error, :bundle_expired} =
             Runtime.scanner_options(Runtime, now: DateTime.add(now, 2, :hour))
  end

  test "a second runtime cannot take the security tables from the running one" do
    Process.flag(:trap_exit, true)
    owner = Process.whereis(Runtime)

    assert {:error, {%ArgumentError{message: message}, _}} =
             Runtime.start_link(name: :second_runtime, config: [trust_bundle: :none])

    assert message =~ "cannot own :sigil_guard_rates"
    assert :ets.info(:sigil_guard_replay, :owner) == owner
    assert Process.whereis(:second_runtime) == nil
  end

  test "runtime options and explicit configuration are validated before any table is touched" do
    Process.flag(:trap_exit, true)
    owner = Process.whereis(Runtime)

    assert {:error, {%ArgumentError{message: "invalid SigilGuard.Runtime options: [:bogus]"}, _}} =
             Runtime.start_link(name: :third_runtime, bogus: true)

    assert {:error, {%SigilGuard.ConfigError{key: :trust_bundle}, _}} =
             Runtime.start_link(name: :fourth_runtime, config: [trust_bundle: 42])

    assert :ets.info(:sigil_guard_replay, :owner) == owner
    assert :ets.info(:sigil_guard_rates, :owner) == owner
    assert Process.whereis(:third_runtime) == nil
    assert Process.whereis(:fourth_runtime) == nil
  end

  test "start_link/0 does not replace the registered runtime" do
    owner = Process.whereis(Runtime)

    assert Runtime.start_link() == {:error, {:already_started, owner}}
  end
end
