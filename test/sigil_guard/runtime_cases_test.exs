defmodule SigilGuard.RuntimeCasesTest do
  @moduledoc false

  # The tests start runtimes that compete for the named tables.
  use ExUnit.Case, async: false

  alias SigilGuard.Runtime

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
