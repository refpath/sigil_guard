defmodule SigilGuard.BackendTest do
  @moduledoc false

  use ExUnit.Case, async: false

  doctest SigilGuard.Backend

  alias SigilGuard.Backend

  setup do
    original = Application.fetch_env(:sigil_guard, :backend)

    on_exit(fn ->
      case original do
        {:ok, backend} -> Application.put_env(:sigil_guard, :backend, backend)
        :error -> Application.delete_env(:sigil_guard, :backend)
      end
    end)

    :ok
  end

  describe "impl/0" do
    test "is the native Elixir backend when the removed key is absent" do
      Application.delete_env(:sigil_guard, :backend)

      assert Backend.impl() == SigilGuard.Backend.Elixir
    end

    test "raises the removed-key error for any configured value" do
      for value <- [:elixir, :nif, SigilGuard.Backend.Elixir, String, "elixir", nil] do
        Application.put_env(:sigil_guard, :backend, value)

        error = assert_raise SigilGuard.ConfigError, fn -> Backend.impl() end

        assert error.key == :backend
        assert error.reason == :legacy_contract_removed
        assert error.message =~ "MIGRATING-1.0.md"
      end
    end

    test "agrees with runtime configuration validation" do
      config_error =
        assert_raise SigilGuard.ConfigError, fn ->
          SigilGuard.Config.validate!(backend: :elixir)
        end

      Application.put_env(:sigil_guard, :backend, :elixir)
      facade_error = assert_raise SigilGuard.ConfigError, fn -> SigilGuard.scan("safe") end

      assert {facade_error.key, facade_error.reason} == {config_error.key, config_error.reason}
    end
  end

  describe "available?/1" do
    test "elixir backend is always available" do
      assert Backend.available?(:elixir)
    end

    test "nif backend is not available" do
      refute Backend.available?(:nif)
    end
  end

  describe "available_backends/0" do
    test "returns only the native Elixir backend" do
      assert Backend.available_backends() == [:elixir]
    end
  end

  describe "facade dispatch" do
    setup do
      Application.delete_env(:sigil_guard, :backend)
    end

    test "scan dispatches through backend" do
      assert {:ok, "safe"} = SigilGuard.scan("safe")
    end

    test "scan_and_redact dispatches through backend" do
      assert "safe" = SigilGuard.scan_and_redact("safe")
    end

    test "policy_verdict dispatches through backend" do
      assert :allowed = SigilGuard.policy_verdict("read_file", :medium)
    end
  end
end
