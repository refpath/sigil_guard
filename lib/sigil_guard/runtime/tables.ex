defmodule SigilGuard.Runtime.Tables do
  @moduledoc false

  # The named ETS tables `SigilGuard.Runtime` creates and owns. Each owning
  # module reads its name here, and the runtime checks ownership of all of
  # them, so a name is written once.

  @doc false
  @spec rates() :: :sigil_guard_rates
  def rates, do: :sigil_guard_rates

  @doc false
  @spec replay() :: :sigil_guard_replay
  def replay, do: :sigil_guard_replay

  @doc false
  @spec trust_bundle() :: :sigil_guard_trust_bundle
  def trust_bundle, do: :sigil_guard_trust_bundle

  @doc false
  @spec trust_bundle_quarantine() :: :sigil_guard_trust_bundle_quarantine
  def trust_bundle_quarantine, do: :sigil_guard_trust_bundle_quarantine

  @doc false
  @spec all() :: [
          :sigil_guard_rates
          | :sigil_guard_replay
          | :sigil_guard_trust_bundle
          | :sigil_guard_trust_bundle_quarantine,
          ...
        ]
  def all, do: [rates(), replay(), trust_bundle(), trust_bundle_quarantine()]

  # Creating a named table that another process created first raises
  # `ArgumentError`; that race leaves the table in place, which is the goal.
  @doc false
  @spec ensure(atom(), [term()]) :: :ok
  def ensure(name, options) do
    if :ets.whereis(name) == :undefined do
      try do
        :ets.new(name, [:named_table, :public | options])
      rescue
        ArgumentError -> :ok
      end
    end

    :ok
  end

  # Values that cannot be module attributes (compiled regexes and binary
  # patterns) are built on first use and kept in `:persistent_term`. Two
  # processes may both build on a cold start; both store the same value.
  @doc false
  @spec cached(term(), (-> value)) :: value when value: term()
  def cached(key, build) do
    case :persistent_term.get(key, :undefined) do
      :undefined ->
        value = build.()
        :persistent_term.put(key, value)
        value

      value ->
        value
    end
  end
end
