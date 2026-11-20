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
end
