defmodule SigilGuard.Identity.Static do
  @moduledoc """
  Config-driven actor-to-trust mapping for simple host deployments.

  Implements the `SigilGuard.Identity` behaviour over the `:trust_mappings`
  config, so a prefix table needs no custom module. A host that needs more
  writes its own `SigilGuard.Identity` implementation.

  `:trust_mappings` is an ordered list of `{pattern, trust_level}` pairs
  evaluated first-match-wins. A pattern is an exact string or a single trailing
  `*` (prefix match); the grammar is validated at runtime startup by
  `SigilGuard.Config.validate!/0`. An actor matching no entry (or an empty
  table) is `:low`. Matching is pure string comparison and never creates atoms.

      config :sigil_guard,
        trust_mappings: [
          {"spiffe://prod/*", :high},
          {"user:*", :medium}
        ]
  """

  @behaviour SigilGuard.Identity

  alias SigilGuard.Config

  @doc "Return the actor string unchanged; non-binary actors map to `\"\"`."
  @impl SigilGuard.Identity
  @spec identity(term()) :: String.t()
  def identity(actor) when is_binary(actor), do: actor
  def identity(_), do: ""

  @doc """
  Return the trust level of the first `:trust_mappings` entry whose pattern
  matches `actor`, or `:low` when none match or the actor is not a string.
  """
  @impl SigilGuard.Identity
  @spec trust_level(term()) :: SigilGuard.Identity.trust_level()
  def trust_level(actor), do: trust_level(actor, Config.trust_mappings())

  @doc """
  Return the trust level of the first entry of `mappings` whose pattern
  matches `actor`, or `:low`.

  This is `trust_level/1` without the application environment: the caller
  supplies the table. A host that gives its configuration to
  `SigilGuard.Runtime` passes the runtime's own table.

  ## Examples

      iex> mappings = [{"spiffe://prod/*", :high}, {"user:*", :medium}]
      ...> SigilGuard.Identity.Static.trust_level("user:alice", mappings)
      :medium
      iex> SigilGuard.Identity.Static.trust_level("guest", mappings)
      :low

  """
  @doc since: "1.1.0"
  @spec trust_level(term(), [{String.t(), SigilGuard.Identity.trust_level()}]) ::
          SigilGuard.Identity.trust_level()
  def trust_level(actor, mappings) when is_binary(actor) and is_list(mappings),
    do: resolve(actor, mappings)

  def trust_level(_, _), do: :low

  @doc "Static identities carry no additional bindings."
  @impl SigilGuard.Identity
  @spec bindings(term()) :: [String.t()]
  def bindings(_), do: []

  defp resolve(actor, mappings) do
    Enum.find_value(mappings, :low, fn
      {pattern, trust_level} -> if matches?(pattern, actor), do: trust_level
      _ -> nil
    end)
  end

  defp matches?(pattern, actor) when is_binary(pattern) do
    if String.ends_with?(pattern, "*") do
      String.starts_with?(actor, binary_part(pattern, 0, byte_size(pattern) - 1))
    else
      actor == pattern
    end
  end

  defp matches?(_, _), do: false
end
