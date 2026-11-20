defmodule SigilGuard.Config.Validators do
  @moduledoc false

  # NimbleOptions `{:custom, module, function, args}` validators for the
  # configuration and process start options. NimbleOptions calls them by name,
  # so they are public, and they live here to stay out of the documented API.

  @spec trust_bundle_source(term()) :: {:ok, term()} | {:error, String.t()}
  def trust_bundle_source(:none), do: {:ok, :none}
  def trust_bundle_source({:file, path} = source) when is_binary(path), do: {:ok, source}

  def trust_bundle_source({:map, envelope} = source) when is_map(envelope),
    do: {:ok, source}

  def trust_bundle_source({:binary, bytes} = source) when is_binary(bytes),
    do: {:ok, source}

  def trust_bundle_source({:priv, app, path} = source)
      when is_atom(app) and is_binary(path) do
    {:ok, source}
  end

  def trust_bundle_source(_) do
    {:error, "expected :none, {:file, path}, {:priv, app, path}, {:map, map}, or {:binary, bin}"}
  end

  @spec trust_mappings(term()) :: {:ok, term()} | {:error, String.t()}
  def trust_mappings(mappings) when is_list(mappings) do
    if Enum.all?(mappings, &valid_trust_mapping?/1) do
      {:ok, mappings}
    else
      {:error,
       "expected {pattern, trust_level} tuples; pattern is an exact string or a single " <>
         "trailing `*` prefix, trust_level is :low | :medium | :high"}
    end
  end

  def trust_mappings(_), do: {:error, "expected a list of {pattern, trust_level} tuples"}

  defp valid_trust_mapping?({pattern, trust_level}) do
    valid_mapping_pattern?(pattern) and trust_level in [:low, :medium, :high]
  end

  defp valid_trust_mapping?(_), do: false

  # A pattern is an exact string or a single trailing `*` prefix match.
  defp valid_mapping_pattern?(pattern) when is_binary(pattern) do
    case :binary.matches(pattern, "*") do
      [] -> true
      [{pos, 1}] -> pos == byte_size(pattern) - 1
      _ -> false
    end
  end

  defp valid_mapping_pattern?(_), do: false

  @spec ed25519_private_key(term()) :: {:ok, binary()} | {:error, String.t()}
  def ed25519_private_key(private_key) when is_binary(private_key), do: {:ok, private_key}
  def ed25519_private_key(_), do: {:error, "expected a binary Ed25519 seed"}
end
